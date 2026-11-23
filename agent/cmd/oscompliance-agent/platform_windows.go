package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winaccounts"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winacl"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winaudit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/windefender"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/windevice"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winfirewall"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winneighbours"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winpackages"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winpolicy"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winservices"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wintime"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winupdate"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

var allCollectors = []string{"identity", "groups", "config", "listening", "neighbours", "services", "wazuh", "acl", "audit", "firewall", "packages", "units", "updates", "transactions", "malware", "timesync", "device"}

func collectorsFor(e *emit.Emitter, opts options) map[string]func() error {

	wazuhPaths := wazuh.DefaultAgentConfig
	wazuhPaths.SharedConf = opts.Paths.WazuhSharedConf
	wazuhPaths.ClientKeys = opts.Paths.WazuhClientKeys
	run := winps.Run

	return map[string]func() error{
		"identity":     func() error { return winaccounts.CollectIdentity(e, run) },
		"groups":       func() error { return winaccounts.CollectGroups(e, run) },
		"config":       func() error { return winpolicy.Collect(e, run) },
		"listening":    func() error { return winservices.CollectListening(e, run) },
		"neighbours":   func() error { return winneighbours.Collect(e, run) },
		"units":        func() error { return winservices.CollectUnits(e, run) },
		"packages":     func() error { return winpackages.Collect(e, run) },
		"firewall":     func() error { return winfirewall.Collect(e, run) },
		"malware":      func() error { return windefender.Collect(e, run, windefender.Default) },
		"timesync":     func() error { return wintime.Collect(e, run) },
		"updates":      func() error { return winupdate.CollectStatus(e, run) },
		"transactions": func() error { return winupdate.CollectTransactions(e, run) },
		"device":       func() error { return windevice.Collect(e, run) },
		"wazuh":        func() error { return wazuh.CollectAgentConfig(e, wazuhPaths) },
		"acl":          func() error { return winacl.Collect(e, run, wazuhPaths) },
		"audit": func() error {
			return winaudit.Collect(e, run, winaudit.Config{Wazuh: wazuhPaths, Managed: managedWatches(opts), Guard: guardState(opts)}, time.Now())
		},
		"services": func() error {
			return wazuh.CollectServiceLogs(e, wazuh.ServiceLogConfig{SharedConf: wazuhPaths.SharedConf, ClientKeys: wazuhPaths.ClientKeys})
		},
	}
}

func managedWatches(opts options) string {
	return filepath.Join(filepath.Dir(opts.State), "sacl-managed.json")
}

func guardState(opts options) string {
	return filepath.Join(filepath.Dir(opts.State), "sacl-guard.json")
}

const eventSource = "oscompliance-agent"

// Each suspension goes to the Application log, which the Wazuh agent forwards: rule 119008 alerts on it.
func guardWithAlerts(opts options) error {

	unlock, err := lockPass(filepath.Join(filepath.Dir(opts.State), "audit-guard.lock"))
	if err != nil {
		return err
	}
	defer unlock()

	runID, err := fact.NewRunID()
	if err != nil {
		return err
	}
	out, err := emit.OpenFile(opts.Output)
	if err != nil {
		return err
	}
	defer out.Close()

	suspended, err := winaudit.Guard(emit.New(out, opts.Host, version, runID), winps.Run, winaudit.GuardConfig{
		Managed: managedWatches(opts), State: guardState(opts), Limit: opts.AuditReadLimit, Suspend: winaudit.DefaultSuspend,
	}, time.Now())

	for _, s := range suspended {
		message := fmt.Sprintf("read watch suspended %s until %s: %d reads", s.Path, s.Until.UTC().Format(time.RFC3339), s.Reads)
		if werr := writeEvent(message); werr != nil {
			fmt.Fprintln(os.Stderr, message)
			err = errors.Join(err, werr)
		}
	}
	return err
}

func writeEvent(message string) error {
	script, err := winps.WithInput(map[string]string{"message": message}, "Write-EventLog -LogName Application -Source '"+eventSource+"' -EventId 1006 -EntryType Warning -Message $in.message")
	if err != nil {
		return err
	}
	_, err = winps.Run(script)
	return err
}

func lockPass(path string) (func(), error) {

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// No share mode: a second pass cannot open the file while this handle lives.
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("another pass is running (%s): %w", path, err)
	}

	return func() { _ = syscall.CloseHandle(h) }, nil
}

const maxFactsLog = 64 << 20

// Windows has no logrotate: the Wazuh agent follows the renamed file to its end and opens the new one.
func rotateFacts(path string) error {
	info, err := os.Stat(path)
	if err != nil || info.Size() < maxFactsLog {
		return nil
	}
	return os.Rename(path, path+".1")
}
