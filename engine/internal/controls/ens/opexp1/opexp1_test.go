package opexp1

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var allScans = []string{"hardware", "os", "network", "packages", "ports", "processes"}

func config(change func(*fact.WazuhAgentConfig)) *fact.WazuhAgentConfig {
	c := &fact.WazuhAgentConfig{Status: fact.SourceRead, SyscollectorInterval: 3600, SyscollectorScans: allScans}
	if change != nil {
		change(c)
	}
	return c
}

func fresh(c *fact.WazuhAgentConfig) Freshness {
	return Freshness{Config: c, Reporting: &source.Reporting{Status: "active", LastKeepAlive: now.Add(-time.Minute)}, MaxHours: 24, Now: now}
}

var inventory = &source.Inventory{
	System:    &source.System{OS: "Ubuntu", Version: "24.04.4 LTS", Kernel: "6.8.0", Architecture: "aarch64"},
	Hardware:  &source.Hardware{Cores: 4, MemoryMB: 8192},
	Packages:  map[string]int{"deb": 160, "snap": 5},
	Addresses: []string{"192.168.1.10"},
	Listening: 3,
	Processes: 40,
}

func TestInventoryFreshness(t *testing.T) {

	check(t, "current", JudgeEV01(inventory, fresh(config(nil))), verdict.Compliant, "", "Ubuntu 24.04.4 LTS, kernel 6.8.0, aarch64, 4 cores, 8192 MB")
	check(t, "disabled", JudgeEV01(inventory, fresh(config(func(c *fact.WazuhAgentConfig) { c.SyscollectorDisabled = true }))), verdict.NonCompliant, "", "disabled")
	check(t, "scan off", JudgeEV02(inventory, fresh(config(func(c *fact.WazuhAgentConfig) { c.SyscollectorScans = []string{"os"} }))), verdict.NonCompliant, "", "packages")
	check(t, "slow", JudgeEV03(inventory, fresh(config(func(c *fact.WazuhAgentConfig) { c.SyscollectorInterval = 129600 }))), verdict.NonCompliant, "", "every 36 h, P-08 allows 24 h")

	silent := fresh(config(nil))
	silent.Reporting = &source.Reporting{Status: "disconnected", LastKeepAlive: now.Add(-30 * time.Hour)}
	check(t, "no contact", JudgeEV01(inventory, silent), verdict.NonCompliant, "", "no contact with the manager since 2026-10-28 06:00 UTC")

	manager := silent
	manager.Manager, manager.Reporting = true, nil
	check(t, "manager needs no keepalive", JudgeEV02(inventory, manager), verdict.Compliant, "", "165 packages: deb 160, snap 5")

	check(t, "no config fact", JudgeEV01(inventory, fresh(nil)), verdict.NotEvaluable, verdict.CauseCollection, fact.WazuhAgentConfigFact)
	check(t, "no inventory", JudgeEV01(nil, fresh(config(nil))), verdict.NotEvaluable, verdict.CauseCollection, "no system inventory")
	check(t, "no network", JudgeEV03(&source.Inventory{Processes: 3}, fresh(config(nil))), verdict.NotEvaluable, verdict.CauseCollection, "no network inventory")

	unset := fresh(config(nil))
	unset.HoursProblem = catalog.Says("param.not_set", "param", "P-08")
	check(t, "P-08 not set", JudgeEV01(inventory, unset), verdict.NotEvaluable, verdict.CauseConfiguration, "P-08")
}

func TestJudgeEV04(t *testing.T) {

	check(t, "active", JudgeEV04(&source.Reporting{Status: "active", LastKeepAlive: now.Add(-time.Minute)}, false, 24, catalog.Message{}, now), verdict.Compliant, "", "agent active")
	check(t, "disconnected", JudgeEV04(&source.Reporting{Status: "disconnected", LastKeepAlive: now.Add(-time.Hour)}, false, 24, catalog.Message{}, now), verdict.NonCompliant, "", "agent disconnected")
	check(t, "too long ago", JudgeEV04(&source.Reporting{Status: "active", LastKeepAlive: now.Add(-25 * time.Hour)}, false, 24, catalog.Message{}, now), verdict.NonCompliant, "", "no contact")
	check(t, "not in monitoring", JudgeEV04(nil, false, 24, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseCollection, "monitoring")
	check(t, "manager", JudgeEV04(nil, true, 24, catalog.Message{}, now), verdict.Compliant, "", "the Wazuh manager itself")
}

func TestJudgeEV05(t *testing.T) {

	table := &fact.NeighbourSnapshot{Status: fact.SourceRead, Neighbours: []fact.Neighbour{
		{IP: "192.168.1.1", MAC: "aa:aa:aa:aa:aa:01"},
		{IP: "192.168.1.20", MAC: "aa:aa:aa:aa:aa:20"},
		{IP: "192.168.1.66", MAC: "aa:aa:aa:aa:aa:66"},
	}}
	agents := map[string]bool{"192.168.1.20": true}

	check(t, "unknown host", JudgeEV05(table, []string{" 192.168.1.1 "}, catalog.Message{}, agents), verdict.NonCompliant, "", "192.168.1.66 (aa:aa:aa:aa:aa:66)")
	check(t, "all known", JudgeEV05(table, []string{"192.168.1.1", "192.168.1.66"}, catalog.Message{}, agents), verdict.Compliant, "", "3 neighbours")
	check(t, "no table", JudgeEV05(nil, nil, catalog.Message{}, agents), verdict.NotEvaluable, verdict.CauseCollection, fact.NeighbourSnapshotFact)
	check(t, "unreadable", JudgeEV05(&fact.NeighbourSnapshot{Status: fact.SourceUnreadable, Error: "denied"}, nil, catalog.Message{}, agents), verdict.NotEvaluable, verdict.CauseCollection, "denied")
	check(t, "P-02 not set", JudgeEV05(table, nil, catalog.Says("param.not_set", "param", "P-02"), agents), verdict.NotEvaluable, verdict.CauseConfiguration, "P-02")
}

func TestJudgeEV06(t *testing.T) {

	changes := map[time.Time]int{
		time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC):   4,
		time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC): 2,
	}

	check(t, "recent", JudgeEV06([]string{"2026-10-01 | todo | RS"}, catalog.Message{}, 90, catalog.Message{}, changes, now), verdict.Compliant, "", "28 days ago (P-04 90): 2026-10-01 | todo | RS; 2 package changes since")
	check(t, "overdue", JudgeEV06([]string{"2026-03-01 | todo | RS"}, catalog.Message{}, 90, catalog.Message{}, changes, now), verdict.NonCompliant, "", "P-04 asks every 90")
	check(t, "empty register", JudgeEV06(nil, catalog.Says("param.not_set", "param", "P-09"), 90, catalog.Message{}, changes, now), verdict.NotEvaluable, verdict.CauseConfiguration, "P-09")
}

func TestJudgeEV07(t *testing.T) {

	rows := []string{"lab-agent-01 | J. Gómez | Sistemas | servidor", "printer | M. López | | ", "nas | | | soporte"}
	natures := []string{"servidor", "soporte"}

	check(t, "declared", JudgeEV07("LAB-AGENT-01", rows, catalog.Message{}, natures, catalog.Message{}), verdict.Compliant, "", "owner J. Gómez, nature servidor")
	check(t, "not declared", JudgeEV07("web01", rows, catalog.Message{}, natures, catalog.Message{}), verdict.NonCompliant, "", "web01 is not in P-01")
	check(t, "no owner", JudgeEV07("nas", rows, catalog.Message{}, natures, catalog.Message{}), verdict.NonCompliant, "", "no owner")
	check(t, "no nature", JudgeEV07("printer", rows, catalog.Message{}, natures, catalog.Message{}), verdict.NonCompliant, "", "no nature")
	check(t, "nature outside the taxonomy", JudgeEV07("lab-agent-01", rows, catalog.Message{}, []string{"estación"}, catalog.Message{}), verdict.NonCompliant, "", "not in P-03")
	check(t, "no taxonomy", JudgeEV07("lab-agent-01", rows, catalog.Message{}, nil, catalog.Message{}), verdict.Compliant, "", "")
}
