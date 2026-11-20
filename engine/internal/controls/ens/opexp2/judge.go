package opexp2

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Baseline struct {
	Config        *fact.WazuhAgentConfig
	Reporting     *source.Reporting
	Manager       bool
	MaxHours      int
	HoursProblem  catalog.Message
	Policies      []string
	PolicyProblem catalog.Message
	Summaries     []source.SCASummary
	Now           time.Time
}

func (b Baseline) assessed() ([]source.SCASummary, verdict.Judgement, bool) {

	switch {
	case !b.HoursProblem.IsZero():
		return nil, passes.Gap(verdict.CauseConfiguration, b.HoursProblem), false
	case !b.PolicyProblem.IsZero():
		return nil, passes.Gap(verdict.CauseConfiguration, b.PolicyProblem), false
	case b.Config == nil:
		return nil, passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact)), false
	case b.Config.Status != fact.SourceRead:
		return nil, passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", b.Config.Status, b.Config.Error)), false
	case b.Config.SCADisabled:
		return nil, verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.sca_disabled")), false
	case b.Config.SCAInterval > b.MaxHours*3600:
		return nil, verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.sca_interval_too_long", "interval", b.Config.SCAInterval/3600, "max", b.MaxHours)), false
	}

	if !b.Manager {
		if b.Reporting == nil || b.Reporting.LastKeepAlive.IsZero() {
			return nil, passes.Gap(verdict.CauseCollection, catalog.Says("opexp1.no_monitoring")), false
		}
		if b.Now.Sub(b.Reporting.LastKeepAlive) > time.Duration(b.MaxHours)*time.Hour {
			return nil, verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.no_contact", "since", b.Reporting.LastKeepAlive.UTC().Format("2006-01-02 15:04 UTC"), "max", b.MaxHours)), false
		}
	}

	var found []source.SCASummary
	for _, s := range b.Summaries {
		if slices.ContainsFunc(b.Policies, func(p string) bool { return strings.EqualFold(strings.TrimSpace(p), s.PolicyID) }) {
			found = append(found, s)
		}
	}
	slices.SortFunc(found, func(a, b source.SCASummary) int { return strings.Compare(a.PolicyID, b.PolicyID) })

	if len(found) == 0 {
		var other []string
		for _, s := range b.Summaries {
			other = append(other, s.PolicyID)
		}
		slices.Sort(other)
		return nil, verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.no_baseline", "policies", b.Policies, "other", other)), false
	}

	return found, verdict.Judgement{}, true
}

func scores(list []source.SCASummary) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = fmt.Sprintf("%s %d %% (%d/%d)", s.PolicyID, s.Score, s.Passed, s.Passed+s.Failed)
	}
	return out
}

func JudgeEV01(b Baseline) verdict.Judgement {

	found, j, ok := b.assessed()
	if !ok {
		return j
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.baseline", "policies", scores(found)))
}

func JudgeEV06(b Baseline, minScore int, scoreProblem catalog.Message) verdict.Judgement {

	if !scoreProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, scoreProblem)
	}

	found, j, ok := b.assessed()
	if !ok {
		return j
	}

	var low []source.SCASummary
	for _, s := range found {
		if s.Score < minScore {
			low = append(low, s)
		}
	}
	if len(low) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.score_below", "policies", scores(low), "min", minScore)).Counting(len(found)-len(low), len(found))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.score_reached", "policies", scores(found), "min", minScore)).Counting(len(found), len(found))
}

type Accounts struct {
	Snapshot *fact.IdentitySnapshot
	Records  []fact.IdentityRecord
}

func JudgeEV02(a Accounts, standard []string, problem catalog.Message, logins []source.Login, today time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if gap, found := passes.IdentityGap(a.Snapshot, a.Records); found {
		return gap
	}

	listed := map[string]string{}
	for _, row := range standard {
		name, product, _ := strings.Cut(row, "|")
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			listed[name] = strings.TrimSpace(product)
		}
	}

	var active, disabled, entered []string
	for _, r := range a.Records {
		if _, ok := listed[strings.ToLower(r.AccountName)]; !ok {
			continue
		}
		if off, known := opacc1.IsDisabled(r, today); known && off {
			disabled = append(disabled, r.AccountName)
		} else {
			active = append(active, r.AccountName)
		}
	}
	for _, l := range logins {
		if _, ok := listed[strings.ToLower(l.Account)]; ok && !slices.Contains(entered, l.Account) {
			entered = append(entered, l.Account)
		}
	}
	slices.Sort(active)
	slices.Sort(entered)

	switch {
	case len(active) > 0 || len(entered) > 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.standard_accounts", "active", active, "entered", entered))
	case len(disabled) > 0:
		slices.Sort(disabled)
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.standard_disabled", "accounts", disabled))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.no_standard_accounts", "count", len(listed)))
}

type Listening struct {
	Snapshot *fact.ListeningSnapshot
	Sockets  []fact.ListeningSocket
}

func JudgeEV03(l Listening, rows []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	switch {
	case l.Snapshot == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.ListeningSnapshotFact))
	case l.Snapshot.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("/proc/net", l.Snapshot.Status, l.Snapshot.Error))
	case len(l.Sockets) < l.Snapshot.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, passes.Incomplete(l.Snapshot.RunID, len(l.Sockets), l.Snapshot.RecordsEmitted, fact.ListeningSocketFact))
	}

	type service struct {
		process string
		ports   []int
	}
	var justified []service
	for _, r := range rows {
		name, ports, _ := strings.Cut(r, "|")
		s := service{process: strings.TrimSpace(name)}
		for _, p := range strings.Split(ports, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				s.ports = append(s.ports, n)
			}
		}
		justified = append(justified, s)
	}

	var extra []string
	unjustified := 0
	for _, sock := range l.Sockets {
		ok := slices.ContainsFunc(justified, func(s service) bool {
			if sock.Process == "" {
				return slices.Contains(s.ports, sock.Port)
			}
			return strings.EqualFold(s.process, sock.Process) && (len(s.ports) == 0 || slices.Contains(s.ports, sock.Port))
		})
		if ok {
			continue
		}
		unjustified++
		process := sock.Process
		if process == "" {
			process = "?"
		}
		if item := fmt.Sprintf("%s %s/%d", process, sock.Protocol, sock.Port); !slices.Contains(extra, item) {
			extra = append(extra, item)
		}
	}
	slices.Sort(extra)

	if len(extra) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.unjustified_services", "list", extra)).Counting(len(l.Sockets)-unjustified, len(l.Sockets))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.services_justified", "count", len(l.Sockets))).Counting(len(l.Sockets), len(l.Sockets))
}

type Defaults struct {
	Settings opacc6.Settings
	Accounts Accounts
	ACL      *fact.ACLSnapshot
	Files    []fact.ACLRecord
}

var weakCiphers = []string{"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se"}

var weakMACs = []string{"hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com"}

var weakKex = []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}

func sshdDeviations(d opacc6.SSHD) map[string]string {

	out := map[string]string{}
	set := func(check, value string) { out[check] = value }

	if v := d.Get("permitrootlogin"); v != "" && v != "no" {
		set("ssh_permitrootlogin", v)
	}
	for _, key := range []string{"permitemptypasswords", "x11forwarding", "hostbasedauthentication"} {
		if d.Get(key) == "yes" {
			set("ssh_"+key, "yes")
		}
	}
	if d.Get("ignorerhosts") == "no" {
		set("ssh_ignorerhosts", "no")
	}
	for _, w := range []struct {
		check, key string
		list       []string
	}{{"ssh_cifrados_debiles", "ciphers", weakCiphers}, {"ssh_macs_debiles", "macs", weakMACs}, {"ssh_kex_debiles", "kexalgorithms", weakKex}} {
		check, key, list := w.check, w.key, w.list
		var weak []string
		for _, a := range strings.Split(d.Get(key), ",") {
			if slices.Contains(list, strings.TrimSpace(a)) {
				weak = append(weak, strings.TrimSpace(a))
			}
		}
		if len(weak) > 0 {
			set(check, strings.Join(weak, ","))
		}
	}
	return out
}

type Exception struct {
	Asset, Check string
	Until        time.Time
}

func ParseExceptions(rows []string) []Exception {
	var out []Exception
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 5 {
			c = append(c, "")
		}
		until, err := time.Parse("2006-01-02", strings.TrimSpace(c[4]))
		if err != nil {
			continue
		}
		out = append(out, Exception{Asset: strings.TrimSpace(c[0]), Check: strings.TrimSpace(c[1]), Until: until})
	}
	return out
}

func JudgeEV04(d Defaults, machine string, files []string, exceptions []Exception, today time.Time) verdict.Judgement {

	if gap, found := d.Settings.Gap(); found {
		return gap
	}
	if gap, found := passes.IdentityGap(d.Accounts.Snapshot, d.Accounts.Records); found {
		return gap
	}

	deviations := map[string]string{}

	sshd := d.Settings.SSHD()
	if sshd.Status == fact.SourceError || sshd.Status == fact.SourceUnreadable {
		return passes.Gap(verdict.CauseCollection, passes.Source("sshd -T", sshd.Status, sshd.Error))
	}
	for k, v := range sshdDeviations(sshd) {
		deviations[k] = v
	}

	for _, r := range d.Accounts.Records {
		if r.PasswordState == fact.PasswordEmpty {
			deviations["cuenta_sin_contrasena:"+r.AccountName] = "empty"
		}
		if r.UID == 0 && r.AccountName != "root" {
			deviations["uid0:"+r.AccountName] = "0"
		}
	}

	if len(files) > 0 {
		if d.ACL == nil || d.ACL.Status != fact.SourceRead {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.ACLSnapshotFact))
		}
		byPath := map[string]fact.ACLRecord{}
		for _, r := range d.Files {
			byPath[r.Path] = r
		}
		for _, row := range files {
			c := strings.Split(row, "|")
			for len(c) < 3 {
				c = append(c, "")
			}
			path, mode, owner := strings.TrimSpace(c[0]), strings.TrimSpace(c[1]), strings.TrimSpace(c[2])
			r, ok := byPath[path]
			switch {
			case !ok:
				return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.acl_not_sent", "path", path))
			case r.Status == fact.SourceAbsent:
				continue
			case r.Status != fact.SourceRead:
				return passes.Gap(verdict.CauseCollection, catalog.Says("item.error", "path", path, "error", r.Error))
			}
			max, err := strconv.ParseUint(mode, 8, 32)
			if err != nil {
				return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.mode_not_octal", "path", path, "mode", mode))
			}
			if got, _ := strconv.ParseUint(r.Mode, 8, 32); got&^max != 0 {
				deviations["permisos:"+path] = r.Mode
			}
			user, _, _ := strings.Cut(r.Owner, ":")
			if owner != "" && owner != r.Owner && (strings.Contains(owner, ":") || owner != user) {
				deviations["propietario:"+path] = r.Owner
			}
		}
	}

	var failed, allowed []string
	for check, value := range deviations {
		item := check + " (" + value + ")"
		if slices.ContainsFunc(exceptions, func(x Exception) bool {
			return strings.EqualFold(x.Asset, machine) && x.Check == check && !x.Until.Before(today)
		}) {
			allowed = append(allowed, item)
		} else {
			failed = append(failed, item)
		}
	}
	slices.Sort(failed)
	slices.Sort(allowed)

	if len(failed) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.insecure_defaults", "list", failed, "allowed", len(allowed)))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.secure_defaults", "allowed", allowed))
}

func JudgeEV05(v *fact.Virtualization, machine string, rows []string, problem catalog.Message, reporting map[string]bool) verdict.Judgement {

	if v == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.VirtualizationFact))
	}
	if v.Status != fact.SourceRead {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp2.virtualization_unreadable", "error", v.Error))
	}
	if !v.Virtual {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.not_virtual"))
	}
	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 3 {
			c = append(c, "")
		}
		hypervisor, vm, host := strings.TrimSpace(c[0]), strings.TrimSpace(c[1]), strings.TrimSpace(c[2])
		if !strings.EqualFold(vm, machine) {
			continue
		}
		if known, up := reportingOf(reporting, host); known && !up {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.host_not_reporting", "host", host))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.virtual_declared", "platform", v.Platform, "hypervisor", hypervisor, "host", host))
	}

	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.virtual_not_declared", "platform", v.Platform, "machine", machine))
}

func reportingOf(reporting map[string]bool, host string) (known, up bool) {
	for name, ok := range reporting {
		if strings.EqualFold(name, host) {
			return true, ok
		}
	}
	return false, false
}
