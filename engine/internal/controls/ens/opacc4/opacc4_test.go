package opacc4

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func config(files ...fact.ConfigFile) opacc6.Settings {
	return opacc6.Settings{Snapshot: &fact.ConfigSnapshot{RecordsEmitted: len(files)}, Files: files}
}

func entries(source string, section string, kv ...string) fact.ConfigFile {
	f := fact.ConfigFile{Source: source, Kind: fact.ConfigKindFile, Status: fact.SourceRead}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Entries = append(f.Entries, fact.ConfigEntry{Key: kv[i], Value: kv[i+1], Section: section})
	}
	return f
}

func TestJudgeEV01(t *testing.T) {

	drop := &fact.FirewallSnapshot{Tool: "nft", Status: fact.SourceRead, Chains: []fact.FirewallChain{{Family: "inet", Name: "input", Hook: "input", Policy: "drop"}}}
	accept := &fact.FirewallSnapshot{Tool: "iptables", Status: fact.SourceRead, Chains: []fact.FirewallChain{{Family: "ip", Name: "INPUT", Hook: "input", Policy: "accept"}}}
	empty := &fact.FirewallSnapshot{Tool: "nft", Status: fact.SourceRead}
	none := &fact.FirewallSnapshot{Tool: "none", Status: fact.SourceRead}
	smb := entries("/etc/samba/smb.conf", "publico", "guest ok", "Yes")

	check(t, "closed", JudgeEV01(EV01Input{Firewall: drop, Settings: config()}), verdict.Compliant, "", "denies by default")
	check(t, "accept policy", JudgeEV01(EV01Input{Firewall: accept, Settings: config(), Resources: []string{"sudo"}}), verdict.NonCompliant, "", "cortafuegos: iptables (ip, input): the INPUT chain accepts")
	check(t, "empty ruleset", JudgeEV01(EV01Input{Firewall: empty, Settings: config()}), verdict.NonCompliant, "", "no input chain")
	check(t, "no firewall, authorised", JudgeEV01(EV01Input{Firewall: none, Settings: config(), Resources: []string{"cortafuegos"}}), verdict.Compliant, "", "authorised in P-01")
	check(t, "guest share, no P-01", JudgeEV01(EV01Input{Firewall: drop, Settings: config(smb), ResourcesProblem: catalog.Says("param.not_set", "param", "P-01")}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-01")
	check(t, "guest share not authorised", JudgeEV01(EV01Input{Firewall: drop, Settings: config(smb), Resources: []string{"cortafuegos"}}), verdict.NonCompliant, "", "publico: Samba share that admits guests (guest ok = Yes)")
	check(t, "vsftpd", JudgeEV01(EV01Input{Firewall: drop, Settings: config(entries("/etc/vsftpd.conf", "", "anonymous_enable", "YES")), Resources: []string{"x"}}), verdict.NonCompliant, "", "vsftpd")
	check(t, "no firewall fact", JudgeEV01(EV01Input{Settings: config()}), verdict.NotEvaluable, verdict.CauseCollection, "")
}

func sudoers(grants ...fact.SudoGrant) Sudoers {
	return Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceRead, RecordsEmitted: len(grants)}, Grants: grants}
}

func TestJudgeEV02(t *testing.T) {

	root := fact.SudoGrant{SubjectKind: "user", Subject: "root", Spec: "ALL=(ALL:ALL) ALL", File: "/etc/sudoers", Line: 1}
	group := fact.SudoGrant{SubjectKind: "group", Subject: "sudo", Spec: "ALL=(ALL:ALL)   ALL", File: "/etc/sudoers", Line: 2}
	ops := fact.SudoGrant{SubjectKind: "user", Subject: "ops", Spec: "ALL=(root) /usr/bin/systemctl, /usr/bin/journalctl", File: "/etc/sudoers.d/ops", Line: 1}

	matrix := ParseMatrix([]string{
		"root | sudo | ALL=(ALL:ALL) ALL,ALL=(ALL) NOPASSWD:ALL",
		"%sudo | sudo | ALL=(ALL:ALL) ALL",
		"ops | sudo | ALL=(root) /usr/bin/systemctl, /usr/bin/journalctl",
	})

	check(t, "as authorised, commas and blanks", JudgeEV02(sudoers(root, group, ops), matrix, catalog.Message{}), verdict.Compliant, "", "3 sudo grants")
	check(t, "no row", JudgeEV02(sudoers(fact.SudoGrant{SubjectKind: "user", Subject: "eve", Spec: "ALL=(ALL) ALL"}), matrix, catalog.Message{}), verdict.NonCompliant, "", "without a «eve | sudo» row in P-01")

	wider := ops
	wider.Spec = "ALL=(root) /usr/bin/systemctl, /bin/bash"
	check(t, "beyond the row", JudgeEV02(sudoers(wider), matrix, catalog.Message{}), verdict.NonCompliant, "", "«/bin/bash» is not among")
	check(t, "no sudo", JudgeEV02(Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceAbsent}}, matrix, catalog.Message{}), verdict.Compliant, "", "not installed")
	check(t, "no P-01", JudgeEV02(sudoers(root), nil, catalog.Says("param.not_set", "param", "P-01")), verdict.NotEvaluable, verdict.CauseConfiguration, "P-01")
}

func accounts() Accounts {
	n, g := 4, 3
	return Accounts{
		Identity: &fact.IdentitySnapshot{PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &n},
		IdentityRecords: []fact.IdentityRecord{
			{AccountName: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
			{AccountName: "ana", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			{AccountName: "syslog", UID: 104, GID: 110, Shell: "/usr/sbin/nologin"},
			{AccountName: "backup", UID: 34, GID: 34, Shell: "/bin/sh"},
		},
		Groups: &fact.GroupSnapshot{GroupStatus: fact.SourceRead, RecordsEmitted: &g},
		GroupRecords: []fact.GroupRecord{
			{GroupName: "root", GID: 0},
			{GroupName: "sudo", GID: 27, Members: []string{"ana"}},
			{GroupName: "rrhh", GID: 2000, Members: []string{"ana"}},
		},
	}
}

func TestJudgeEV03AndEV08(t *testing.T) {

	matrix := ParseMatrix([]string{"root | sudo | ALL=(ALL:ALL) ALL", "ana", "%sudo | sudo | ALL=(ALL:ALL) ALL"})

	check(t, "members declared", JudgeEV03(accounts(), []string{"root", "sudo"}, matrix, catalog.Message{}), verdict.Compliant, "", "2 memberships")
	check(t, "member not a role", JudgeEV03(accounts(), []string{"sudo"}, ParseMatrix([]string{"root"}), catalog.Message{}), verdict.NonCompliant, "", "ana in sudo")

	in := EV08Input{Sudoers: sudoers(fact.SudoGrant{SubjectKind: "group", Subject: "sudo", Spec: "ALL=(ALL:ALL) ALL"}), Accounts: accounts(), UIDMin: 1000, Rows: matrix}
	check(t, "backup has a shell", JudgeEV08(in), verdict.NonCompliant, "", "backup (system account, uid 34, shell /bin/sh)")

	clean := accounts()
	three := 3
	clean.IdentityRecords, clean.Identity.RecordsEmitted = clean.IdentityRecords[:3], &three
	in.Accounts = clean
	check(t, "broad but declared", JudgeEV08(in), verdict.Compliant, "", "%sudo (sudo ALL=(ALL:ALL) ALL)")

	in.Sudoers = sudoers(fact.SudoGrant{SubjectKind: "user", Subject: "ops", Spec: "ALL=(root) /usr/bin/systemctl"})
	check(t, "hardened", JudgeEV08(in), verdict.Compliant, "", "no unrestricted sudo grant")

	if !unrestricted("ALL=(ALL) NOPASSWD: ALL") || unrestricted("ALL=(root) /usr/bin/x") || !unrestricted("ALL=(root) /usr/bin/x, ALL") {
		t.Error("unrestricted")
	}
}

func TestJudgeEV04(t *testing.T) {

	change := func(auid, path string) source.AuditAccess {
		return source.AuditAccess{Key: "oscompliance_perm", Success: "yes", AUID: auid, Path: path}
	}

	check(t, "competent", JudgeEV04([]source.AuditAccess{change("1000", "/srv/x")}, accounts(), []string{"ana"}, catalog.Message{}, catalog.Message{}), verdict.Compliant, "", "1 rights changes")
	check(t, "not competent", JudgeEV04([]source.AuditAccess{change("1000", "/etc/group")}, accounts(), []string{"rsec"}, catalog.Message{}, catalog.Message{}), verdict.NonCompliant, "", "ana changed /etc/group")
	check(t, "blind", JudgeEV04(nil, accounts(), []string{"rsec"}, catalog.Message{}, catalog.Says("chain.auditd", "state", catalog.Says("auditd.absent"), "error", "")), verdict.NotEvaluable, verdict.CauseCollection, "auditd absent")
	check(t, "P-02", JudgeEV04(nil, accounts(), nil, catalog.Says("param.not_set", "param", "P-02"), catalog.Message{}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-02")

	if c := AuditChain(&fact.AuditWatchSnapshot{Auditd: fact.AuditdRunning}, &fact.WazuhAgentConfig{Status: fact.SourceRead, Localfiles: []fact.AgentLocalfile{{Format: "audit"}}}, true, nil); !strings.Contains(c.Render("en"), "permission change rules") {
		t.Errorf("chain without perm rules: %q", c)
	}
}

func TestJudgeEV05(t *testing.T) {

	check(t, "recent", JudgeEV05([]string{"2026-09-01 | todo | RS", "2026-03-01 | todo | RS"}, catalog.Message{}, 90, catalog.Message{}, now), verdict.Compliant, "", "54 days ago")
	check(t, "old", JudgeEV05([]string{"2026-03-01 | todo | RS"}, catalog.Message{}, 90, catalog.Message{}, now), verdict.NonCompliant, "", "238 days ago")
	check(t, "future typo does not hide", JudgeEV05([]string{"2062-09-01 | x | y", "2026-09-01 | todo | RS"}, catalog.Message{}, 90, catalog.Message{}, now), verdict.Compliant, "", "")
	check(t, "bad dates", JudgeEV05([]string{"01/09/2026 | x | y"}, catalog.Message{}, 90, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseEvidence, "01/09/2026")
	check(t, "no register", JudgeEV05(nil, catalog.Says("param.not_set", "param", "P-08"), 90, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseConfiguration, "P-08")
}

func TestJudgeEV06(t *testing.T) {

	reaches := passes.AuthLog{Known: true, Reaches: true}
	login := source.Login{Account: "jgomez", SourceIP: "10.0.0.9", Method: source.MethodSSHD}

	check(t, "authorised with note", JudgeEV06([]source.Login{login}, []string{"jgomez | VPN"}, catalog.Message{}, reaches), verdict.Compliant, "", "1 remote logins")
	check(t, "not authorised", JudgeEV06([]source.Login{login}, []string{"ana"}, catalog.Message{}, reaches), verdict.NonCompliant, "", "jgomez from 10.0.0.9")
	check(t, "quiet and blind", JudgeEV06(nil, []string{"ana"}, catalog.Message{}, passes.AuthLog{Detail: catalog.Says("gap.no_fact", "fact", "auth_log_probe")}), verdict.NotEvaluable, verdict.CauseCollection, "auth_log_probe")
}

func TestJudgeEV07(t *testing.T) {

	resources := ParseSensitive([]string{"/datos/rrhh | rrhh", "/datos/rrhh/direccion | direccion"})
	read := func(auid, path string) source.AuditAccess {
		return source.AuditAccess{Key: "oscompliance_read", Success: "yes", AUID: auid, Path: path}
	}

	check(t, "secondary group counts", JudgeEV07([]source.AuditAccess{read("1000", "/datos/rrhh/nominas.pdf")}, accounts(), resources, catalog.Message{}, catalog.Message{}), verdict.Compliant, "", "1 accesses")
	check(t, "longest resource wins", JudgeEV07([]source.AuditAccess{read("1000", "/datos/rrhh/direccion/plan.pdf")}, accounts(), resources, catalog.Message{}, catalog.Message{}), verdict.NonCompliant, "", "ana on /datos/rrhh/direccion/plan.pdf")
	check(t, "blind", JudgeEV07(nil, accounts(), resources, catalog.Message{}, catalog.Says("chain.unwatched", "path", "/datos/rrhh")), verdict.NotEvaluable, verdict.CauseCollection, "not watched")
}
