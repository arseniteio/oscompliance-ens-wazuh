package opexp2

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
var today = now.Truncate(24 * time.Hour)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func baseline() Baseline {
	return Baseline{
		Config:    &fact.WazuhAgentConfig{Status: fact.SourceRead, SCAInterval: 43200},
		Reporting: &source.Reporting{Status: "active", LastKeepAlive: now.Add(-time.Minute)},
		MaxHours:  24,
		Policies:  []string{"cis_ubuntu24-04", "cis_ubuntu22-04"},
		Summaries: []source.SCASummary{{PolicyID: "cis_ubuntu24-04", Score: 47, Passed: 90, Failed: 100}},
		Now:       now,
	}
}

func TestBaseline(t *testing.T) {

	check(t, "assessed", JudgeEV01(baseline()), verdict.Compliant, "", "cis_ubuntu24-04 47 % (90/190)")

	off := baseline()
	off.Config = &fact.WazuhAgentConfig{Status: fact.SourceRead, SCADisabled: true}
	check(t, "sca off", JudgeEV01(off), verdict.NonCompliant, "", "SCA is disabled")

	slow := baseline()
	slow.Config = &fact.WazuhAgentConfig{Status: fact.SourceRead, SCAInterval: 172800}
	check(t, "slow", JudgeEV06(slow, 40, catalog.Message{}), verdict.NonCompliant, "", "every 48 h")

	other := baseline()
	other.Summaries = []source.SCASummary{{PolicyID: "cis_debian12"}}
	check(t, "another policy", JudgeEV01(other), verdict.NonCompliant, "", "assessed: cis_debian12")

	check(t, "score low", JudgeEV06(baseline(), 80, catalog.Message{}), verdict.NonCompliant, "", "below 80 %")
	check(t, "score reached", JudgeEV06(baseline(), 40, catalog.Message{}), verdict.Compliant, "", "minimum 40 %")
	check(t, "P-05 not set", JudgeEV06(baseline(), 0, catalog.Says("param.not_set", "param", "P-05")), verdict.NotEvaluable, verdict.CauseConfiguration, "P-05")
}

func accounts(records ...fact.IdentityRecord) Accounts {
	n := len(records)
	return Accounts{Snapshot: &fact.IdentitySnapshot{PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &n}, Records: records}
}

func TestJudgeEV02(t *testing.T) {

	keys := 0
	admin := fact.IdentityRecord{AccountName: "admin", Shell: "/bin/bash", PasswordState: fact.PasswordSet}
	tomcat := fact.IdentityRecord{AccountName: "tomcat", Shell: "/usr/sbin/nologin", PasswordState: fact.PasswordLocked, AuthorizedKeys: &keys}
	standard := []string{"Admin | Zimbra", "tomcat | Tomcat", "sa | SQL Server"}

	check(t, "active", JudgeEV02(accounts(admin, tomcat), standard, catalog.Message{}, nil, today), verdict.NonCompliant, "", "active: admin")
	check(t, "logged in", JudgeEV02(accounts(tomcat), standard, catalog.Message{}, []source.Login{{Account: "sa"}}, today), verdict.NonCompliant, "", "logged in: sa")
	check(t, "disabled", JudgeEV02(accounts(tomcat), standard, catalog.Message{}, nil, today), verdict.Compliant, "", "disabled: tomcat")
	check(t, "none", JudgeEV02(accounts(), standard, catalog.Message{}, nil, today), verdict.Compliant, "", "none of the 3")
}

func TestJudgeEV03(t *testing.T) {

	sockets := []fact.ListeningSocket{
		{Protocol: "tcp", Port: 22, Process: "sshd"},
		{Protocol: "tcp", Port: 1514},
		{Protocol: "tcp", Port: 8080, Process: "java"},
	}
	l := Listening{Snapshot: &fact.ListeningSnapshot{Status: fact.SourceRead, RecordsEmitted: 3}, Sockets: sockets}

	check(t, "java not justified", JudgeEV03(l, []string{"sshd | 22", "wazuh-remoted | 1514"}, catalog.Message{}), verdict.NonCompliant, "", "java tcp/8080")
	check(t, "unknown process by port", JudgeEV03(l, []string{"sshd | 22", "java |"}, catalog.Message{}), verdict.NonCompliant, "", "? tcp/1514")
	check(t, "all justified", JudgeEV03(l, []string{"sshd | 22", "wazuh-remoted | 1514", "java"}, catalog.Message{}), verdict.Compliant, "", "3 listening sockets")
	check(t, "incomplete", JudgeEV03(Listening{Snapshot: &fact.ListeningSnapshot{Status: fact.SourceRead, RecordsEmitted: 4}, Sockets: sockets}, nil, catalog.Message{}), verdict.NotEvaluable, verdict.CauseCollection, "3 of 4")
}

func TestJudgeEV04(t *testing.T) {

	sshd := fact.ConfigFile{Source: "/usr/sbin/sshd -T", Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{
		{Key: "permitrootlogin", Value: "without-password"},
		{Key: "x11forwarding", Value: "yes"},
		{Key: "macs", Value: "hmac-sha2-256,hmac-sha1"},
	}}
	d := Defaults{
		Settings: opacc6.Settings{Snapshot: &fact.ConfigSnapshot{RecordsEmitted: 1}, Files: []fact.ConfigFile{sshd}},
		Accounts: accounts(fact.IdentityRecord{AccountName: "root"}, fact.IdentityRecord{AccountName: "toor", PasswordState: fact.PasswordEmpty}),
		ACL:      &fact.ACLSnapshot{Status: fact.SourceRead},
		Files: []fact.ACLRecord{
			{Path: "/etc/shadow", Status: fact.SourceRead, Mode: "0640", Owner: "root:shadow"},
			{Path: "/etc/crontab", Status: fact.SourceRead, Mode: "0644", Owner: "root:root"},
			{Path: "/boot/grub/grub.cfg", Status: fact.SourceAbsent},
		},
	}
	files := []string{"/etc/shadow | 640 | root", "/etc/crontab | 600 | root", "/boot/grub/grub.cfg | 600 | root"}
	exceptions := ParseExceptions([]string{"web01 | ssh_x11forwarding | soporte | RS | 2027-01-01", "web01 | uid0:toor | x | RS | 2026-01-01"})

	got := JudgeEV04(d, "web01", files, exceptions, today)
	check(t, "deviations", got, verdict.NonCompliant, "", "cuenta_sin_contrasena:toor (empty)")
	for _, want := range []string{"permisos:/etc/crontab (0644)", "ssh_permitrootlogin (without-password)", "ssh_macs_debiles (hmac-sha1)", "uid0:toor (0)", "1 authorised"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("deviations: %q lacks %q", got.Reason, want)
		}
	}
	if strings.Contains(got.Reason, "x11forwarding (yes);") || strings.Contains(got.Reason, "shadow") || strings.Contains(got.Reason, "grub") {
		t.Errorf("an authorised exception, a closed file or an absent file failed: %q", got.Reason)
	}

	clean := Defaults{Settings: opacc6.Settings{Snapshot: &fact.ConfigSnapshot{}}, Accounts: accounts(fact.IdentityRecord{AccountName: "root"})}
	check(t, "secure", JudgeEV04(clean, "web01", nil, nil, today), verdict.Compliant, "", "secure defaults")
	check(t, "files not sent", JudgeEV04(clean, "web01", files, nil, today), verdict.NotEvaluable, verdict.CauseCollection, "acl_snapshot")
}

func TestJudgeEV05(t *testing.T) {

	vm := &fact.Virtualization{Status: fact.SourceRead, Virtual: true, Platform: "kvm"}
	rows := []string{"pve01 | web01 | pve01", "aws | db01 | cuenta 1234"}
	reporting := map[string]bool{"pve01": false, "web01": true}

	check(t, "physical", JudgeEV05(&fact.Virtualization{Status: fact.SourceRead}, "web01", nil, catalog.Message{}, reporting), verdict.Compliant, "", "not a virtual machine")
	check(t, "host down", JudgeEV05(vm, "web01", rows, catalog.Message{}, reporting), verdict.NonCompliant, "", "host pve01 is not reporting")
	check(t, "cloud reference", JudgeEV05(vm, "DB01", rows, catalog.Message{}, reporting), verdict.Compliant, "", "managed by cuenta 1234")
	check(t, "not declared", JudgeEV05(vm, "app01", rows, catalog.Message{}, reporting), verdict.NonCompliant, "", "not in P-06")
	check(t, "no fact", JudgeEV05(nil, "web01", rows, catalog.Message{}, reporting), verdict.NotEvaluable, verdict.CauseCollection, "virtualization")
}

func TestJudgeEV03CountsSockets(t *testing.T) {
	sockets := []fact.ListeningSocket{{Protocol: "tcp", Port: 22, Process: "sshd"}, {Protocol: "tcp", Port: 8080, Process: "java"}, {Protocol: "tcp6", Port: 8080, Process: "java"}}
	l := Listening{Snapshot: &fact.ListeningSnapshot{Status: fact.SourceRead, RecordsEmitted: 3}, Sockets: sockets}

	if got := JudgeEV03(l, []string{"sshd | 22"}, catalog.Message{}).Tally; got == nil || got.Met != 1 || got.Total != 3 {
		t.Errorf("tally %+v", got)
	}
}
