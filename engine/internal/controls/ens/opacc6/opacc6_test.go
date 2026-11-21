package opacc6

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/history"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var today = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func intp(n int) *int { return &n }

func config(files ...fact.ConfigFile) Settings {
	return Settings{Snapshot: &fact.ConfigSnapshot{RecordsEmitted: len(files)}, Files: files}
}

func file(source string, kv ...string) fact.ConfigFile {
	f := fact.ConfigFile{Source: source, Kind: fact.ConfigKindFile, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Entries = append(f.Entries, fact.ConfigEntry{Key: kv[i], Value: kv[i+1]})
	}
	return f
}

func sshdT(kv ...string) fact.ConfigFile {
	f := file("/usr/sbin/sshd -T", kv...)
	f.Kind = fact.ConfigKindCommand
	return f
}

func sshV(version string) fact.ConfigFile {
	f := file("/usr/bin/ssh -V", "version", version)
	f.Kind = fact.ConfigKindCommand
	return f
}

func pam(lines ...string) PAM {
	p := PAM{Snapshot: &fact.PAMSnapshot{Status: fact.SourceRead}}
	seen := map[string]bool{}
	pos := map[string]int{}
	for _, l := range lines {
		f := strings.Fields(l)
		if !seen[f[0]] {
			seen[f[0]] = true
			p.Snapshot.Services = append(p.Snapshot.Services, f[0])
		}
		p.Rules = append(p.Rules, fact.PAMRule{Service: f[0], Type: f[1], Control: f[2], Module: f[3], Args: f[4:], Position: pos[f[0]], File: "/etc/pam.d/" + f[0], Line: 1})
		pos[f[0]]++
	}
	p.Snapshot.RecordsEmitted = len(p.Rules)
	return p
}

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func TestJudgeEV03(t *testing.T) {

	passwordSSHD := sshdT("passwordauthentication", "yes", "kbdinteractiveauthentication", "no", "usepam", "yes")
	keysOnly := sshdT("passwordauthentication", "no", "kbdinteractiveauthentication", "no", "usepam", "yes")
	faillock := file("/etc/security/faillock.conf", "deny", "4", "unlock_time", "0")

	cases := []struct {
		name   string
		in     EV03Input
		status verdict.Status
		cause  verdict.Cause
		reason string
	}{
		{"no PAM read", EV03Input{Settings: config(), MaxAttempts: 5}, verdict.NotEvaluable, verdict.CauseCollection, "pam_snapshot did not arrive"},
		{"P-05 missing", EV03Input{Settings: config(), PAM: pam("login auth required pam_unix.so"), MaxAttemptsProblem: catalog.Says("param.not_set", "param", "P-05")}, verdict.NotEvaluable, verdict.CauseConfiguration, "P-05"},
		{"stock Ubuntu: no lockout on login", EV03Input{
			Settings: config(keysOnly), PAM: pam("sshd auth required pam_unix.so", "login auth required pam_unix.so"), MaxAttempts: 5,
		}, verdict.NonCompliant, "", "login: no lockout module"},
		{"faillock defaults unlock after 600 s", EV03Input{
			Settings: config(keysOnly), PAM: pam("login auth required pam_faillock.so preauth"), MaxAttempts: 5,
		}, verdict.NonCompliant, "", "unlocks by itself after 600 s"},
		{"deny above P-05", EV03Input{
			Settings: config(keysOnly), PAM: pam("login auth required pam_faillock.so preauth deny=10 unlock_time=never"), MaxAttempts: 5,
		}, verdict.NonCompliant, "", "locks after 10 attempts (deny), P-05 allows 5"},
		{"faillock.conf settings, rule overrides", EV03Input{
			Settings: config(passwordSSHD, faillock),
			PAM:      pam("sshd auth required pam_faillock.so preauth", "login auth [default=die] pam_faillock.so authfail deny=3"), MaxAttempts: 5,
		}, verdict.Compliant, "", "sshd, login lock after at most 5"},
		{"optional faillock does not lock", EV03Input{
			Settings: config(keysOnly, faillock), PAM: pam("login auth optional pam_faillock.so"), MaxAttempts: 5,
		}, verdict.NonCompliant, "", "no lockout module"},
		{"tally2 without deny", EV03Input{
			Settings: config(keysOnly), PAM: pam("login auth required pam_tally2.so onerr=fail"), MaxAttempts: 5,
		}, verdict.NonCompliant, "", "without a maximum number of attempts"},
		{"sshd unreadable", EV03Input{
			Settings: config(fact.ConfigFile{Source: "/usr/sbin/sshd -T", Kind: fact.ConfigKindCommand, Status: fact.SourceError, Error: "exit 255", Entries: []fact.ConfigEntry{}}),
			PAM:      pam("sshd auth required pam_unix.so"), MaxAttempts: 5,
		}, verdict.NotEvaluable, verdict.CauseCollection, "exit 255"},
		{"keys only and no console", EV03Input{
			Settings: config(keysOnly), PAM: pam("sshd auth required pam_unix.so"), MaxAttempts: 5,
		}, verdict.Compliant, "", "no login path accepts passwords"},
	}

	for _, c := range cases {
		check(t, c.name, JudgeEV03(c.in), c.status, c.cause, c.reason)
	}
}

func TestJudgeEV05(t *testing.T) {

	accounts := func(records ...fact.IdentityRecord) Accounts {
		n := len(records)
		return Accounts{
			Snapshot: &fact.IdentitySnapshot{PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &n},
			Records:  records,
		}
	}
	fresh := fact.IdentityRecord{AccountName: "ana", Shell: "/bin/bash", PasswordState: fact.PasswordSet, PasswordChanged: "2026-09-01", PasswordMaxDays: intp(90), AuthorizedKeys: intp(0)}
	old := fresh
	old.AccountName, old.PasswordChanged = "bob", "2025-01-01"
	never := fresh
	never.AccountName, never.PasswordMaxDays = "eve", nil
	service := fact.IdentityRecord{AccountName: "daemon", Shell: "/usr/sbin/nologin", PasswordState: fact.PasswordLocked, AuthorizedKeys: intp(0)}
	oldKeys := fact.IdentityRecord{AccountName: "deploy", Shell: "/bin/bash", PasswordState: fact.PasswordLocked, AuthorizedKeys: intp(2), AuthorizedKeysChanged: "2025-06-01T10:00:00Z"}
	forced := fresh
	forced.AccountName, forced.PasswordChanged, forced.PasswordChangeForced = "new", "", true
	unknownKeys := fact.IdentityRecord{AccountName: "x", Shell: "/bin/bash", PasswordState: fact.PasswordLocked}

	defs := config(file("/etc/login.defs", "PASS_MAX_DAYS", "90"))

	cases := []struct {
		name   string
		in     EV05Input
		status verdict.Status
		cause  verdict.Cause
		reason string
	}{
		{"no identity pass", EV05Input{MaxAge: 180}, verdict.NotEvaluable, verdict.CauseCollection, "identity_snapshot"},
		{"P-04 missing", EV05Input{Accounts: accounts(fresh), MaxAgeProblem: catalog.Says("param.not_set", "param", "P-04")}, verdict.NotEvaluable, verdict.CauseConfiguration, "P-04"},
		{"fresh, service skipped", EV05Input{Accounts: accounts(fresh, service, forced), Settings: defs, Today: today, MaxAge: 180}, verdict.Compliant, "", "2 accounts"},
		{"old password", EV05Input{Accounts: accounts(fresh, old), Settings: defs, Today: today, MaxAge: 180}, verdict.NonCompliant, "", "bob: password 662 days old"},
		{"never expires", EV05Input{Accounts: accounts(never), Settings: defs, Today: today, MaxAge: 180}, verdict.NonCompliant, "", "eve: password never expires"},
		{"old keys", EV05Input{Accounts: accounts(oldKeys), Settings: defs, Today: today, MaxAge: 180}, verdict.NonCompliant, "", "deploy: 2 SSH keys unchanged for 511 days"},
		{"login.defs default", EV05Input{Accounts: accounts(fresh), Settings: config(file("/etc/login.defs", "PASS_MAX_DAYS", "99999")), Today: today, MaxAge: 180}, verdict.NonCompliant, "", "after 99999 days (PASS_MAX_DAYS"},
		{"keys unknown", EV05Input{Accounts: accounts(fresh, unknownKeys), Settings: defs, Today: today, MaxAge: 180}, verdict.NotEvaluable, verdict.CauseCollection, "x: cannot tell"},
	}

	for _, c := range cases {
		check(t, c.name, JudgeEV05(c.in), c.status, c.cause, c.reason)
	}
}

func TestJudgeEV09(t *testing.T) {

	sudoers := func(defaults []fact.SudoDefault, grants ...fact.SudoGrant) Sudoers {
		return Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceRead, RecordsEmitted: len(grants), Defaults: defaults}, Grants: grants}
	}
	all := fact.SudoGrant{SubjectKind: "group", Subject: "ops", File: "/etc/sudoers", Line: 3, NoPasswd: true, NoPasswdCommands: []string{"ALL"}}
	one := fact.SudoGrant{SubjectKind: "user", Subject: "backup", File: "/etc/sudoers", Line: 4, NoPasswd: true, NoPasswdCommands: []string{"/usr/bin/rsync --server"}}
	root := fact.SudoGrant{SubjectKind: "user", Subject: "root", File: "/etc/sudoers", Line: 1, NoPasswdCommands: []string{"ALL"}}
	alias := fact.SudoGrant{SubjectKind: "user", Subject: "x", File: "/etc/sudoers", Line: 5, NoPasswdCommands: []string{"UNDEFINED"}}
	noAuth := []fact.SudoDefault{{Binding: ":ana", Setting: "!authenticate", File: "/etc/sudoers", Line: 9}}
	forever := []fact.SudoDefault{{Binding: "", Setting: "timestamp_timeout=-1", File: "/etc/sudoers", Line: 2}}
	wheel := pam("su auth sufficient pam_wheel.so trust use_uid")

	cases := []struct {
		name   string
		in     EV09Input
		status verdict.Status
		cause  verdict.Cause
		reason string
	}{
		{"P-08 missing", EV09Input{PointsProblem: catalog.Says("param.not_set", "param", "P-08")}, verdict.NotEvaluable, verdict.CauseConfiguration, "P-08"},
		{"clean", EV09Input{Sudoers: sudoers(nil, root), PAM: pam("su auth required pam_unix.so"), Points: []string{"sudo", "su"}}, verdict.Compliant, "", "sudo, su"},
		{"NOPASSWD ALL", EV09Input{Sudoers: sudoers(nil, all), PAM: pam(), Points: []string{"sudo"}}, verdict.NonCompliant, "", "group ops"},
		{"one command, not listed", EV09Input{Sudoers: sudoers(nil, one), PAM: pam(), Points: []string{"sudo"}}, verdict.Compliant, "", ""},
		{"one command, listed", EV09Input{Sudoers: sudoers(nil, one), PAM: pam(), Points: []string{"sudo:/usr/bin/rsync"}}, verdict.NonCompliant, "", "sudo:/usr/bin/rsync"},
		{"ALL reaches a listed command", EV09Input{Sudoers: sudoers(nil, all), PAM: pam(), Points: []string{"sudo:/usr/bin/rsync"}}, verdict.NonCompliant, "", "NOPASSWD: ALL"},
		{"!authenticate", EV09Input{Sudoers: sudoers(noAuth), PAM: pam(), Points: []string{"sudo"}}, verdict.NonCompliant, "", "!authenticate"},
		{"timestamp forever", EV09Input{Sudoers: sudoers(forever), PAM: pam(), Points: []string{"sudo"}}, verdict.NonCompliant, "", "without expiry"},
		{"su trusts wheel", EV09Input{Sudoers: sudoers(nil), PAM: wheel, Points: []string{"su"}}, verdict.NonCompliant, "", "pam_wheel with the trust option"},
		{"undefined alias", EV09Input{Sudoers: sudoers(nil, alias), PAM: pam(), Points: []string{"sudo"}}, verdict.NotEvaluable, verdict.CauseCollection, "UNDEFINED"},
		{"no sudo installed", EV09Input{Sudoers: Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceAbsent}}, PAM: pam(), Points: []string{"sudo"}}, verdict.Compliant, "", ""},
		{"blind spots", EV09Input{Sudoers: Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceRead, BlindSpots: 1, BlindSpotReasons: []string{"/etc/sudoers:3: ALL users granted"}}}, PAM: pam(), Points: []string{"sudo"}}, verdict.NotEvaluable, verdict.CauseCollection, "ALL users granted"},
		{"no sudoers read", EV09Input{PAM: pam(), Points: []string{"sudo"}}, verdict.NotEvaluable, verdict.CauseCollection, "sudoers_snapshot"},
	}

	for _, c := range cases {
		check(t, c.name, JudgeEV09(c.in), c.status, c.cause, c.reason)
	}
}

func TestJudgeEV11(t *testing.T) {

	p10 := map[string]int{CriterionLength: 12, CriterionClasses: 3, CriterionHistory: 5, CriterionBlocklist: 1}

	cases := []struct {
		name   string
		in     EV11Input
		status verdict.Status
		cause  verdict.Cause
		reason string
	}{
		{"P-10 missing", EV11Input{PAM: pam("passwd password required pam_unix.so"), Settings: config(), MinimumsProblem: catalog.Says("param.not_set", "param", "P-10")}, verdict.NotEvaluable, verdict.CauseConfiguration, "P-10"},
		{"stock Ubuntu pam_unix", EV11Input{PAM: pam("passwd password [success=1] pam_unix.so obscure yescrypt"), Settings: config(), Minimums: p10}, verdict.NonCompliant, "", "minimum length 6 (P-10 12)"},
		{"pwquality, drop-in wins over main file", EV11Input{
			PAM: pam("passwd password requisite pam_pwquality.so retry=3", "passwd password required pam_pwhistory.so use_authtok", "passwd password [success=1] pam_unix.so use_authtok"),
			Settings: config(
				file("/etc/security/pwquality.conf", "minlen", "8", "minclass", "3"),
				file("/etc/security/pwquality.conf.d/50-ens.conf", "minlen", "14"),
			),
			Minimums: p10,
		}, verdict.Compliant, "", "minimum length 14"},
		{"credits count as classes", EV11Input{
			PAM:      pam("passwd password requisite pam_pwquality.so minlen=12 dcredit=-1 ucredit=-1 dictcheck=0", "passwd password required pam_unix.so remember=5"),
			Settings: config(), Minimums: p10,
		}, verdict.NonCompliant, "", "character classes 2 (P-10 3); blocklist 0 (P-10 1)"},
		{"no passwd stack", EV11Input{PAM: pam("sshd auth required pam_unix.so"), Settings: config(), Minimums: p10}, verdict.NotEvaluable, verdict.CauseCollection, "passwd"},
	}

	for _, c := range cases {
		check(t, c.name, JudgeEV11(c.in), c.status, c.cause, c.reason)
	}
}

func TestJudgeEV12(t *testing.T) {

	ubuntu := sshV("OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024")
	absent := fact.ConfigFile{Source: "/usr/sbin/sshd -T", Kind: fact.ConfigKindCommand, Status: fact.SourceAbsent, Entries: []fact.ConfigEntry{}}

	cases := []struct {
		name   string
		in     EV12Input
		status verdict.Status
		cause  verdict.Cause
		reason string
	}{
		{"no sshd", EV12Input{Settings: config(absent), Allowed: []string{"ninguna"}}, verdict.Compliant, "", "not installed"},
		{"Ubuntu default shows the distribution", EV12Input{Settings: config(sshdT("banner", "none", "versionaddendum", "none"), ubuntu), Allowed: []string{ExposureVersion}}, verdict.NonCompliant, "", ExposureDistribution},
		{"DebianBanner no", EV12Input{Settings: config(sshdT("debianbanner", "no", "banner", "none"), ubuntu), Allowed: []string{ExposureVersion}}, verdict.Compliant, "", ExposureVersion},
		{"ninguna with sshd always fails", EV12Input{Settings: config(sshdT("debianbanner", "no"), ubuntu), Allowed: []string{"ninguna"}}, verdict.NonCompliant, "", ExposureVersion},
		{"banner and addendum", EV12Input{Settings: config(sshdT("debianbanner", "no", "banner", "/etc/issue.net", "versionaddendum", "corp"), ubuntu), Allowed: []string{ExposureVersion}}, verdict.NonCompliant, "", ExposureAddendum + ", " + ExposureBanner},
		{"P-11 missing", EV12Input{Settings: config(), AllowedProblem: catalog.Says("param.not_set", "param", "P-11")}, verdict.NotEvaluable, verdict.CauseConfiguration, "P-11"},
	}

	for _, c := range cases {
		check(t, c.name, JudgeEV12(c.in), c.status, c.cause, c.reason)
	}
}

var (
	reaches = passes.AuthLog{Known: true, Reaches: true, Detail: catalog.Says("probe.back", "run", "r1", "ts", "2026-10-01T00:00:00Z")}
	lost    = passes.AuthLog{Known: true, Detail: catalog.Says("probe.lost", "count", 3)}
)

func TestProbeResult(t *testing.T) {

	probe := func(run string, age time.Duration, status string) fact.AuthLogProbe {
		p := fact.AuthLogProbe{Status: status}
		p.RunID, p.TS = run, today.Add(-age).Format(time.RFC3339)
		if status == fact.ProbeError {
			p.Error = "dial unixgram /dev/log: no such file"
		}
		return p
	}

	cases := []struct {
		name           string
		probes         []fact.AuthLogProbe
		seen           map[string]bool
		known, reaches bool
	}{
		{"none", nil, nil, false, false},
		{"seen", []fact.AuthLogProbe{probe("a", time.Minute, fact.ProbeWritten), probe("b", time.Hour, fact.ProbeWritten)}, map[string]bool{"b": true}, true, true},
		{"too recent", []fact.AuthLogProbe{probe("a", time.Minute, fact.ProbeWritten)}, nil, false, false},
		{"lost", []fact.AuthLogProbe{probe("a", time.Minute, fact.ProbeWritten), probe("b", time.Hour, fact.ProbeWritten)}, nil, true, false},
		{"cannot write", []fact.AuthLogProbe{probe("a", time.Hour, fact.ProbeError)}, nil, false, false},
	}

	for _, c := range cases {
		got := passes.ProbeResult(c.probes, c.seen, today)
		if got.Known != c.known || got.Reaches != c.reaches {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
}

func TestJudgeEV01(t *testing.T) {

	info := config(sshdT("loglevel", "INFO"))
	quiet := config(sshdT("loglevel", "QUIET"))

	cases := []struct {
		name   string
		in     EV01Input
		status verdict.Status
		cause  verdict.Cause
		reason string
	}{
		{"P-03 missing", EV01Input{SourcesProblem: catalog.Says("param.not_set", "param", "P-03")}, verdict.NotEvaluable, verdict.CauseConfiguration, "P-03"},
		{"no local source", EV01Input{Sources: []string{"ldap"}}, verdict.Compliant, "", "ldap"},
		{"probe came back", EV01Input{Settings: info, Sources: []string{"local"}, Log: reaches}, verdict.Compliant, "", "reaches Wazuh"},
		{"probe lost", EV01Input{Settings: info, Sources: []string{"local"}, Log: lost}, verdict.NonCompliant, "", "never reached Wazuh"},
		{"probe not known", EV01Input{Settings: info, Sources: []string{"local"}, Log: passes.AuthLog{Detail: catalog.Says("gap.no_fact", "fact", "auth_log_probe")}}, verdict.NotEvaluable, verdict.CauseCollection, "auth_log_probe did not arrive"},
		{"sshd quiet", EV01Input{Settings: quiet, Sources: []string{"local"}, Log: reaches}, verdict.NonCompliant, "", "LogLevel QUIET"},
	}

	for _, c := range cases {
		check(t, c.name, JudgeEV01(c.in), c.status, c.cause, c.reason)
	}
}

func TestJudgeEV07(t *testing.T) {

	ssh := source.Login{Account: "ana", SourceIP: "10.0.0.5", Method: source.MethodSSHD}
	console := source.Login{Account: "root", Method: source.MethodConsole}

	check(t, "authorized", JudgeEV07(EV07Input{Logins: []source.Login{ssh, console}, Log: reaches, Channels: []string{"SSH"}}), verdict.Compliant, "", "ssh (1 login)")
	check(t, "not in P-07", JudgeEV07(EV07Input{Logins: []source.Login{ssh}, Log: reaches, Channels: []string{"rdp"}}), verdict.NonCompliant, "", "ssh by ana from 10.0.0.5 (1)")
	check(t, "quiet but logging", JudgeEV07(EV07Input{Log: reaches, Channels: []string{"ssh"}}), verdict.Compliant, "", "no remote login")
	check(t, "quiet and blind", JudgeEV07(EV07Input{Log: lost, Channels: []string{"ssh"}}), verdict.NotEvaluable, verdict.CauseCollection, "never reached")
	check(t, "P-07 missing", JudgeEV07(EV07Input{ChannelsProblem: catalog.Says("param.not_set", "param", "P-07")}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-07")
}

func TestJudgeEV04(t *testing.T) {

	fail := func(account string, minutes ...int) []source.Failure {
		var out []source.Failure
		for _, m := range minutes {
			out = append(out, source.Failure{Account: account, Time: today.Add(time.Duration(m) * time.Minute)})
		}
		return out
	}

	burst := fail("ana", 0, 1, 2, 3, 4, 5)
	spread := fail("bob", 0, 20, 40, 60, 80, 100)

	check(t, "burst without lockout", JudgeEV04(EV04Input{Failures: burst, Log: reaches, MaxAttempts: 5}), verdict.NonCompliant, "", "ana (6 failures within 15 minutes)")
	check(t, "burst stopped", JudgeEV04(EV04Input{Failures: burst, Lockouts: []source.Lockout{{Account: "ana"}}, Log: reaches, MaxAttempts: 5}), verdict.Compliant, "", "stopped by a lockout")
	check(t, "spread out", JudgeEV04(EV04Input{Failures: spread, Log: reaches, MaxAttempts: 5}), verdict.Compliant, "", "at most 1 within")
	check(t, "quiet", JudgeEV04(EV04Input{Log: reaches, MaxAttempts: 5}), verdict.Compliant, "", "no failed attempt")
	check(t, "quiet and blind", JudgeEV04(EV04Input{Log: lost, MaxAttempts: 5}), verdict.NotEvaluable, verdict.CauseCollection, "")
	check(t, "P-05 missing", JudgeEV04(EV04Input{MaxAttemptsProblem: catalog.Says("param.not_set", "param", "P-05")}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-05")
}

func TestJudgeEV10(t *testing.T) {

	accounts := func(records ...fact.IdentityRecord) Accounts {
		n := len(records)
		return Accounts{
			Snapshot: &fact.IdentitySnapshot{PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &n},
			Records:  records,
		}
	}
	active := fact.IdentityRecord{AccountName: "ana", Shell: "/bin/bash", PasswordState: fact.PasswordSet, AuthorizedKeys: intp(0), LastLogin: "2026-10-20T08:00:00Z"}
	idle := fact.IdentityRecord{AccountName: "bob", Shell: "/bin/bash", PasswordState: fact.PasswordSet, AuthorizedKeys: intp(0), LastLogin: "2026-01-10T08:00:00Z"}
	automation := fact.IdentityRecord{AccountName: "deploy", Shell: "/bin/bash", PasswordState: fact.PasswordLocked, AuthorizedKeys: intp(1), AuthorizedKeysChanged: "2025-01-01T00:00:00Z"}
	neverUsed := fact.IdentityRecord{AccountName: "new", Shell: "/bin/bash", PasswordState: fact.PasswordSet, AuthorizedKeys: intp(0), PasswordChanged: "2026-10-01"}
	undated := fact.IdentityRecord{AccountName: "odd", Shell: "/bin/bash", PasswordState: fact.PasswordSet, AuthorizedKeys: intp(0)}

	alerts := map[string]time.Time{"deploy": today.Add(-2 * time.Hour)}

	check(t, "all used", JudgeEV10(EV10Input{Accounts: accounts(active, automation, neverUsed), Today: today, LastAlert: alerts, MaxIdle: 45}), verdict.Compliant, "", "3 accounts")
	check(t, "idle account", JudgeEV10(EV10Input{Accounts: accounts(active, idle), Today: today, MaxIdle: 45}), verdict.NonCompliant, "", "bob (last used 288 days ago)")
	check(t, "never used, old credential", JudgeEV10(EV10Input{Accounts: accounts(automation), Today: today, MaxIdle: 45}), verdict.NonCompliant, "", "deploy (never used, credential set")
	check(t, "undated", JudgeEV10(EV10Input{Accounts: accounts(undated), Today: today, MaxIdle: 45}), verdict.NotEvaluable, verdict.CauseEvidence, "odd")
	check(t, "P-09 missing", JudgeEV10(EV10Input{Accounts: accounts(active), MaxIdleProblem: catalog.Says("param.not_set", "param", "P-09")}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-09")
}

func TestMechanismDecisions(t *testing.T) {

	d := MechanismDecisions(Mechanism([]string{"R2"}, nil))

	if _, decided := d["op.acc.6.r2.1"]; decided {
		t.Error("r2.1 applies with R2: no decision expected")
	}
	if _, decided := d["op.acc.6.r1.2"]; decided {
		t.Error("r1.2 applies with R2: no decision expected")
	}
	if d["op.acc.6.r1.1"].Status != verdict.NotApplicable || d["op.acc.6.r3.1"].Status != verdict.NotApplicable {
		t.Errorf("R1 and R3 requirements: %+v %+v", d["op.acc.6.r1.1"], d["op.acc.6.r3.1"])
	}

	d = MechanismDecisions(Mechanism(nil, nil))
	if len(d) != 7 || d["op.acc.6.r3.1"].Status != verdict.NotEvaluable || d["op.acc.6.r3.1"].Cause != verdict.CauseConfiguration {
		t.Errorf("no P-01: %+v", d)
	}

	if m, p := Mechanism([]string{"R5"}, nil); m != "" || p.IsZero() {
		t.Errorf("R5: %q %q", m, p)
	}
}

func listening(addresses []string, sockets ...fact.ListeningSocket) Listening {
	return Listening{
		Snapshot: &fact.ListeningSnapshot{Status: fact.SourceRead, Addresses: addresses, ProcessesMatched: true, RecordsEmitted: len(sockets)},
		Sockets:  sockets,
	}
}

func TestParseZones(t *testing.T) {

	z, problem := ParseZones([]string{"10.0.0.0/8 office", "192.168.1.7", "fd00::/8", "local console"})
	if !problem.IsZero() {
		t.Fatal(problem)
	}

	for origin, want := range map[string]bool{"10.1.2.3": true, "192.168.1.7": true, "192.168.1.8": false, "fd12::1": true, "8.8.8.8": false, "local": true, "::ffff:10.0.0.1": true} {
		if got, known := z.Controlled(origin); got != want || !known {
			t.Errorf("%s: got %v %v, want %v", origin, got, known, want)
		}
	}
	if _, known := z.Controlled(""); known {
		t.Error("empty origin must be unknown")
	}
	if _, problem := ParseZones([]string{"10.0.0.0/33"}); problem.IsZero() {
		t.Error("bad prefix must make P-02 unusable")
	}
}

func TestJudgeEV08(t *testing.T) {

	sshd := fact.ListeningSocket{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", Unit: "ssh.service", UnitEnabled: "enabled"}
	telnet := fact.ListeningSocket{Protocol: "tcp", Address: "0.0.0.0", Port: 23, Process: "in.telnetd"}
	nginx := fact.ListeningSocket{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx"}
	container := fact.ListeningSocket{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"}
	addrs := []string{"192.168.10.5"}

	always := []string{"ssh | si | Responsable de Seguridad | si"}
	onDemand := []string{"ssh | si | Responsable de Seguridad | no"}

	check(t, "ssh declared", JudgeEV08(EV08Input{Listening: listening(addrs, sshd, nginx), Rows: always}), verdict.Compliant, "", "ssh; 1 other")
	check(t, "constant use allows disabled too", JudgeEV08(EV08Input{Listening: listening(addrs, container), Rows: always}), verdict.Compliant, "", "ssh")
	check(t, "on demand but enabled", JudgeEV08(EV08Input{Listening: listening(addrs, sshd), Rows: onDemand}), verdict.NonCompliant, "", "enabled at boot")
	check(t, "on demand, no systemd", JudgeEV08(EV08Input{Listening: listening(addrs, container), Rows: onDemand}), verdict.NotEvaluable, verdict.CauseEvidence, "unknown")
	check(t, "telnet", JudgeEV08(EV08Input{Listening: listening(addrs, sshd, telnet), Rows: append(always, "telnet | no | x | si")}), verdict.NonCompliant, "", "telnet (in.telnetd on [23]): not encrypted")
	check(t, "no row", JudgeEV08(EV08Input{Listening: listening(addrs, sshd), Rows: []string{"rdp | si | x | si"}}), verdict.NonCompliant, "", "no P-07 row")
	check(t, "nothing listens", JudgeEV08(EV08Input{Listening: listening(addrs), Rows: always}), verdict.Compliant, "", "no remote access channel")
	check(t, "not root", JudgeEV08(EV08Input{Listening: Listening{Snapshot: &fact.ListeningSnapshot{Status: fact.SourceRead, RecordsEmitted: 1}, Sockets: []fact.ListeningSocket{container}}, Rows: always}), verdict.NotEvaluable, verdict.CauseCollection, "root")
}

func TestJudgeEV02(t *testing.T) {

	keys := sshdT("pubkeyauthentication", "yes", "passwordauthentication", "no", "kbdinteractiveauthentication", "no", "authenticationmethods", "any")
	mfa := sshdT("pubkeyauthentication", "yes", "passwordauthentication", "no", "kbdinteractiveauthentication", "yes", "authenticationmethods", "publickey,keyboard-interactive")
	totp := pam("sshd auth required pam_google_authenticator.so", "login auth required pam_unix.so")
	plain := pam("sshd auth required pam_unix.so", "login auth required pam_unix.so")
	ssh := fact.ListeningSocket{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"}
	office, _ := ParseZones([]string{"192.168.10.0/24"})

	keyLogin := source.Login{Account: "ana", SourceIP: "203.0.113.9", Method: source.MethodSSHD, Auth: "publickey", KeyType: "ED25519"}
	officeLogin := source.Login{Account: "ana", SourceIP: "192.168.10.20", Method: source.MethodSSHD, Auth: "publickey", KeyType: "ED25519"}
	mfaLogin := source.Login{Account: "ana", SourceIP: "203.0.113.9", Method: source.MethodSSHD, Auth: "keyboard-interactive/pam"}

	got := JudgeEV02(EV02Input{Logins: []source.Login{keyLogin}, Listening: listening([]string{"203.0.113.5"}, ssh), Settings: config(keys), PAM: plain, Log: reaches, Zones: office})
	check(t, "r8.1 public keys", got[ReqR81], verdict.NonCompliant, "", "one factor")
	check(t, "r1.1 public keys", got[ReqR11], verdict.Compliant, "", "")
	check(t, "r2.1 public keys", got[ReqR21], verdict.NonCompliant, "", "")

	got = JudgeEV02(EV02Input{Logins: []source.Login{officeLogin}, Listening: listening([]string{"192.168.10.5"}, ssh), Settings: config(keys), PAM: plain, Log: reaches, Zones: office})
	check(t, "r8.1 office", got[ReqR81], verdict.Compliant, "", "")

	got = JudgeEV02(EV02Input{Logins: []source.Login{mfaLogin}, Listening: listening([]string{"203.0.113.5"}, ssh), Settings: config(mfa), PAM: totp, Log: reaches, Zones: office})
	for _, req := range []string{ReqR81, ReqR11, ReqR21} {
		check(t, req+" mfa", got[req], verdict.Compliant, "", "")
	}

	match := file("/etc/ssh/sshd_config", "Match", "User backup")
	got = JudgeEV02(EV02Input{Logins: []source.Login{keyLogin}, Listening: listening([]string{"203.0.113.5"}, ssh), Settings: config(keys, match), PAM: plain, Log: reaches, Zones: office})
	check(t, "r8.1 match", got[ReqR81], verdict.NotEvaluable, verdict.CauseEvidence, "Match block")

	got = JudgeEV02(EV02Input{ZonesProblem: catalog.Says("param.not_set", "param", "P-02")})
	check(t, "no P-02", got[ReqR81], verdict.NotEvaluable, verdict.CauseConfiguration, "P-02")

	if w := worst(got[ReqR81], verdict.Judgement{Status: verdict.NonCompliant}); w.Status != verdict.NonCompliant {
		t.Errorf("worst: %+v", w)
	}
}

func TestJudgeEV06(t *testing.T) {

	at := func(s string) *time.Time { v, _ := time.Parse(time.RFC3339, s); return &v }
	hist := map[string]history.Account{
		"left":    {AccountName: "left", DisabledSince: at("2026-10-20T10:00:00Z"), DisabledObserved: true},
		"slow":    {AccountName: "slow", DisabledSince: at("2026-10-23T10:00:00Z"), DisabledObserved: true},
		"active":  {AccountName: "active"},
		"gone":    {AccountName: "gone", DeletedAt: at("2026-10-20T12:00:00Z")},
		"preseen": {AccountName: "preseen", DisabledSince: at("2026-10-24T09:00:00Z")},
	}

	notices, problem := ParseRegister([]string{
		"left | 2026-10-20T08:00:00Z | baja",
		"gone | 2026-10-20 | compromiso",
		"elsewhere | 2026-10-01 | baja",
	})
	if !problem.IsZero() {
		t.Fatal(problem)
	}

	check(t, "on time", JudgeEV06(EV06Input{History: hist, Now: today, Notices: notices, MaxHours: 24}), verdict.Compliant, "", "left (baja")

	late, _ := ParseRegister([]string{"slow | 2026-10-20T08:00:00Z | baja", "active | 2026-10-22 | compromiso"})
	check(t, "late", JudgeEV06(EV06Input{History: hist, Now: today, Notices: late, MaxHours: 24}), verdict.NonCompliant, "", "active (compromiso 2026-10-22T00:00:00Z): still enabled after 84 hours; slow (baja 2026-10-20T08:00:00Z): disabled after 74 hours")

	bound, _ := ParseRegister([]string{"preseen | 2026-10-20T08:00:00Z | baja"})
	check(t, "upper bound beyond", JudgeEV06(EV06Input{History: hist, Now: today, Notices: bound, MaxHours: 24}), verdict.NotEvaluable, verdict.CauseEvidence, "when it took is unknown")
	check(t, "upper bound within", JudgeEV06(EV06Input{History: hist, Now: today, Notices: bound, MaxHours: 200}), verdict.Compliant, "", "preseen")

	check(t, "empty register", JudgeEV06(EV06Input{History: hist, Now: today, MaxHours: 24}), verdict.Compliant, "", "no notice")
	check(t, "no register", JudgeEV06(EV06Input{NoticesProblem: catalog.Says("param.not_set", "param", "P-12"), MaxHours: 24}), verdict.NotEvaluable, verdict.CauseConfiguration, "P-12")

	if _, problem := ParseRegister([]string{"ana | yesterday | baja"}); problem.IsZero() {
		t.Error("bad date must make the register unusable")
	}
}

func secedit(kv ...string) fact.ConfigFile {
	f := file("secedit", kv...)
	f.Kind = fact.ConfigKindCommand
	for i := range f.Entries {
		f.Entries[i].Section = "System Access"
	}
	return f
}

func TestWindowsAccountPolicy(t *testing.T) {

	p10 := map[string]int{CriterionLength: 12, CriterionClasses: 3, CriterionHistory: 5}
	hardened := secedit("LockoutBadCount", "5", "LockoutDuration", "-1", "MinimumPasswordLength", "14", "PasswordComplexity", "1", "PasswordHistorySize", "24", "MaximumPasswordAge", "60")
	stock := secedit("LockoutBadCount", "0", "MinimumPasswordLength", "0", "PasswordComplexity", "0", "PasswordHistorySize", "0", "MaximumPasswordAge", "42")
	selfUnlock := secedit("LockoutBadCount", "10", "LockoutDuration", "30")

	cases := []struct {
		name   string
		got    verdict.Judgement
		status verdict.Status
		reason string
	}{
		{"lockout hardened", JudgeEV03(EV03Input{Settings: config(hardened), MaxAttempts: 5}), verdict.Compliant, "windows"},
		{"no lockout", JudgeEV03(EV03Input{Settings: config(stock), MaxAttempts: 5}), verdict.NonCompliant, "windows: no lockout module"},
		{"deny too high and unlocks", JudgeEV03(EV03Input{Settings: config(selfUnlock), MaxAttempts: 5}), verdict.NonCompliant, "secpol locks after 10 attempts"},
		{"quality hardened", JudgeEV11(EV11Input{Settings: config(hardened), Minimums: p10}), verdict.Compliant, "secpol"},
		{"quality stock", JudgeEV11(EV11Input{Settings: config(stock), Minimums: p10}), verdict.NonCompliant, "minimum length 0 (P-10 12)"},
	}
	for _, c := range cases {
		check(t, c.name, c.got, c.status, "", c.reason)
	}

	if m := (accountPolicyOf(t, stock)).maxAge(30); m.IsZero() {
		t.Error("42 days accepted with P-04 30")
	}
	if m := (accountPolicyOf(t, secedit("MaximumPasswordAge", "0"))).maxAge(30); m.IsZero() {
		t.Error("passwords that never expire accepted")
	}
	if m := (accountPolicyOf(t, hardened)).maxAge(90); !m.IsZero() {
		t.Errorf("60 days refused with P-04 90: %v", m)
	}
}

func accountPolicyOf(t *testing.T, f fact.ConfigFile) accountPolicy {
	t.Helper()
	p, ok := windowsPolicy(config(f))
	if !ok {
		t.Fatal("no Windows policy")
	}
	return p
}
