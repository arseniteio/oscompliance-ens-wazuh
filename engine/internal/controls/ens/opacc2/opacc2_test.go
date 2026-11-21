package opacc2

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type want struct {
	status  verdict.Status
	cause   verdict.Cause
	reasons []string
}

func check(t *testing.T, name string, got verdict.Judgement, w want) {
	t.Helper()
	if got.Status != w.status || got.Cause != w.cause {
		t.Errorf("%s: got %s/%s, want %s/%s (reason %q)", name, got.Status, got.Cause, w.status, w.cause, got.Reason)
	}
	for _, r := range w.reasons {
		if !strings.Contains(got.Reason, r) {
			t.Errorf("%s: reason %q does not contain %q", name, got.Reason, r)
		}
	}
}

func sweep(files ...fact.SpecialFile) Sweep {
	return Sweep{Snapshot: &fact.FileSweepSnapshot{Roots: []string{"/"}, Status: fact.SweepComplete, RecordsEmitted: len(files)}, Files: files}
}

func ww(path, mode string, dir, sticky bool) fact.SpecialFile {
	kind := "file"
	if dir {
		kind = "directory"
	}
	return fact.SpecialFile{Path: path, Kind: kind, Mode: mode, WorldWritable: true, Sticky: sticky}
}

func umasks(values ...string) *fact.UmaskSnapshot {
	return &fact.UmaskSnapshot{Sources: []fact.UmaskSource{
		{Path: "/etc/login.defs", Status: fact.SourceRead, Umasks: values},
		{Path: "/etc/profile", Status: fact.SourceAbsent},
	}}
}

func TestJudgeEV01(t *testing.T) {
	scope := []string{"/etc", "/srv/data"}

	base := func(s Sweep, u *fact.UmaskSnapshot) EV01Input {
		return EV01Input{Sweep: s, Umask: u, Scope: scope, Exceptions: []string{"/srv/data/drop"}, MinUmask: "027"}
	}

	sticky := base(sweep(ww("/srv/data/tmp", "1777", true, true)), umasks("027"))
	sticky.StickyAllowed = true

	partial := base(sweep(), umasks("027"))
	partial.Sweep.Snapshot.Unreadable = 2

	timedOut := base(sweep(ww("/etc/x", "0666", false, false)), umasks("027"))
	timedOut.Sweep.Snapshot.Status = fact.SweepTimeout

	symbolic := base(sweep(), &fact.UmaskSnapshot{Sources: []fact.UmaskSource{{Path: "/etc/profile", Status: fact.SourceRead, Umasks: []string{"027"}, Uninterpretable: []string{"u=rwx"}}}})

	badP07 := base(sweep(), umasks("027"))
	badP07.MinUmask = "abc"

	config := base(sweep(), umasks("027"))
	config.ConfigProblem = catalog.Says("param.not_set", "param", "P-02")

	cases := map[string]struct {
		in EV01Input
		w  want
	}{
		"config":                        {config, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-02"}}},
		"P-07 not octal":                {badP07, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-07"}}},
		"no sweep":                      {base(Sweep{}, umasks("027")), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"file_sweep_snapshot"}}},
		"no umask facts":                {base(sweep(), nil), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"umask read"}}},
		"clean":                         {base(sweep(), umasks("027", "077")), want{verdict.Compliant, "", []string{"2 umask declarations"}}},
		"world-writable in scope":       {base(sweep(ww("/etc/shadow-", "0666", false, false)), umasks("027")), want{verdict.NonCompliant, "", []string{"/etc/shadow- (0666)"}}},
		"outside scope ignored":         {base(sweep(ww("/tmp", "1777", true, true), ww("/etcetera/x", "0666", false, false)), umasks("027")), want{verdict.Compliant, "", nil}},
		"exception by exact path":       {base(sweep(ww("/srv/data/drop", "0777", true, false)), umasks("027")), want{verdict.Compliant, "", nil}},
		"sticky not allowed by default": {base(sweep(ww("/srv/data/tmp", "1777", true, true)), umasks("027")), want{verdict.NonCompliant, "", []string{"/srv/data/tmp"}}},
		"sticky allowed by P-03":        {sticky, want{verdict.Compliant, "", nil}},
		"umask bitwise, not numeric":    {base(sweep(), umasks("032")), want{verdict.NonCompliant, "", []string{"umask 032"}}},
		"weak umask":                    {base(sweep(), umasks("022")), want{verdict.NonCompliant, "", []string{"weaker than 027"}}},
		"partial sweep, nothing found":  {partial, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"directories that could not be read: 2"}}},
		"finding stands on a timeout":   {timedOut, want{verdict.NonCompliant, "", []string{"/etc/x"}}},
		"symbolic umask":                {symbolic, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"not octal"}}},
		"no declaration":                {base(sweep(), umasks()), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"no source declares"}}},
	}

	for name, c := range cases {
		check(t, name, JudgeEV01(c.in), c.w)
	}
}

func suid(path string) fact.SpecialFile {
	return fact.SpecialFile{Path: path, Kind: "file", Mode: "4755", SUID: true}
}

func TestJudgeEV07(t *testing.T) {
	baseline := []string{"/usr/bin/sudo", "/usr/bin/passwd"}

	unowned := fact.SpecialFile{Path: "/opt/app/bin", Kind: "file", Mode: "0755", UID: 1500, GID: 1500, NoOwner: true, NoGroup: true}

	timedOut := EV07Input{Sweep: sweep(suid("/usr/bin/sudo")), Authorized: baseline}
	timedOut.Sweep.Snapshot.Status = fact.SweepTimeout

	cases := map[string]struct {
		in EV07Input
		w  want
	}{
		"no sweep":                         {EV07Input{}, want{verdict.NotEvaluable, verdict.CauseCollection, nil}},
		"all reviewed":                     {EV07Input{Sweep: sweep(suid("/usr/bin/sudo"), suid("/usr/bin/passwd")), Authorized: baseline}, want{verdict.Compliant, "", []string{"2 SUID/SGID"}}},
		"unreviewed SUID":                  {EV07Input{Sweep: sweep(suid("/usr/bin/sudo"), suid("/tmp/x")), Authorized: baseline}, want{verdict.NonCompliant, "", []string{"/tmp/x (4755)"}}},
		"unowned without baseline":         {EV07Input{Sweep: sweep(unowned, suid("/usr/bin/sudo")), AuthorizedProblem: catalog.Says("param.not_set", "param", "P-00")}, want{verdict.NonCompliant, "", []string{"uid 1500"}}},
		"SUID without baseline":            {EV07Input{Sweep: sweep(suid("/usr/bin/sudo")), AuthorizedProblem: catalog.Says("param.not_set", "param", "P-00")}, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-10"}}},
		"no SUID needs no baseline":        {EV07Input{Sweep: sweep(), AuthorizedProblem: catalog.Says("param.not_set", "param", "P-00")}, want{verdict.Compliant, "", nil}},
		"timeout with nothing wrong found": {timedOut, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"time limit"}}},
	}

	for name, c := range cases {
		check(t, name, JudgeEV07(c.in), c.w)
	}
}

func accounts() Accounts {
	n, g := 5, 3
	return Accounts{
		Identity: &fact.IdentitySnapshot{PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &n},
		IdentityRecords: []fact.IdentityRecord{
			{AccountName: "root", UID: 0, GID: 0},
			{AccountName: "ana", UID: 1000, GID: 1000},
			{AccountName: "bob", UID: 1001, GID: 27},
			{AccountName: "eva", UID: 1002, GID: 1002},
			{AccountName: "ops1", UID: 1003, GID: 1003},
		},
		Groups: &fact.GroupSnapshot{GroupStatus: fact.SourceRead, RecordsEmitted: &g},
		GroupRecords: []fact.GroupRecord{
			{GroupName: "root", GID: 0, Members: []string{}},
			{GroupName: "sudo", GID: 27, Members: []string{"ana"}},
			{GroupName: "ops", GID: 1500, Members: []string{"ops1"}},
		},
	}
}

func sudoers(blind int, grants ...fact.SudoGrant) Sudoers {
	return Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceRead, BlindSpots: blind, BlindSpotReasons: []string{"/etc/sudoers:9: ALL users granted"}[:min(blind, 1)], RecordsEmitted: len(grants)}, Grants: grants}
}

func grant(kind, subject string) fact.SudoGrant {
	return fact.SudoGrant{SubjectKind: kind, Subject: subject, File: "/etc/sudoers", Line: 1}
}

func TestJudgeEV05(t *testing.T) {
	base := func(s Sudoers, declared ...string) EV05Input {
		return EV05Input{Accounts: accounts(), Sudoers: s, Groups: []string{"sudo"}, Declared: declared}
	}

	config := base(sudoers(0))
	config.ConfigProblem = catalog.Says("param.not_set", "param", "P-05")

	noGroups := base(sudoers(0))
	noGroups.Accounts.Groups = nil

	unreadable := base(sudoers(0))
	unreadable.Sudoers.Snapshot.Status = fact.SourceUnreadable

	cases := map[string]struct {
		in EV05Input
		w  want
	}{
		"config":                         {config, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-05"}}},
		"no groups":                      {noGroups, want{verdict.NotEvaluable, verdict.CauseCollection, nil}},
		"no sudoers facts":               {EV05Input{Accounts: accounts(), Groups: []string{"sudo"}}, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"read of the sudo rules"}}},
		"sudoers unreadable":             {unreadable, want{verdict.NotEvaluable, verdict.CauseCollection, nil}},
		"all declared":                   {base(sudoers(0, grant("user", "root"), grant("group", "sudo")), "ana", "bob"), want{verdict.Compliant, "", []string{"2 privileged accounts"}}},
		"primary group member counts":    {base(sudoers(0), "ana"), want{verdict.NonCompliant, "", []string{"bob (group sudo)"}}},
		"sudo user grant":                {base(sudoers(0, grant("user", "eva")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"eva (sudoers /etc/sudoers:1)"}}},
		"sudo by uid":                    {base(sudoers(0, grant("uid", "1002")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"eva"}}},
		"sudo by gid":                    {base(sudoers(0, grant("gid", "1500")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"ops1"}}},
		"blind spots, nothing found":     {base(sudoers(1), "ana", "bob"), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"ALL users"}}},
		"blind spots do not hide a find": {base(sudoers(1, grant("user", "eva")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"eva"}}},
		"unknown group":                  {base(sudoers(0, grant("group", "ghosts")), "ana", "bob"), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"%ghosts"}}},
		"no sudo installed":              {base(Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceAbsent}}, "ana", "bob"), want{verdict.Compliant, "", nil}},
	}

	for name, c := range cases {
		check(t, name, JudgeEV05(c.in), c.w)
	}
}

func wazuhConfig(dirs ...fact.FIMDirectory) *fact.WazuhAgentConfig {
	return &fact.WazuhAgentConfig{Status: fact.SourceRead, SyscheckFrequency: 43200, Directories: dirs, Ignored: []string{"/etc/mtab"}}
}

func TestJudgeEV02(t *testing.T) {

	etc := wazuhConfig(fact.FIMDirectory{Path: "/etc"})
	critical := []string{"/etc/passwd", "/etc/sudoers.d"}
	change := source.FIMChange{Path: "/etc/sudoers.d/90-ops", Event: "added", Time: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)}
	other := source.FIMChange{Path: "/etc/hosts", Event: "modified"}

	check(t, "unchanged", JudgeEV02(EV02Input{Config: etc, Changes: []source.FIMChange{other}, Window: 26 * time.Hour, Critical: critical}), want{verdict.Compliant, "", []string{"2 critical paths"}})
	check(t, "changed", JudgeEV02(EV02Input{Config: etc, Changes: []source.FIMChange{change}, Window: 26 * time.Hour, Critical: critical}), want{verdict.NonCompliant, "", []string{"/etc/sudoers.d/90-ops added"}})
	check(t, "not watched", JudgeEV02(EV02Input{Config: wazuhConfig(fact.FIMDirectory{Path: "/usr/bin"}), Window: 26 * time.Hour, Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"/etc/passwd (no FIM directory covers it)"}})

	slow := wazuhConfig(fact.FIMDirectory{Path: "/etc"})
	slow.SyscheckFrequency = 7 * 86400
	check(t, "scans too far apart", JudgeEV02(EV02Input{Config: slow, Window: 26 * time.Hour, Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"longer than the evaluation window"}})
	realtime := wazuhConfig(fact.FIMDirectory{Path: "/etc", Realtime: true})
	realtime.SyscheckFrequency = 7 * 86400
	check(t, "realtime", JudgeEV02(EV02Input{Config: realtime, Window: 26 * time.Hour, Critical: critical}), want{verdict.Compliant, "", nil})

	off := wazuhConfig(fact.FIMDirectory{Path: "/etc"})
	off.SyscheckDisabled = true
	check(t, "FIM off", JudgeEV02(EV02Input{Config: off, Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"disabled"}})
	check(t, "no config", JudgeEV02(EV02Input{Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, nil})
	check(t, "P-02 missing", JudgeEV02(EV02Input{CriticalProblem: catalog.Says("param.not_set", "param", "P-00")}), want{verdict.NotEvaluable, verdict.CauseConfiguration, nil})
}

func TestJudgeEV03(t *testing.T) {

	reaches := passes.AuthLog{Known: true, Reaches: true, Detail: catalog.Says("probe.back", "run", "r1", "ts", "2026-10-01T00:00:00Z")}
	s := sudoers(0, grant("group", "sudo"))
	base := func(e ...source.Elevation) EV03Input {
		return EV03Input{Accounts: accounts(), Sudoers: s, Elevations: e, Log: reaches, Groups: []string{"sudo"}}
	}

	check(t, "admin sudo", JudgeEV03(base(source.Elevation{From: "ana", To: "root", Method: "sudo"})), want{verdict.Compliant, "", []string{"1 elevation"}})
	check(t, "su to root by eva", JudgeEV03(base(source.Elevation{From: "eva", To: "root", Method: "su"})), want{verdict.NonCompliant, "", []string{"su by eva to root"}})
	check(t, "lateral", JudgeEV03(base(source.Elevation{From: "eva", To: "ops1", Method: "su"})), want{verdict.Compliant, "", nil})
	check(t, "refusal", JudgeEV03(base(source.Elevation{From: "eva", To: "root", Method: "sudo", Denied: true})), want{verdict.Compliant, "", []string{"1 refused"}})
	check(t, "LDAP user", JudgeEV03(base(source.Elevation{From: "ldapuser", To: "root", Method: "sudo"})), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"not a local account"}})

	blind := base(source.Elevation{From: "eva", To: "root", Method: "sudo"})
	blind.Sudoers = sudoers(1, grant("group", "sudo"))
	check(t, "sudoers blind spots", JudgeEV03(blind), want{verdict.NotEvaluable, verdict.CauseCollection, nil})

	quiet := base()
	quiet.Log = passes.AuthLog{Known: true, Detail: catalog.Says("probe.lost", "count", 2)}
	check(t, "quiet and blind", JudgeEV03(quiet), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"never reached"}})
	check(t, "quiet and reaching", JudgeEV03(base()), want{verdict.Compliant, "", nil})
}

func TestJudgeEV04(t *testing.T) {

	acls := func(records ...fact.ACLRecord) ACLs {
		return ACLs{Snapshot: &fact.ACLSnapshot{Config: "/var/ossec/etc/shared/agent.conf", Status: fact.SourceRead, RecordsEmitted: len(records)}, Records: records}
	}
	datos := fact.ACLRecord{Path: "/srv/datos", Status: fact.SourceRead, Mode: "0750", Owner: "root:ops", ACL: []string{"g:auditors:r-x", "m::r-x", "u:auditor:r-x"}}

	check(t, "as declared", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | root:ops | user:auditor:rx, g:auditors:r-x"}}), want{verdict.Compliant, "", []string{"1 resource"}})
	check(t, "mode", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 0700 | | u:auditor:r-x,g:auditors:r-x"}}), want{verdict.NonCompliant, "", []string{"mode 0750, declared 0700"}})
	check(t, "owner", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | root:root | u:auditor:r-x g:auditors:r-x"}}), want{verdict.NonCompliant, "", []string{"owner root:ops"}})
	check(t, "undeclared entry", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | root:ops | u:auditor:r-x"}}), want{verdict.NonCompliant, "", []string{"undeclared entries: g:auditors:r-x"}})
	check(t, "missing entry", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | | u:auditor:r-x g:auditors:r-x u:eva:rwx"}}), want{verdict.NonCompliant, "", []string{"lacks declared entries: u:eva:rwx"}})
	check(t, "path missing", JudgeEV04(EV04Input{ACLs: acls(fact.ACLRecord{Path: "/srv/x", Status: fact.SourceAbsent}), Rows: []string{"/srv/x | 750 | |"}}), want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"does not have: /srv/x"}})
	check(t, "a missing path does not hide a deviation", JudgeEV04(EV04Input{ACLs: acls(datos, fact.ACLRecord{Path: "/srv/x", Status: fact.SourceAbsent}), Rows: []string{"/srv/datos | 0700 | |", "/srv/x | 750 | |"}}), want{verdict.NonCompliant, "", []string{"mode 0750"}})
	check(t, "not sent", JudgeEV04(EV04Input{ACLs: acls(), Rows: []string{"/srv/y | 750 | |"}}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"does not receive this path"}})
	check(t, "no paths in the group configuration", JudgeEV04(EV04Input{ACLs: ACLs{Snapshot: &fact.ACLSnapshot{Status: fact.SourceAbsent}}, Rows: []string{"/srv/y | 750 | |"}}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"group configuration"}})
	check(t, "P-08 missing", JudgeEV04(EV04Input{RowsProblem: catalog.Says("param.not_set", "param", "P-08")}), want{verdict.NotEvaluable, verdict.CauseConfiguration, nil})
}

func TestJudgeEV06(t *testing.T) {

	watches := &fact.AuditWatchSnapshot{Auditd: fact.AuditdRunning, Wanted: []string{"/srv/datos"}, Loaded: []string{"/srv/datos"}}
	config := &fact.WazuhAgentConfig{Status: fact.SourceRead, Localfiles: []fact.AgentLocalfile{{Location: "/var/log/audit/audit.log", Format: "audit"}}}
	rules := []string{"ops | /srv/datos | lectura,escritura", "ops | /srv/datos/ro | lectura"}
	profiles := []string{"ana | ops | sudo:no"}
	access := func(key, auid, path string) source.AuditAccess {
		return source.AuditAccess{Key: key, Success: "yes", AUID: auid, Path: path}
	}
	base := func(a ...source.AuditAccess) EV06Input {
		return EV06Input{Watches: watches, Config: config, Accesses: a, Accounts: accounts(), Rules: rules, Profiles: profiles}
	}

	check(t, "within", JudgeEV06(base(access("oscompliance_write", "1000", "/srv/datos/a.txt"))), want{verdict.Compliant, "", []string{"1 access"}})
	check(t, "longest path wins", JudgeEV06(base(access("oscompliance_write", "1000", "/srv/datos/ro/b.txt"))), want{verdict.NonCompliant, "", []string{"escritura by ana (profile ops) on /srv/datos/ro/b.txt"}})
	check(t, "no profile", JudgeEV06(base(access("oscompliance_exec", "1002", "/srv/datos/x"))), want{verdict.Compliant, "", []string{"1 by accounts without a P-09 profile"}})
	check(t, "no person", JudgeEV06(base(access("oscompliance_read", "4294967295", "/srv/datos/x"))), want{verdict.NotEvaluable, verdict.CauseEvidence, []string{"no person"}})
	check(t, "syscall without a path", JudgeEV06(base(access("oscompliance_attr", "4294967295", ""), access("oscompliance_write", "1000", "/srv/datos/a.txt"))), want{verdict.Compliant, "", []string{"1 access"}})

	stopped := base()
	stopped.Watches = &fact.AuditWatchSnapshot{Auditd: fact.AuditdAbsent}
	check(t, "no auditd", JudgeEV06(stopped), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"auditd absent"}})
	unread := base()
	unread.Config = &fact.WazuhAgentConfig{Status: fact.SourceRead}
	check(t, "audit log not read", JudgeEV06(unread), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"auditd audit log"}})
	check(t, "params", JudgeEV06(EV06Input{Problem: catalog.Says("param.not_set", "param", "P-06")}), want{verdict.NotEvaluable, verdict.CauseConfiguration, nil})
}
