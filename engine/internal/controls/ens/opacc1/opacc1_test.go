package opacc1

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/history"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type fakeFacts struct {
	currentIdentity map[string][]fact.IdentitySnapshot
	earlierIdentity map[string][]fact.IdentitySnapshot
	identityRecords map[string][]fact.IdentityRecord
	identityAsked   []string
	failIdentityRun string
	probes          map[string]map[string]bool
}

func (f *fakeFacts) ProbesSeen(context.Context, time.Time) (map[string]map[string]bool, error) {
	return f.probes, nil
}

func (f *fakeFacts) IdentitySnapshots(_ context.Context, _ time.Time, n int) (map[string][]fact.IdentitySnapshot, error) {
	if n == 1 {
		return f.currentIdentity, nil
	}
	return f.earlierIdentity, nil
}

func (f *fakeFacts) IdentityRecords(_ context.Context, _, runID string, _ time.Time) ([]fact.IdentityRecord, error) {
	f.identityAsked = append(f.identityAsked, runID)
	if runID == f.failIdentityRun {
		return nil, errors.New("boom")
	}
	return f.identityRecords[runID], nil
}

func (f *fakeFacts) Logins(context.Context, string, time.Time) ([]source.Login, error) {
	return nil, nil
}

func (f *fakeFacts) AuthActivity(context.Context, time.Time) (map[string]time.Time, error) {
	return nil, nil
}

func (f *fakeFacts) GroupSnapshots(context.Context, time.Time) (map[string]fact.GroupSnapshot, error) {
	return nil, nil
}

func (f *fakeFacts) GroupRecords(context.Context, string, string, time.Time) ([]fact.GroupRecord, error) {
	return nil, nil
}

type memHistory struct{ saved []history.Account }

func (m *memHistory) Load(context.Context, string) (map[string]history.Account, error) {
	return map[string]history.Account{}, nil
}

func (m *memHistory) Save(_ context.Context, accounts []history.Account) error {
	m.saved = append(m.saved, accounts...)
	return nil
}

type noParams struct{}

func (noParams) List(string, string, string) ([]string, error) { return nil, params.ErrNotSet }

func (noParams) ListColumn(string, string, string, int) ([]string, error) {
	return nil, params.ErrNotSet
}

func (noParams) Number(string, string, string) (float64, error) { return 0, params.ErrNotSet }

func (noParams) Bool(string, string, string) (bool, error) { return false, params.ErrNotSet }

func (noParams) Matcher(string, string, string) (params.Matcher, error) {
	return params.Matcher{}, params.ErrNotSet
}

func (noParams) Level() string { return "" }

func (noParams) ControlEnabled(string) bool { return true }

func identityPass(runID string, emitted int, read bool) fact.IdentitySnapshot {
	s := fact.IdentitySnapshot{Envelope: fact.Envelope{RunID: runID, TS: "2026-10-22T12:00:00Z"}, PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &emitted}
	if !read {
		s.ShadowStatus, s.ShadowError, s.RecordsEmitted = fact.SourceUnreadable, "denied", nil
	}
	return s
}

func begin(t *testing.T, facts Facts, hist History) *Evaluator {
	t.Helper()
	e := NewEvaluator(facts, hist)
	now := time.Date(2026, 10, 22, 13, 0, 0, 0, time.UTC)
	if err := e.Begin(context.Background(), evaluator.Pass{Now: now, WindowStart: now.Add(-26 * time.Hour), LookbackStart: now.Add(-168 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEvaluatorPicksPreviousCompleteIdentityPass(t *testing.T) {
	cur := identityPass("cur", 1, true)
	facts := &fakeFacts{
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {cur}},
		earlierIdentity: map[string][]fact.IdentitySnapshot{"001": {
			cur,
			identityPass("unread", 0, false),
			identityPass("incomplete", 2, true),
			identityPass("good", 1, true),
			identityPass("older", 1, true),
		}},
		identityRecords: map[string][]fact.IdentityRecord{
			"cur": {{AccountName: "root"}}, "incomplete": {{}}, "good": {{AccountName: "root"}}, "older": {{}},
		},
	}

	results, err := begin(t, facts, &memHistory{}).Agent(context.Background(), verdict.Agent{ID: "001"}, noParams{})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"cur", "incomplete", "good"}
	if len(facts.identityAsked) != len(want) {
		t.Fatalf("records asked for %v, want %v", facts.identityAsked, want)
	}
	for i := range want {
		if facts.identityAsked[i] != want[i] {
			t.Fatalf("records asked for %v, want %v", facts.identityAsked, want)
		}
	}

	if len(results) != 8 {
		t.Errorf("want 8 evidence results, got %d", len(results))
	}
	if r := results["EV-02"]; r.RunID != "cur" || r.Judgement.Status != verdict.Compliant {
		t.Errorf("EV-02: %+v", r)
	}
}

func TestEvaluatorKeepsOtherEvidencesOnReadError(t *testing.T) {
	facts := &fakeFacts{
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {identityPass("cur", 1, true)}},
		failIdentityRun: "cur",
	}

	results, err := begin(t, facts, &memHistory{}).Agent(context.Background(), verdict.Agent{ID: "001"}, noParams{})
	if err == nil {
		t.Error("want the read error")
	}
	for _, id := range []string{"EV-01", "EV-02", "EV-04", "EV-07", "EV-08"} {
		if _, ok := results[id]; ok {
			t.Errorf("%s judged despite the read error", id)
		}
	}
	for _, id := range []string{"EV-03", "EV-05", "EV-06"} {
		if _, ok := results[id]; !ok {
			t.Errorf("%s missing", id)
		}
	}
}

func TestEvaluatorSavesHistory(t *testing.T) {
	facts := &fakeFacts{
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {identityPass("cur", 1, true)}},
		identityRecords: map[string][]fact.IdentityRecord{"cur": {{AccountName: "ana", UID: 1500, Shell: "/bin/bash", PasswordState: "set"}}},
	}
	hist := &memHistory{}

	if _, err := begin(t, facts, hist).Agent(context.Background(), verdict.Agent{ID: "001", Name: "a"}, noParams{}); err != nil {
		t.Fatal(err)
	}
	if len(hist.saved) != 1 || hist.saved[0].AccountName != "ana" || hist.saved[0].AgentName != "a" {
		t.Errorf("saved: %+v", hist.saved)
	}
}

var evalDay = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

func account(name string, uid int, state string, keys int) fact.IdentityRecord {
	r := fact.IdentityRecord{AccountName: name, UID: uid, GID: uid, Shell: "/bin/bash", PasswordState: state}
	if keys >= 0 {
		r.AuthorizedKeys = &keys
	}
	return r
}

func inventory(records ...fact.IdentityRecord) Inventory {
	return Inventory{Current: identitySnapshot("cur", len(records)), Records: records, UIDMin: DefaultUIDMin, Today: evalDay}
}

func TestJudgeEV01(t *testing.T) {
	root := account("root", 0, "locked", 0)

	badP10 := inventory(root)
	badP10.UIDMinProblem = catalog.Says("param.invalid", "param", "P-10", "error", `"many" is not a number`)

	incomplete := inventory(root)
	incomplete.Current = identitySnapshot("cur", 3)

	shadowDenied := inventory()
	shadowDenied.Current.ShadowStatus, shadowDenied.Current.ShadowError, shadowDenied.Current.RecordsEmitted = fact.SourceUnreadable, "permission denied", nil

	cases := []struct {
		name    string
		in      Inventory
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-10 unusable", badP10, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-10"}},
		{"no identity pass", Inventory{UIDMin: DefaultUIDMin}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"shadow unreadable", shadowDenied, verdict.NotEvaluable, verdict.CauseCollection, []string{"permission denied"}},
		{"incomplete pass", incomplete, verdict.NotEvaluable, verdict.CauseCollection, []string{"1 of 3"}},
		{"duplicate UIDs, system ones included", inventory(root, account("toor", 0, "locked", 0), account("ana", 1001, "set", 0), account("bob", 1001, "set", 0)), verdict.NonCompliant, "", []string{"UID 0 (root, toor); UID 1001 (ana, bob)"}},
		{"unique UIDs", inventory(root, account("daemon", 1, "locked", 0), account("ana", 1001, "set", 0)), verdict.Compliant, "", []string{"3 accounts, 1 of people (UID from 1000"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV01(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			if got.Status != verdict.Compliant && got.Reason == "" {
				t.Error("empty reason")
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

func identity(name string, uid int, state string) fact.IdentityRecord {
	return fact.IdentityRecord{
		Envelope:    fact.Envelope{RunID: "run-" + name, TS: "2026-10-21T14:00:00Z"},
		AccountName: name, UID: uid, GID: uid, Shell: "/bin/bash", PasswordState: state,
	}
}

func TestDiffIdentities(t *testing.T) {

	root := identity("root", 0, "locked")
	alice := identity("alice", 1000, "set")
	bob := identity("bob", 1001, "set")

	aliceLocked := alice
	aliceLocked.PasswordState = "locked"

	bobOtherPass := bob
	bobOtherPass.RunID, bobOtherPass.TS, bobOtherPass.AgentVersion = "other", "2026-10-22T00:00:00Z", "2"

	one, otherOne, two := 1, 1, 2
	keyed := identity("kim", 1004, "locked")
	keyed.AuthorizedKeys = &one
	keyedSame := keyed
	keyedSame.AuthorizedKeys = &otherOne
	keyedMore := keyed
	keyedMore.AuthorizedKeys = &two
	keyedUnknown := keyed
	keyedUnknown.AuthorizedKeys = nil

	carol := identity("carol", 1002, "set")
	dave := identity("dave", 1003, "set")
	daveExpires := dave
	daveExpires.AccountExpires = "2027-01-01"

	cases := []struct {
		name     string
		previous []fact.IdentityRecord
		current  []fact.IdentityRecord
		want     IdentityChanges
	}{
		{"same accounts, envelope differs", []fact.IdentityRecord{root, bob}, []fact.IdentityRecord{root, bobOtherPass}, IdentityChanges{}},
		{"created", []fact.IdentityRecord{root}, []fact.IdentityRecord{root, carol, alice}, IdentityChanges{Created: []string{"alice", "carol"}}},
		{"deleted", []fact.IdentityRecord{root, bob, alice}, []fact.IdentityRecord{root}, IdentityChanges{Deleted: []string{"alice", "bob"}}},
		{"modified password state", []fact.IdentityRecord{alice}, []fact.IdentityRecord{aliceLocked}, IdentityChanges{Modified: []string{"alice"}}},
		{"modified expiry", []fact.IdentityRecord{dave}, []fact.IdentityRecord{daveExpires}, IdentityChanges{Modified: []string{"dave"}}},
		{"all three", []fact.IdentityRecord{root, alice, bob}, []fact.IdentityRecord{root, aliceLocked, carol}, IdentityChanges{Created: []string{"carol"}, Deleted: []string{"bob"}, Modified: []string{"alice"}}},
		{"same key count in another pass", []fact.IdentityRecord{keyed}, []fact.IdentityRecord{keyedSame}, IdentityChanges{}},
		{"key added", []fact.IdentityRecord{keyed}, []fact.IdentityRecord{keyedMore}, IdentityChanges{Modified: []string{"kim"}}},
		{"keys became unknown", []fact.IdentityRecord{keyed}, []fact.IdentityRecord{keyedUnknown}, IdentityChanges{Modified: []string{"kim"}}},
		{"name twice: first wins", []fact.IdentityRecord{alice}, []fact.IdentityRecord{alice, aliceLocked}, IdentityChanges{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DiffIdentities(c.previous, c.current)

			if !sameList(got.Created, c.want.Created) || !sameList(got.Deleted, c.want.Deleted) || !sameList(got.Modified, c.want.Modified) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func sameList(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func identitySnapshot(runID string, emitted int) *fact.IdentitySnapshot {
	return &fact.IdentitySnapshot{
		Envelope:   fact.Envelope{RunID: runID},
		PasswdPath: "/etc/passwd", PasswdStatus: fact.SourceRead,
		ShadowPath: "/etc/shadow", ShadowStatus: fact.SourceRead,
		RecordsEmitted: &emitted,
	}
}

func TestJudgeEV02(t *testing.T) {

	root := identity("root", 0, "locked")
	alice := identity("alice", 1000, "set")
	bob := identity("bob", 1001, "set")

	shadowDenied := identitySnapshot("cur", 0)
	shadowDenied.ShadowStatus, shadowDenied.ShadowError, shadowDenied.RecordsEmitted = fact.SourceUnreadable, "permission denied", nil

	passwdBad := identitySnapshot("cur", 0)
	passwdBad.PasswdStatus, passwdBad.PasswdError = fact.SourceImplausible, "no entry with UID 0"
	passwdBad.ShadowStatus, passwdBad.ShadowError, passwdBad.RecordsEmitted = fact.SourceUnreadable, "not read", nil

	noCounter := identitySnapshot("cur", 0)
	noCounter.RecordsEmitted = nil

	cases := []struct {
		name    string
		in      EV02Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"no snapshot", EV02Input{}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"shadow unreadable", EV02Input{Current: shadowDenied}, verdict.NotEvaluable, verdict.CauseCollection, []string{"permission denied"}},
		{"passwd implausible", EV02Input{Current: passwdBad}, verdict.NotEvaluable, verdict.CauseCollection, []string{"no entry with UID 0"}},
		{"read without counter", EV02Input{Current: noCounter}, verdict.NotEvaluable, verdict.CauseEvidence, []string{"how many records"}},
		{"incomplete pass", EV02Input{Current: identitySnapshot("cur", 3), Records: []fact.IdentityRecord{root}}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"baseline", EV02Input{Current: identitySnapshot("cur", 2), Records: []fact.IdentityRecord{root, alice}}, verdict.Compliant, "", []string{"baseline", "2 accounts"}},
		{"no changes", EV02Input{
			Current: identitySnapshot("cur", 2), Records: []fact.IdentityRecord{root, alice},
			Previous: identitySnapshot("prev", 2), PreviousRecords: []fact.IdentityRecord{root, alice},
		}, verdict.Compliant, "", []string{"no account changes since the previous pass"}},
		{"changes", EV02Input{
			Current: identitySnapshot("cur", 2), Records: []fact.IdentityRecord{root, bob},
			Previous: identitySnapshot("prev", 2), PreviousRecords: []fact.IdentityRecord{root, alice},
		}, verdict.Compliant, "", []string{"since the previous pass", "created: bob", "deleted: alice"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV02(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			if got.Status != verdict.Compliant && got.Reason == "" {
				t.Error("empty reason")
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
			if strings.Contains(got.Reason, "modified") && c.name == "changes" {
				t.Errorf("reason lists an empty list: %q", got.Reason)
			}
		})
	}
}

func login(account string) source.Login {
	return source.Login{Time: time.Date(2026, 10, 22, 11, 40, 0, 0, time.UTC), Account: account, SourceIP: "10.0.0.9", Method: source.MethodSSHD}
}

func TestJudgeEV03(t *testing.T) {
	generic := params.ListMatcher("admin", "guest", "test")

	pattern, err := params.PatternMatcher("(adm|tmp)[0-9]*")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		in      LoginInput
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-04 not set", LoginInput{ForbiddenProblem: catalog.Says("param.not_set", "param", "P-04"), AuthSeen: true}, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-04", "not set"}},
		{"P-04 problem wins over a silent source", LoginInput{ForbiddenProblem: catalog.Says("param.not_set", "param", "P-04")}, verdict.NotEvaluable, verdict.CauseConfiguration, nil},
		{"no authentication events", LoginInput{Forbidden: generic}, verdict.NotEvaluable, verdict.CauseCollection, []string{"no authentication events"}},
		{"generic account logged in", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), login("admin")}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"case is ignored", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("Admin")}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"one account whatever its case", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("Admin"), login("admin")}}, verdict.NonCompliant, "", []string{"admin (2)"}},
		{"counted and sorted", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("test"), login("admin"), login("test")}}, verdict.NonCompliant, "", []string{"admin (1), test (2)"}},
		{"only named accounts", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), login("mgarcia")}}, verdict.Compliant, "", []string{"2 logins in the window (sshd 2)"}},
		{"su to a generic account counts", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{{Account: "admin", Method: source.MethodSU}}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"methods counted", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), {Account: "ana", Method: source.MethodConsole}, {Account: "ana", Method: source.MethodSU}}}, verdict.Compliant, "", []string{"3 logins in the window (console 1, sshd 1, su 1)"}},
		{"pattern: whole name", LoginInput{Forbidden: pattern, AuthSeen: true, Logins: []source.Login{login("tmp7"), login("admin"), login("xadm")}}, verdict.NonCompliant, "", []string{"generic accounts authenticated: tmp7 (1)"}},
		{"source alive, no logins", LoginInput{Forbidden: generic, AuthSeen: true}, verdict.Compliant, "", []string{"0 logins in the window, none"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV03(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			if got.Status != verdict.Compliant && got.Reason == "" {
				t.Error("empty reason")
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

func TestJudgeEV05(t *testing.T) {
	service := params.ListMatcher("daemon", "www-data", "sshd")

	got := JudgeEV05(LoginInput{Forbidden: service, AuthSeen: true, Logins: []source.Login{login("jperez"), login("www-data")}})
	if got.Status != verdict.NonCompliant || !strings.Contains(got.Reason, "service accounts authenticated: www-data (1)") {
		t.Errorf("service login: %+v", got)
	}

	got = JudgeEV05(LoginInput{Forbidden: service, AuthSeen: true, Logins: []source.Login{login("jperez")}})
	if got.Status != verdict.Compliant || !strings.Contains(got.Reason, "P-03") {
		t.Errorf("named login: %+v", got)
	}

	got = JudgeEV05(LoginInput{ForbiddenProblem: catalog.Says("param.not_set", "param", "P-03"), AuthSeen: true})
	if got.Status != verdict.NotEvaluable || got.Cause != verdict.CauseConfiguration || !strings.Contains(got.Reason, "P-03: not set") {
		t.Errorf("P-03 not set: %+v", got)
	}
}

func person(name string, state, expires string) fact.IdentityRecord {
	none := 0
	return fact.IdentityRecord{AccountName: name, UID: 1500, GID: 1500, Shell: "/bin/bash", PasswordState: state, AccountExpires: expires, AuthorizedKeys: &none}
}

func withKeys(r fact.IdentityRecord, n int) fact.IdentityRecord {
	r.AuthorizedKeys = &n
	return r
}

func keysUnknown(r fact.IdentityRecord) fact.IdentityRecord {
	r.AuthorizedKeys = nil
	return r
}

func TestIsDisabled(t *testing.T) {
	today := day("2026-10-22")

	nologin := person("a", "set", "")
	nologin.Shell = "/usr/sbin/nologin"

	cases := []struct {
		name            string
		record          fact.IdentityRecord
		disabled, known bool
	}{
		{"no-login shell", nologin, true, true},
		{"expired", person("a", "set", "2026-10-01"), true, true},
		{"expires later", person("a", "set", "2027-01-01"), false, true},
		{"usable password", person("a", "set", ""), false, true},
		{"empty password logs in", person("a", "empty", ""), false, true},
		{"locked, no keys", person("a", "locked", ""), true, true},
		{"locked, with a key: still logs in", withKeys(person("a", "locked", ""), 1), false, true},
		{"no shadow entry, no keys", person("a", "missing", ""), true, true},
		{"locked, keys unknown", keysUnknown(person("a", "locked", "")), false, false},
		{"usable password, keys unknown: keys do not matter", keysUnknown(person("a", "set", "")), false, true},
	}

	for _, c := range cases {
		if d, k := IsDisabled(c.record, today); d != c.disabled || k != c.known {
			t.Errorf("%s: got disabled=%v known=%v, want %v %v", c.name, d, k, c.disabled, c.known)
		}
	}
}

func day(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestJudgeEV04(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

	base := func(accounts ...fact.IdentityRecord) EV04Input {
		return EV04Input{Accounts: accounts, Declared: map[string]time.Time{}, DeadlineDays: 1, UIDMin: DefaultUIDMin, Now: now}
	}
	declare := func(in EV04Input, name, date string) EV04Input {
		in.Declared[name] = day(date)
		in.DeclaredSet = true
		return in
	}

	system := person("svc", "set", "")
	system.UID = 500

	nologin := person("ana", "set", "")
	nologin.Shell = "/usr/sbin/nologin"

	badConfig := base()
	badConfig.ConfigProblem = catalog.Says("param.not_set", "param", "P-05")

	noIdentity := base()
	noIdentity.Accounts, noIdentity.AccountsProblem = nil, catalog.Says("opacc1.no_identity_pass_lookback")

	cases := []struct {
		name    string
		in      EV04Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"configuration problem", badConfig, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-05"}},
		{"no identity table", noIdentity, verdict.NotEvaluable, verdict.CauseCollection, []string{"no complete pass of the account inventory"}},
		{"declared and still enabled past the deadline", declare(base(person("antonio", "set", "")), "antonio", "2026-10-01"), verdict.NonCompliant, "", []string{"antonio (21 days)", "1 days (P-05)"}},
		{"declared, within the deadline", declare(base(person("antonio", "set", "")), "antonio", "2026-10-21"), verdict.Compliant, "", []string{"1 accounts"}},
		{"declared and locked, no keys", declare(base(person("antonio", "locked", "")), "antonio", "2026-10-01"), verdict.Compliant, "", nil},
		{"declared, locked but with a key", declare(base(withKeys(person("antonio", "locked", ""), 1)), "antonio", "2026-10-01"), verdict.NonCompliant, "", []string{"antonio (21 days)"}},
		{"declared, locked, keys unknown", declare(base(keysUnknown(person("antonio", "locked", ""))), "antonio", "2026-10-01"), verdict.NotEvaluable, verdict.CauseEvidence, []string{"SSH keys that cannot be read: antonio"}},
		{"keys unknown but within the deadline", declare(base(keysUnknown(person("antonio", "locked", ""))), "antonio", "2026-10-21"), verdict.Compliant, "", nil},
		{"declared and no-login shell", declare(base(nologin), "ana", "2026-10-01"), verdict.Compliant, "", nil},
		{"declared, account already deleted", declare(base(person("jperez", "set", "")), "antonio", "2026-07-31"), verdict.Compliant, "", []string{"0 accounts"}},
		{"expiry in the past disables", base(person("eva", "set", "2026-09-01")), verdict.Compliant, "", []string{"1 accounts"}},
		{"system account ignored", declare(base(system), "svc", "2026-01-01"), verdict.Compliant, "", []string{"0 accounts"}},
		{"no dates at all", base(person("jperez", "set", "")), verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-09 is empty"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV04(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

func groupPass(groups ...fact.GroupRecord) (*fact.GroupSnapshot, []fact.GroupRecord) {
	n := len(groups)
	return &fact.GroupSnapshot{Envelope: fact.Envelope{RunID: "g1"}, GroupPath: "/etc/group", GroupStatus: fact.SourceRead, RecordsEmitted: &n}, groups
}

func group(name string, members ...string) fact.GroupRecord {
	if members == nil {
		members = []string{}
	}
	return fact.GroupRecord{GroupName: name, Members: members}
}

func TestJudgeEV06(t *testing.T) {
	base := func(groups ...fact.GroupRecord) EV06Input {
		snapshot, records := groupPass(groups...)
		return EV06Input{
			Groups: snapshot, GroupRecords: records,
			Accounts:   []string{"root", "ubuntu", "jperez", "jperez.adm", "mgarcia"},
			Privileged: DefaultPrivilegedGroups, AdminAffixes: []AdminAffix{{Text: ".adm"}}, AuthSeen: true,
		}
	}

	withLogins := func(in EV06Input, accounts ...string) EV06Input {
		for _, a := range accounts {
			in.Logins = append(in.Logins, source.Login{Account: a})
		}
		return in
	}

	unread := base()
	unread.Groups = &fact.GroupSnapshot{GroupPath: "/etc/group", GroupStatus: fact.SourceUnreadable, GroupError: "denied"}

	incomplete := base(group("sudo"))
	two := 2
	incomplete.Groups.RecordsEmitted = &two

	noAccounts := base(group("sudo", "ubuntu"))
	noAccounts.Accounts, noAccounts.AccountsProblem = nil, catalog.Says("opacc1.no_identity_pass_lookback")

	badP11 := base()
	badP11.ConfigProblem = catalog.Says("param.invalid", "param", "P-11", "error", "regex not supported")

	silent := base(group("sudo", "jperez.adm"))
	silent.AuthSeen = false

	silentWithFinding := base(group("sudo", "ubuntu"))
	silentWithFinding.AuthSeen = false

	noAffix := base(group("sudo", "jperez"))
	noAffix.AdminAffixes = nil

	both := func(groups ...fact.GroupRecord) EV06Input {
		in := base(groups...)
		in.Accounts = append(in.Accounts, "adm_mgarcia")
		in.AdminAffixes = []AdminAffix{{Text: ".adm"}, {Text: "adm_", Prefix: true}}
		return in
	}

	defaulted := base(group("sudo", "jperez.adm"))
	defaulted.PrivilegedDefault = true

	cases := []struct {
		name    string
		in      EV06Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-11 unusable", badP11, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-11"}},
		{"no group snapshot", EV06Input{Privileged: DefaultPrivilegedGroups}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"group file unread", unread, verdict.NotEvaluable, verdict.CauseCollection, []string{"denied"}},
		{"incomplete group pass", incomplete, verdict.NotEvaluable, verdict.CauseCollection, []string{"1 of 2"}},
		{"account list unavailable", noAccounts, verdict.NotEvaluable, verdict.CauseCollection, []string{"no complete pass of the account inventory"}},
		{"privileged member without admin identity", base(group("sudo", "ubuntu"), group("adm", "ubuntu")), verdict.NonCompliant, "", []string{"no separate admin identity: ubuntu (sudo)"}},
		{"admin identity exists", base(group("sudo", "jperez")), verdict.Compliant, "", []string{"1 members"}},
		{"admin account itself is not a finding", base(group("wheel", "jperez.adm")), verdict.Compliant, "", nil},
		{"member of two privileged groups", base(group("sudo", "mgarcia"), group("wheel", "mgarcia")), verdict.NonCompliant, "", []string{"mgarcia (sudo, wheel)"}},
		{"login with the privileged identity", withLogins(base(group("sudo", "jperez")), "jperez", "jperez", "mgarcia"), verdict.NonCompliant, "", []string{"privileged identity used to log in: jperez (2)"}},
		{"login with the admin identity is fine", withLogins(base(group("sudo", "jperez.adm")), "jperez.adm"), verdict.Compliant, "", nil},
		{"no convention: nobody excluded", noAffix, verdict.NonCompliant, "", []string{"jperez (sudo)"}},
		{"both conventions pair each person", both(group("sudo", "jperez", "mgarcia")), verdict.Compliant, "", []string{"2 members"}},
		{"prefixed admin account is not a finding", both(group("sudo", "adm_mgarcia")), verdict.Compliant, "", nil},
		{"both conventions, person without admin identity", both(group("sudo", "ubuntu", "mgarcia")), verdict.NonCompliant, "", []string{"ubuntu (sudo)"}},
		{"finding stands without auth log", silentWithFinding, verdict.NonCompliant, "", []string{"ubuntu"}},
		{"nothing found, auth log silent", silent, verdict.NotEvaluable, verdict.CauseCollection, []string{"cannot be checked"}},
		{"default P-11 is said", defaulted, verdict.Compliant, "", []string{"product default"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV06(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

func TestJudgeEV07(t *testing.T) {
	root := account("root", 0, "locked", 0)
	jperez := account("jperez", 1001, "locked", 1)
	mgarcia := account("mgarcia", 1002, "set", 0)
	old := account("old", 1003, "locked", 0)
	unknown := account("kim", 1004, "locked", -1)

	nologin := account("svc", 1005, "set", 0)
	nologin.Shell = "/usr/sbin/nologin"

	incomplete := inventory(jperez)
	incomplete.Current = identitySnapshot("cur", 3)

	cases := []struct {
		name    string
		in      EV07Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-07 not set", EV07Input{AuthorizedProblem: catalog.Says("param.not_set", "param", "P-07"), Inventory: inventory(root)}, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-07: not set"}},
		{"no inventory", EV07Input{Authorized: []string{"jperez"}, Inventory: Inventory{UIDMin: DefaultUIDMin}}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"incomplete inventory", EV07Input{Authorized: []string{"jperez"}, Inventory: incomplete}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"unauthorized active account", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(root, jperez, mgarcia)}, verdict.NonCompliant, "", []string{"not in P-07: mgarcia"}},
		{"key login counts as active", EV07Input{Authorized: []string{"mgarcia"}, Inventory: inventory(jperez, mgarcia)}, verdict.NonCompliant, "", []string{"jperez"}},
		{"case matters", EV07Input{Authorized: []string{"JPerez"}, Inventory: inventory(jperez)}, verdict.NonCompliant, "", []string{"jperez"}},
		{"disabled accounts do not count", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(root, jperez, old, nologin)}, verdict.Compliant, "", []string{"1 active accounts"}},
		{"system accounts do not count", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(account("daemon", 1, "set", 0), jperez)}, verdict.Compliant, "", nil},
		{"unknown and not listed", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(jperez, unknown)}, verdict.NotEvaluable, verdict.CauseEvidence, []string{"kim"}},
		{"unknown but listed", EV07Input{Authorized: []string{"jperez", "kim"}, Inventory: inventory(jperez, unknown)}, verdict.Compliant, "", nil},
		{"all authorized", EV07Input{Authorized: []string{"jperez", "mgarcia"}, Inventory: inventory(jperez, mgarcia)}, verdict.Compliant, "", []string{"2 active accounts, all in P-07"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV07(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

func deletedAccount(name string, disabled, deleted string, observed bool, expires string) history.Account {
	a := history.Account{AccountName: name, UID: 1500, AccountExpires: expires, DisabledObserved: observed}
	if disabled != "" {
		d := day(disabled)
		a.DisabledSince = &d
	}
	del := day(deleted)
	a.DeletedAt = &del
	return a
}

func TestJudgeEV08(t *testing.T) {
	base := func(deleted ...history.Account) EV08Input {
		return EV08Input{Deleted: deleted, RetentionDays: 30, Declared: map[string]time.Time{}, UIDMin: DefaultUIDMin}
	}

	badConfig := base()
	badConfig.ConfigProblem = catalog.Says("param.not_set", "param", "P-06")

	noIdentity := base()
	noIdentity.IdentityProblem = catalog.Says("opacc1.no_identity_pass_window")

	declared := base(deletedAccount("ana", "2026-10-01", "2026-10-20", false, ""))
	declared.Declared["ana"] = day("2026-09-01")

	unknownState := deletedAccount("lee", "", "2026-10-10", false, "")
	unknownState.StateUnknown = true

	system := deletedAccount("svc", "2026-10-01", "2026-10-02", true, "")
	system.UID = 500

	cases := []struct {
		name    string
		in      EV08Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"configuration problem", badConfig, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-06"}},
		{"no identity pass", noIdentity, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"nothing deleted", base(), verdict.Compliant, "", []string{"no account deleted"}},
		{"observed disabling, deleted too early", base(deletedAccount("ana", "2026-10-01", "2026-10-11", true, "")), verdict.NonCompliant, "", []string{"ana (10 days)", "30 days (P-06)"}},
		{"observed disabling, kept long enough", base(deletedAccount("ana", "2026-08-01", "2026-10-11", true, "")), verdict.Compliant, "", []string{"1 accounts deleted"}},
		{"P-09 date wins", declared, verdict.Compliant, "", nil},
		{"expiry date used", base(deletedAccount("eva", "2026-10-05", "2026-10-10", false, "2026-10-01")), verdict.NonCompliant, "", []string{"eva (9 days)"}},
		{"start unknown", base(deletedAccount("old", "2026-10-05", "2026-10-10", false, "")), verdict.NotEvaluable, verdict.CauseEvidence, []string{"old"}},
		{"last state unknown", base(unknownState), verdict.NotEvaluable, verdict.CauseEvidence, []string{"lee"}},
		{"deleted while enabled", base(deletedAccount("bob", "", "2026-10-10", false, "")), verdict.NonCompliant, "", []string{"bob (deleted while enabled)"}},
		{"too early wins over unknown", base(deletedAccount("bob", "", "2026-10-10", false, ""), deletedAccount("old", "2026-10-05", "2026-10-10", false, "")), verdict.NonCompliant, "", []string{"bob"}},
		{"system account ignored", base(system), verdict.Compliant, "", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV08(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

func TestParseAdminAffixes(t *testing.T) {
	cases := []struct {
		name    string
		rows    []string
		want    []AdminAffix
		problem string
	}{
		{"stored value without position is a suffix", []string{".adm"}, []AdminAffix{{Text: ".adm"}}, ""},
		{"explicit suffix", []string{".adm | sufijo"}, []AdminAffix{{Text: ".adm"}}, ""},
		{"prefix", []string{"adm_ | prefijo"}, []AdminAffix{{Text: "adm_", Prefix: true}}, ""},
		{"both conventions", []string{".adm|sufijo", "adm_|prefijo"}, []AdminAffix{{Text: ".adm"}, {Text: "adm_", Prefix: true}}, ""},
		{"unknown position", []string{".adm | medio"}, nil, "medio"},
		{"empty text", []string{" | prefijo"}, nil, "P-12"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, problem := parseAdminAffixes(c.rows)

			if !reflect.DeepEqual(got, c.want) && c.problem == "" {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
			if c.problem == "" && !problem.IsZero() {
				t.Errorf("unexpected problem %q", problem.Render("en"))
			}
			if c.problem != "" && !strings.Contains(problem.Render("en"), c.problem) {
				t.Errorf("problem %q does not contain %q", problem.Render("en"), c.problem)
			}
		})
	}
}

func TestProbeMakesAnEmptyAuthLogEvaluable(t *testing.T) {

	for _, c := range []struct {
		name   string
		probes map[string]map[string]bool
		want   verdict.Status
	}{
		{"probe seen", map[string]map[string]bool{"001": {"run": true}}, verdict.Compliant},
		{"no probe", nil, verdict.NotEvaluable},
	} {
		facts := &fakeFacts{currentIdentity: map[string][]fact.IdentitySnapshot{"001": {identityPass("cur", 1, true)}},
			identityRecords: map[string][]fact.IdentityRecord{"cur": {{AccountName: "root"}}}, probes: c.probes}
		results, err := begin(t, facts, &memHistory{}).Agent(context.Background(), verdict.Agent{ID: "001"}, forbidRoot{})
		if err != nil {
			t.Fatal(err)
		}
		if got := results["EV-03"].Judgement.Status; got != c.want {
			t.Errorf("%s: EV-03 %s, want %s: %s", c.name, got, c.want, results["EV-03"].Judgement.Reason)
		}
	}
}

type forbidRoot struct{ noParams }

func (forbidRoot) Matcher(string, string, string) (params.Matcher, error) {
	return params.ListMatcher("root"), nil
}

func TestJudgeEV07CountsListedAccounts(t *testing.T) {
	in := EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(account("jperez", 1001, "locked", 1), account("mgarcia", 1002, "set", 0))}

	got := JudgeEV07(in)

	if got.Tally == nil || got.Tally.Met != 1 || got.Tally.Total != 2 {
		t.Errorf("%s %q tally %+v", got.Status, got.Reason, got.Tally)
	}
}
