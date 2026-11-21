package opexp4

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

var days = []source.VulnerabilityDay{
	{Severity: "Critical", Detected: now.Add(-10 * 24 * time.Hour), Count: 2, Examples: []string{"CVE-2026-1"}},
	{Severity: "High", Detected: now.Add(-3 * 24 * time.Hour), Count: 4},
	{Severity: "Low", Detected: now.Add(-400 * 24 * time.Hour), Count: 1},
}

func TestVulnerabilities(t *testing.T) {

	fresh := verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.packages", "count", 1, "types", []string{"deb 1"}))
	check(t, "inventory", JudgeEV01(fresh, false, days), verdict.Compliant, "", "Crítica 2, Alta 4, Baja 1")
	check(t, "manager", JudgeEV01(fresh, true, days), verdict.NotEvaluable, verdict.CauseCollection, "manager")

	deadlines, problem := Deadlines([]string{"Crítica | 7", "Alta | 30", "Media | 90", "Baja |"})
	if !problem.IsZero() {
		t.Fatal(problem)
	}
	check(t, "overdue", JudgeEV02(false, days, deadlines, catalog.Message{}, now), verdict.NonCompliant, "", "Crítica 2 (7 días)")
	relaxed, _ := Deadlines([]string{"Crítica | 30"})
	check(t, "within", JudgeEV02(false, days, relaxed, catalog.Message{}, now), verdict.Compliant, "", "7 open vulnerabilities")
	if _, p := Deadlines([]string{"Crítica | pronto"}); p.IsZero() {
		t.Error("a deadline that is not a number is refused")
	}
}

func TestJudgeEV03(t *testing.T) {

	u := &fact.UpdateStatus{Manager: "apt", Status: fact.SourceRead, ListsUpdated: "2026-10-28T06:00:00Z", Pending: 3, Security: 1}
	check(t, "current", JudgeEV03(u, 7, catalog.Message{}, now), verdict.Compliant, "", "3 upgrades pending, 1 of security")
	old := *u
	old.ListsUpdated = "2026-09-01T06:00:00Z"
	check(t, "stale lists", JudgeEV03(&old, 7, catalog.Message{}, now), verdict.NonCompliant, "", "58 days old")
	check(t, "no apt", JudgeEV03(&fact.UpdateStatus{Manager: "none", Status: fact.SourceRead}, 7, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseCollection, "apt")
}

func transactions(records ...fact.PackageTransaction) Transactions {
	return Transactions{Snapshot: &fact.TransactionSnapshot{Manager: "apt", Status: fact.SourceRead, RecordsEmitted: len(records)}, Records: records}
}

func TestMaintenance(t *testing.T) {

	night := fact.PackageTransaction{Start: "2026-10-24T23:10:00+02:00", Actor: "unattended-upgrades", Command: "/usr/bin/unattended-upgrade"}
	noon := fact.PackageTransaction{Start: "2026-10-29T12:30:00+02:00", Actor: "jgomez", Command: "apt install nmap"}
	old := fact.PackageTransaction{Start: "2026-01-01T12:00:00Z", Actor: "intruso"}
	tx := transactions(night, noon, old)
	from := now.Add(-7 * 24 * time.Hour)

	check(t, "unauthorised", JudgeEV04(tx, from, []string{"unattended-upgrades | servidores | automático"}, catalog.Message{}), verdict.NonCompliant, "", "jgomez (apt install nmap)")
	check(t, "authorised", JudgeEV04(tx, from, []string{"unattended-upgrades", "jgomez"}, catalog.Message{}), verdict.Compliant, "", "2 transactions")

	windows := []string{"* | sab 22:00-02:00; * 06:00-07:30", "web01 | * 12:00-13:00"}
	check(t, "outside", JudgeEV07(tx, from, windows, "db01", catalog.Message{}), verdict.NonCompliant, "", "jgomez")
	check(t, "own row", JudgeEV07(transactions(noon), from, windows, "WEB01", catalog.Message{}), verdict.Compliant, "", "1 transaction")
	check(t, "no window", JudgeEV07(tx, from, []string{"web01 | * 12:00-13:00"}, "db01", catalog.Message{}), verdict.NotEvaluable, verdict.CauseConfiguration, "db01")

	sunday := Window{Day: 6, Start: 22 * 60, End: 2 * 60}
	if !sunday.Contains(time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)) || sunday.Contains(time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)) {
		t.Error("a Saturday window running past midnight covers early Sunday only")
	}

	snapshots := &fact.SnapshotList{Status: fact.SourceRead, Snapshots: []fact.Snapshot{{Tool: "lvm", Name: "pre", Created: "2026-10-24T20:00:00Z"}}}
	check(t, "snapshot before", JudgeEV09(transactions(night), from, snapshots, 24, catalog.Message{}), verdict.Compliant, "", "with a snapshot")
	check(t, "no snapshot", JudgeEV09(tx, from, snapshots, 24, catalog.Message{}), verdict.NonCompliant, "", "jgomez")
	if h, ok := ReversionHours([]string{"* | lvm | snapshot | 24", "db01 | zfs | snapshot | 6"}, "db01"); !ok || h != 6 {
		t.Errorf("reversion hours: %d %v", h, ok)
	}
}

func TestJudgeEV05(t *testing.T) {

	ubuntu := &source.System{OS: "Ubuntu", Version: "24.04.4 LTS (Noble Numbat)"}
	rows := []string{"Ubuntu | 22.04 | 2027-04-01", "Ubuntu | 24.04 | 2029-05-31"}
	check(t, "supported", JudgeEV05(ubuntu, rows, catalog.Message{}, now), verdict.Compliant, "", "until 2029-05-31")
	check(t, "out", JudgeEV05(&source.System{OS: "Ubuntu", Version: "20.04.6 LTS"}, []string{"Ubuntu | 20.04 | 2025-05-31"}, catalog.Message{}, now), verdict.NonCompliant, "", "since 2025-05-31")
	check(t, "no row", JudgeEV05(&source.System{OS: "Debian", Version: "12"}, rows, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseConfiguration, "Debian 12")
}

func TestJudgeEV06(t *testing.T) {

	vendors := []string{"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", "Wazuh, Inc <info@wazuh.com>"}
	check(t, "blind spot", JudgeEV06(vendors, []string{"ubuntu | USN | RSS"}, catalog.Message{}), verdict.NonCompliant, "", "Wazuh, Inc")
	check(t, "followed", JudgeEV06(vendors, []string{"ubuntu | USN | RSS", "wazuh | GitHub | correo"}, catalog.Message{}), verdict.Compliant, "", "2 vendors")
}

func TestJudgeEV08(t *testing.T) {

	installed := map[string]time.Time{"nginx 1.24.0-2": now.Add(-2 * time.Hour), "curl 8.5.0-2": now.Add(-3 * time.Hour)}
	pre := map[string]time.Time{"nginx 1.24.0-2": now.Add(-48 * time.Hour)}
	rows := []string{"web01 | pre-web01 | informe 2026-10"}
	from := now.Add(-26 * time.Hour)

	check(t, "untested", JudgeEV08("web01", rows, catalog.Message{}, installed, pre, nil, from), verdict.NonCompliant, "", "curl 8.5.0-2")
	check(t, "present now", JudgeEV08("web01", rows, catalog.Message{}, installed, pre, map[string]bool{"curl 8.5.0-2": true}, from), verdict.Compliant, "", "2 versions")
	check(t, "not production", JudgeEV08("db01", rows, catalog.Message{}, installed, pre, nil, from), verdict.NotEvaluable, verdict.CauseConfiguration, "db01")
}
