package opexp3

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc4"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp5"
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

func TestJudgeEV01(t *testing.T) {

	assessed := verdict.Explain(verdict.Compliant, "", catalog.Says("opexp2.baseline", "policies", []string{"cis_ubuntu24-04 47 % (98/206)"}))
	policies := []string{"cis_ubuntu24-04", "cis_ubuntu22-04"}

	check(t, "kept", JudgeEV01(assessed, policies, map[string]int{"cis_ubuntu24-04": 46}, 40, 30, catalog.Message{}), verdict.Compliant, "", "at least 40 % in the last 30 days (cis_ubuntu24-04 46 %)")
	check(t, "fell", JudgeEV01(assessed, policies, map[string]int{"cis_ubuntu24-04": 38}, 40, 30, catalog.Message{}), verdict.NonCompliant, "", "fell below 40 %: cis_ubuntu24-04 38 %")
	check(t, "no change in the series", JudgeEV01(assessed, policies, nil, 40, 30, catalog.Message{}), verdict.Compliant, "", "evaluated with the SCA policies cis_ubuntu24-04")
	off := verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp2.sca_disabled"))
	check(t, "baseline not assessed", JudgeEV01(off, policies, nil, 40, 30, catalog.Message{}), verdict.NonCompliant, "", "SCA is disabled")
}

func TestEdits(t *testing.T) {

	accounts := opacc4.Accounts{IdentityRecords: []fact.IdentityRecord{{AccountName: "jgomez", UID: 1001}, {AccountName: "ana", UID: 1002}}}
	accesses := []source.AuditAccess{
		{Key: "oscompliance_write", Success: "yes", AUID: "1001", Path: "/etc/ssh/sshd_config"},
		{Key: "oscompliance_write", Success: "yes", AUID: "1002", Path: "/etc/sudoers"},
		{Key: "oscompliance_write", Success: "no", AUID: "1003", Path: "/etc/ssh/sshd_config"},
		{Key: "oscompliance_read", Success: "yes", AUID: "1003", Path: "/etc/ssh/sshd_config"},
		{Key: "oscompliance_write", Success: "yes", AUID: "1002", Path: "/srv/app"},
	}
	edits := Edits(accesses, []string{"/etc/ssh", "/etc/sudoers"})
	if len(edits) != 2 {
		t.Fatalf("edits: %v", edits)
	}

	check(t, "unauthorised", JudgeEV02(edits, accounts, []string{"jgomez"}, catalog.Message{}, catalog.Message{}), verdict.NonCompliant, "", "ana (/etc/sudoers)")
	check(t, "authorised", JudgeEV02(edits, accounts, []string{"jgomez", "ana"}, catalog.Message{}, catalog.Message{}), verdict.Compliant, "", "2 edits")
	check(t, "quiet and blind", JudgeEV02(nil, accounts, []string{"jgomez"}, catalog.Message{}, catalog.Says("chain.no_audit_log")), verdict.NotEvaluable, verdict.CauseCollection, "")
	check(t, "too many", JudgeEV08(edits, accounts, 1, catalog.Message{}, catalog.Message{}), verdict.NonCompliant, "", "2 accounts edited the security configuration, P-09 allows 1: ana, jgomez")
	check(t, "few", JudgeEV08(edits, accounts, 3, catalog.Message{}, catalog.Message{}), verdict.Compliant, "", "P-09 3")
}

func TestJudgeEV03(t *testing.T) {

	selection := &fact.PackageSelection{Manager: "apt", Status: fact.SourceRead, Packages: []string{"nmap", "openssh-server", "tree"}}
	installed := []string{"nmap", "libpcap0.8", "tree"}

	check(t, "unauthorised", JudgeEV03(installed, selection, []string{"tree"}, catalog.Message{}), verdict.NonCompliant, "", "without authorisation in P-01: nmap")
	check(t, "dependency passes", JudgeEV03([]string{"libpcap0.8"}, selection, nil, catalog.Message{}), verdict.Compliant, "", "1 packages installed, 0 on request")
	check(t, "dnf", JudgeEV03(installed, &fact.PackageSelection{Manager: "dnf", Status: fact.SourceRead}, nil, catalog.Message{}), verdict.NotEvaluable, verdict.CauseCollection, "dnf")
}

func TestJudgeEV04(t *testing.T) {

	units := &fact.UnitSnapshot{Status: fact.SourceRead, Units: []string{"cron.service", "getty@tty1.service", "nginx.service", "ssh.service"}}
	listening := &fact.ListeningSnapshot{Status: fact.SourceRead, RecordsEmitted: 2}
	sockets := []fact.ListeningSocket{{Port: 22, Process: "sshd", Unit: "ssh.service"}, {Port: 9000, Process: "php"}}
	authorised := []string{"cron.service", "getty@.service", "ssh.service"}

	check(t, "unauthorised", JudgeEV04(units, listening, sockets, authorised, catalog.Message{}), verdict.NonCompliant, "", "nginx.service, php")
	check(t, "authorised", JudgeEV04(units, listening, sockets, append(authorised, "nginx.service", "php"), catalog.Message{}), verdict.Compliant, "", "4 services and 1 listening processes")
	check(t, "does not use systemd", JudgeEV04(&fact.UnitSnapshot{Status: fact.SourceAbsent}, listening, sockets, []string{"php"}, catalog.Message{}), verdict.Compliant, "", "does not use systemd")
}

func TestJudgeEV09(t *testing.T) {

	b := &fact.BackupSnapshot{Status: fact.SourceRead, Sources: []fact.BackupSource{
		{Source: "git:/etc", Status: fact.SourceRead, Newest: "2026-10-29T03:00:00Z"},
		{Source: "/var/backups/etc-*.tgz", Status: fact.SourceRead, Newest: "2026-10-20T03:00:00Z"},
		{Source: "/srv/none/*.tar", Status: fact.SourceAbsent},
	}}

	check(t, "fresh", JudgeEV09(b, []string{"git:/etc"}, 24, catalog.Message{}, now), verdict.Compliant, "", "git:/etc (2026-10-29 03:00)")
	check(t, "old", JudgeEV09(b, []string{"git:/etc", "/var/backups/etc-*.tgz"}, 24, catalog.Message{}, now), verdict.NonCompliant, "", "/var/backups/etc-*.tgz (2026-10-20 03:00)")
	check(t, "no copy", JudgeEV09(b, []string{"/srv/none/*.tar"}, 24, catalog.Message{}, now), verdict.NonCompliant, "", "/srv/none/*.tar (-)")
	check(t, "not read yet", JudgeEV09(b, []string{"git:/srv"}, 24, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseCollection, "git:/srv")
}

func TestJudgeEV10(t *testing.T) {

	r := []source.SCARegression{{PolicyID: "cis_ubuntu24-04", CheckID: "35500", Title: "Ensure SSH root login is disabled", Time: now.Add(-48 * time.Hour)}}
	check(t, "regression", JudgeEV10(r, now.Add(-30*24*time.Hour), 30), verdict.NonCompliant, "", "35500 Ensure SSH root login")
	check(t, "older than the series", JudgeEV10(r, now.Add(-24*time.Hour), 1), verdict.Compliant, "", "")
}

func TestJudgeEV05(t *testing.T) {

	fim := []source.FIMChange{
		{Time: now.Add(-3 * time.Hour), Path: "/etc/ssh/sshd_config", Event: "modified"},
		{Time: now.Add(-2 * time.Hour), Path: "/etc/hosts", Event: "modified"},
	}
	requests := opexp5.ParseRegister([]string{"RFC-1 | 2026-10-28 | web01 | sshd | bajo | rsi | 2026-10-28 | 2026-10-29 10:00 | 2026-10-29 10:30 | implantada | | "})

	check(t, "unauthorised", JudgeEV05(fim, []string{"/etc/ssh"}, nil, "web01", catalog.Message{}, now.Add(-26*time.Hour)), verdict.NonCompliant, "", "/etc/ssh/sshd_config")
	check(t, "covered", JudgeEV05(fim, []string{"/etc/ssh"}, requests, "web01", catalog.Message{}, now.Add(-26*time.Hour)), verdict.Compliant, "", "1 edits")
}
