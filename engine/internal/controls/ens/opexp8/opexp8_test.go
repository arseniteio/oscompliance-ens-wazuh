package opexp8

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

func TestAuditLog(t *testing.T) {

	running := &fact.AuditWatchSnapshot{Auditd: fact.AuditdRunning, Loaded: []string{"/etc/ssh"}}
	full := &fact.WazuhAgentConfig{Status: fact.SourceRead, Localfiles: []fact.AgentLocalfile{{Location: "/var/log/audit/audit.log", Format: "audit"}, {Location: "journald", Format: "journald"}}}
	check(t, "complete", JudgeEV01(running, full), verdict.Compliant, "", "1 watches")
	check(t, "no auditd", JudgeEV01(&fact.AuditWatchSnapshot{Auditd: fact.AuditdAbsent}, full), verdict.NonCompliant, "", "auditd absent")

	check(t, "fields", JudgeEV03(10, map[string]int{"usuario": 10, "objeto": 7, "tipo": 10, "resultado": 10}), verdict.NonCompliant, "", "objeto 7/10")
	check(t, "no records", JudgeEV03(0, nil), verdict.NotEvaluable, verdict.CauseCollection, "")
}

func TestJudgeEV04(t *testing.T) {

	from := now.Add(-6 * time.Hour)
	var records []source.MonitoringRecord
	for h := from; h.Before(now); h = h.Add(15 * time.Minute) {
		records = append(records, source.MonitoringRecord{Time: h.Add(time.Minute), Status: "active"})
	}
	check(t, "continuous", JudgeEV04(records, false, 1, catalog.Message{}, from, now), verdict.Compliant, "", "24 monitoring records")
	gap := append(records[:4:4], records[12:]...)
	check(t, "gap", JudgeEV04(gap, false, 1, catalog.Message{}, from, now), verdict.NonCompliant, "", "→")
	records[5].Status = "disconnected"
	check(t, "disconnected", JudgeEV04(records, false, 1, catalog.Message{}, from, now), verdict.NonCompliant, "", "disconnected")
}

func TestJudgeEV06(t *testing.T) {

	chrony := &fact.TimeSync{Tool: "chrony", Synchronised: true, Offset: 0.2, Sources: []string{"10.0.0.1"}}
	check(t, "synchronised", JudgeEV06(chrony, []string{"10.0.0.1 | NTP"}, 1, catalog.Message{}), verdict.Compliant, "", "chrony")
	check(t, "offset", JudgeEV06(chrony, nil, 0.1, catalog.Message{}), verdict.NonCompliant, "", "offset 0.2")
	check(t, "nts", JudgeEV06(chrony, []string{"10.0.0.1 | NTS"}, 1, catalog.Message{}), verdict.NonCompliant, "", "authenticated")
	check(t, "none", JudgeEV06(&fact.TimeSync{Tool: "none"}, nil, 1, catalog.Message{}), verdict.NonCompliant, "", "no time")
}

func TestIndexer(t *testing.T) {

	wanted := LongestRetention([]string{"autenticación | 365", "sistema | 180"})
	check(t, "early", JudgeEV07(90, true, wanted, catalog.Message{}), verdict.NonCompliant, "", "after 90 days, P-07 asks 365")
	check(t, "forever", JudgeEV07(0, false, wanted, catalog.Message{}), verdict.Compliant, "", "no indexer retention policy (ISM)")

	days := ShortestFrequency([]string{"alertas | NAS | diaria | sí", "archives | cinta | 7 | sí"})
	check(t, "snapshot", JudgeEV09(now.Add(-2*time.Hour), days, catalog.Message{}, now), verdict.Compliant, "", "P-09 1 days")
	check(t, "no snapshot", JudgeEV09(time.Time{}, days, catalog.Message{}, now), verdict.NonCompliant, "", "no successful snapshot")
}

func TestJudgeEV08(t *testing.T) {

	s := &fact.ACLSnapshot{Status: fact.SourceRead}
	records := []fact.ACLRecord{
		{Path: "/var/log/auth.log", Status: fact.SourceRead, Mode: "0640"},
		{Path: "/var/log/syslog", Status: fact.SourceRead, Mode: "0644"},
		{Path: "/var/log/audit", Status: fact.SourceRead, Mode: "0700", ACL: []string{"user:jgomez:r-x"}},
	}
	check(t, "open", JudgeEV08(s, records, []string{"/var/log/auth.log", "/var/log/syslog", "/var/log/audit"}, []string{"root"}, catalog.Message{}), verdict.NonCompliant, "", "/var/log/syslog (todos)")
	check(t, "closed", JudgeEV08(s, records[:1], []string{"/var/log/auth.log"}, []string{"root"}, catalog.Message{}), verdict.Compliant, "", "1 log paths")
}

func TestManager(t *testing.T) {

	manager := &fact.WazuhAgentConfig{RulesetFiles: 168, CustomRules: []string{"local_rules.xml"}}
	check(t, "no custom", JudgeEV10(manager, []string{"wazuh", "propias"}, catalog.Message{}), verdict.NonCompliant, "", "propias")
	check(t, "ruleset", JudgeEV10(manager, []string{"wazuh"}, catalog.Message{}), verdict.Compliant, "", "168")

	c := &fact.WazuhAgentConfig{Status: fact.SourceRead, ActiveResponses: []string{"firewall-drop"}, Directories: []fact.FIMDirectory{{Path: "/var/ossec/etc"}}}
	p := &fact.MalwareProtection{Responses: []string{"firewall-drop"}}
	check(t, "responses", JudgeEV11([]string{"firewall-drop", "disable-account"}, c, p, catalog.Message{}), verdict.NonCompliant, "", "disable-account")

	ok := verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.reporting", "since", "x"))
	check(t, "watched", JudgeEV13(ok, c), verdict.Compliant, "", "watched")
	check(t, "unwatched", JudgeEV13(ok, &fact.WazuhAgentConfig{Status: fact.SourceRead}), verdict.NonCompliant, "", "/var/ossec/etc")
}
