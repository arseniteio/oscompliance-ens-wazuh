package opexp5

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

var register = []string{
	"RFC-101 | 2026-10-27 09:00 | web01 | Nueva configuración de sshd | alto | amartinez | 2026-10-27 10:00 | 2026-10-28 22:00 | 2026-10-28 23:00 | implantada | manual de sshd | bajo",
	"RFC-STD-1 | 2026-01-01 | * | Parcheado automático | bajo | rsi | 2026-01-01 | 2026-01-01 00:00 | | aprobada | | ",
	"102 | 2026-10-20 | web01 | | alto | jgomez | 2026-10-25 | 2026-10-21 10:00 | 2026-10-21 11:00 | implantada | | ",
	"RFC-103 | 2026-10-28 | db01 | Rechazado | medio | rsi | | 2026-10-29 08:00 | 2026-10-29 09:00 | rechazada | | ",
}

func TestRegister(t *testing.T) {

	r := ParseRegister(register)
	if len(r) != 4 || r[0].From.UTC().Format(time.RFC3339) != "2026-10-28T21:00:00Z" {
		t.Fatalf("register: %+v", r[0])
	}
	if !r[0].Covers("WEB01", time.Date(2026, 10, 28, 21, 30, 0, 0, time.UTC)) || r[0].Covers("web01", time.Date(2026, 10, 28, 23, 30, 0, 0, time.UTC)) {
		t.Error("a request covers its machine inside its window")
	}
	if !r[1].Covers("any", now) {
		t.Error("an open window of * is a standard change")
	}
	if r[3].Covers("db01", time.Date(2026, 10, 29, 8, 30, 0, 0, time.UTC)) {
		t.Error("a rejected request covers nothing")
	}
}

func TestChanges(t *testing.T) {

	requests := ParseRegister(register[:1])
	fim := []source.FIMChange{
		{Time: time.Date(2026, 10, 28, 21, 15, 0, 0, time.UTC), Path: "/etc/ssh/sshd_config", Event: "modified"},
		{Time: time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC), Path: "/etc/hosts", Event: "modified"},
	}
	tx := []fact.PackageTransaction{{Start: "2026-10-29T04:00:00Z", Actor: "root", Command: "apt install tree"}}
	changes := Changes(fim, tx, now.Add(-26*time.Hour))
	if len(changes) != 3 {
		t.Fatalf("changes: %v", changes)
	}

	check(t, "uncovered", JudgeEV02(changes, requests, catalog.Message{}, "web01"), verdict.NonCompliant, "", "2 changes without an approved request")
	check(t, "covered by a standard change", JudgeEV02(changes, ParseRegister(register), catalog.Message{}, "web01"), verdict.Compliant, "", "3 changes")
	check(t, "no register", JudgeEV02(changes, nil, catalog.Says("param.not_set", "param", "P-10"), "web01"), verdict.NotEvaluable, verdict.CauseConfiguration, "P-10")

	off := &fact.WazuhAgentConfig{Status: fact.SourceRead, SyscheckDisabled: true}
	check(t, "fim off", JudgeEV01(off, &fact.TransactionSnapshot{Status: fact.SourceRead}, changes), verdict.NonCompliant, "", "FIM is disabled")
	check(t, "detected", JudgeEV01(&fact.WazuhAgentConfig{Status: fact.SourceRead}, &fact.TransactionSnapshot{Status: fact.SourceRead}, changes), verdict.Compliant, "", "3 changes seen")

	snapshots := &fact.SnapshotList{Status: fact.SourceRead, Snapshots: []fact.Snapshot{{Created: "2026-10-28T20:00:00Z"}}}
	check(t, "reversion", JudgeEV09(changes, snapshots, 4, catalog.Message{}), verdict.NonCompliant, "", "/etc/hosts")
	check(t, "reversion wide", JudgeEV09(changes, snapshots, 12, catalog.Message{}), verdict.Compliant, "", "3 transactions")
}

func TestRequests(t *testing.T) {

	requests := ParseRegister(register)
	required := []string{"peticion", "descripcion", "riesgo", "aprobado_por"}

	check(t, "incomplete", JudgeEV03(requests, "web01", required, "RFC-", false, catalog.Message{}, now), verdict.NonCompliant, "", "102 (descripcion; request number without the prefix RFC-)")
	check(t, "impact at ALTA", JudgeEV03(requests[1:2], "web01", nil, "", true, catalog.Message{}, now), verdict.NonCompliant, "", "RFC-STD-1 (impacto_seguridad)")

	check(t, "high risk", JudgeEV04(requests, "web01", []string{"amartinez"}, catalog.Message{}, now), verdict.NonCompliant, "", "102 (jgomez)")
	check(t, "high risk approved", JudgeEV04(requests[:1], "web01", []string{"amartinez"}, catalog.Message{}, now), verdict.Compliant, "", "1 high-risk")

	docs := []Document{{Name: "manual de sshd", Days: 0}}
	check(t, "undocumented", JudgeEV06(requests, "web01", docs, catalog.Message{}, now), verdict.NonCompliant, "", "102")
}

func TestJudgeEV07(t *testing.T) {

	changes := []Change{{Time: now.Add(-2 * time.Hour), What: "/etc/nginx/nginx.conf (modified)"}}
	failed := &fact.UnitSnapshot{Status: fact.SourceRead, Failed: []string{"nginx.service"}}

	check(t, "failed after change", JudgeEV07(failed, changes, nil, "web01", 24, catalog.Message{}, now), verdict.NonCompliant, "", "nginx.service failed within 24 h")
	check(t, "failed long after", JudgeEV07(failed, changes, nil, "web01", 1, catalog.Message{}, now), verdict.Compliant, "", "no change in the 1 h")
	check(t, "nothing failed", JudgeEV07(&fact.UnitSnapshot{Status: fact.SourceRead}, changes, nil, "web01", 24, catalog.Message{}, now), verdict.Compliant, "", "no service failed")
	check(t, "no systemd", JudgeEV07(&fact.UnitSnapshot{Status: fact.SourceAbsent}, changes, nil, "web01", 24, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseCollection, "systemd")
}
