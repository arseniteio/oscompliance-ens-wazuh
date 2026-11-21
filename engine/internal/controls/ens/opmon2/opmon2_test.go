package opmon2

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func TestCycles(t *testing.T) {

	people := []string{"Responsable de Seguridad | RSEG | metricas", "Director Financiero | DF | recursos"}
	rows := []string{
		"2026-10-10 | 2026-T3 | 72 | Responsable de Seguridad | | | ",
		"2026-10-12 | 2026-T3 | | Director Financiero | 120 | 40 | 9000",
		"2026-10-20 | 2026-T3 | 74 | Becario | | | ",
	}
	if got := Cycles(rows, Validators(people, ScopeMetrics), false); len(got) != 1 || !strings.HasPrefix(got[0], "2026-10-10") {
		t.Errorf("metrics: %v", got)
	}
	if got := Cycles(rows, Validators(people, ScopeResources), true); len(got) != 1 || !strings.HasPrefix(got[0], "2026-10-12") {
		t.Errorf("resources: %v", got)
	}
}

func TestJudges(t *testing.T) {

	incidents := opexp7.ParseRegister([]string{
		"INC-1 | inicial | 2026-10-20 10:00 | alta | web01 | malware | RSI | | no | sí | no | | INC-1 | ",
		"INC-1 | final | 2026-10-21 10:00 | alta | web01 | | | | | | | | | ",
		"INC-2 | inicial | 2026-10-25 10:00 | | web01 | | | | | | | | | ",
		"INC-0 | inicial | 2026-01-25 10:00 | baja | web01 | | | | | | | | | ",
	})
	period := Period(incidents, now.AddDate(0, 0, -90))
	if len(period) != 2 {
		t.Fatalf("period: %d", len(period))
	}
	check(t, "measured", JudgeEV03(period[:1], []string{"incidentes_por_tipo", "notificados_ccn_cert"}), verdict.Compliant, "", "1 incident")
	check(t, "lacking", JudgeEV03(period, []string{"incidentes_por_severidad", "tiempo_medio_contencion"}), verdict.NonCompliant, "", "INC-2")
	check(t, "unknown", JudgeEV03(period, []string{"satisfaccion"}), verdict.NotEvaluable, verdict.CauseConfiguration, "")

	active := &source.Reporting{Status: "active", LastKeepAlive: now}
	window := now.Add(-26 * time.Hour)
	check(t, "measured", JudgeEV04(active, &fact.AgentPass{Envelope: fact.Envelope{TS: "2026-11-01T11:17:00Z"}}, window), verdict.Compliant, "", "")
	check(t, "no pass", JudgeEV04(active, nil, window), verdict.NonCompliant, "", "")
	check(t, "old pass", JudgeEV04(active, &fact.AgentPass{Envelope: fact.Envelope{TS: "2026-10-20T11:17:00Z"}}, window), verdict.NonCompliant, "", "")
	check(t, "disconnected", JudgeEV04(&source.Reporting{Status: "disconnected"}, nil, window), verdict.NonCompliant, "", "")
}

func TestImplementationDegree(t *testing.T) {

	if n := Applicable([]string{"op.acc.1 | sí | MEDIO | R1", "op.cont.2 | no", "op.exp.8 | SÍ", " | sí"}); n != 2 {
		t.Errorf("applicable measures: %d", n)
	}

	degree := &verdict.Degree{Controls: 30, Measured: 27, Score: 81, Unconfigured: []string{"op.exp.9", "op.acc.5"}}
	notSet := passes.Param("P-01", params.ErrNotSet)

	check(t, "no statement of applicability", JudgeEV01(0, notSet, degree, nil), verdict.NotEvaluable, verdict.CauseConfiguration, "P-01")
	check(t, "verdicts unreadable", JudgeEV01(30, catalog.Message{}, nil, errors.New("down")), verdict.NotEvaluable, verdict.CauseCollection, "down")
	check(t, "no verdict yet", JudgeEV01(30, catalog.Message{}, nil, nil), verdict.NotEvaluable, verdict.CauseCollection, "no control verdict")
	check(t, "degree known", JudgeEV01(30, catalog.Message{}, degree, nil), verdict.Compliant, "", "implementation degree 81 % over 30 controls, 27 measured; 30 applicable")

	check(t, "configuration debt listed", JudgeEV05(degree, nil), verdict.Compliant, "", "2 controls with evidences not evaluated by configuration: op.acc.5, op.exp.9")
	check(t, "no debt", JudgeEV05(&verdict.Degree{Controls: 3}, nil), verdict.Compliant, "", "none of its 3 controls")
	check(t, "no degree", JudgeEV05(nil, nil), verdict.NotEvaluable, verdict.CauseCollection, "no control verdict")
}
