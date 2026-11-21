package opexp7

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
	"INC-1 | inicial | 2026-10-27 10:00 | alta | web01 | acceso no autorizado | RSI | | no | | no | | https://intra/INC-1 | ",
	"INC-1 | intermedio | 2026-10-27 13:00 | alta | web01 | acceso no autorizado | | Ana, Luis | no | | no | | | ",
	"INC-1 | final | 2026-10-28 09:00 | alta | web01 | acceso no autorizado | | | no | | no | bloqueo de la cuenta | | 2026-10-29",
	"INC-2 | inicial | 2026-10-29 08:00 | critica | web01, db01 | malware | | | si | | si | | | ",
}

var classes, _ = ParseClasses([]string{"intrusión | alta | 10 | no | acceso", "malware | critica | 12 | si | código dañino"})

func TestDetectionNeedsAReportingMachine(t *testing.T) {

	check(t, "silent machine", JudgeEV01(nil, classes, false, catalog.Message{}), verdict.NotEvaluable, verdict.CauseCollection, "has not reported")
	check(t, "quiet machine", JudgeEV01(nil, classes, true, catalog.Message{}), verdict.Compliant, "", "")

	alert := []source.AlertHour{{Hour: now, Level: 10}}
	check(t, "alerts prove detection", JudgeEV01(alert, classes, false, catalog.Message{}), verdict.Compliant, "", "")
}

func TestReportedSince(t *testing.T) {

	since := now.Add(-24 * time.Hour)
	if !ReportedSince(source.Reporting{LastKeepAlive: now}, since) {
		t.Error("a recent contact is reporting")
	}
	if ReportedSince(source.Reporting{LastKeepAlive: since.Add(-time.Hour)}, since) || ReportedSince(source.Reporting{}, since) {
		t.Error("an old or missing contact is not reporting")
	}
}

func TestRegister(t *testing.T) {

	in := Of(ParseRegister(register), "WEB01", now)
	if len(in) != 2 || in[0].Severity() != "alta" || in[0].Closed().IsZero() || !in[1].Closed().IsZero() {
		t.Fatalf("incidents: %+v", in)
	}
	if got := Of(ParseRegister(register), "db01", now); len(got) != 1 || got[0].ID != "INC-2" {
		t.Errorf("db01: %+v", got)
	}
	if SeverityOf(classes, 11) != "alta" || SeverityOf(classes, 13) != "critica" || MinLevel(classes) != 10 {
		t.Error("severity by level")
	}
}

func TestJudges(t *testing.T) {

	in := Of(ParseRegister(register), "web01", now)
	escalation := []string{"alta | RSI | 4 | correo", "critica | RSI | 1 | teléfono"}

	hours := []source.AlertHour{{Hour: time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC), Level: 10}, {Hour: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), Level: 12}}
	check(t, "orphan", JudgeEV02(hours, classes, escalation, in, "web01", catalog.Message{}), verdict.NonCompliant, "", "2026-10-20 09:00 (critica, nivel 12)")
	check(t, "reconciled", JudgeEV02(hours[:1], classes, escalation, in, "web01", catalog.Message{}), verdict.Compliant, "", "1 hour")

	deadlines := []string{"alta | 4 | 48", "critica | 1 | 24"}
	check(t, "late", JudgeEV03(in, deadlines, catalog.Message{}, now), verdict.NonCompliant, "", "INC-2 (contención)")

	owners := []string{"web01 | Ana | Luis"}
	check(t, "not escalated", JudgeEV04(in, escalation, owners, catalog.Message{}), verdict.NonCompliant, "", "INC-2")

	manager := &fact.WazuhAgentConfig{SealedDays: []string{"2026-10-27", "2026-10-28"}}
	check(t, "sealed", JudgeEV05(in[:1], manager, now), verdict.Compliant, "", "1 incident")
	check(t, "unsealed", JudgeEV05(in, manager, now), verdict.Compliant, "", "")

	check(t, "containment", JudgeEV06(in, nil, now), verdict.NonCompliant, "", "INC-2")
	check(t, "responded", JudgeEV06(in, []time.Time{time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)}, now), verdict.Compliant, "", "2 serious")

	check(t, "personal data", JudgeEV07(in, []string{"web01 | clientes"}, catalog.Message{}), verdict.NonCompliant, "", "INC-2 (72 h)")
	check(t, "ccn-cert", JudgeEV08(in, classes, catalog.Message{}), verdict.NonCompliant, "", "INC-2")
	check(t, "lessons", JudgeEV12(in), verdict.Compliant, "", "1 closed")

	lists := &fact.WazuhAgentConfig{Lists: []fact.CDBList{{Name: "ccn-ioc", Modified: "2026-10-27T00:00:00Z"}}}
	check(t, "advisories", JudgeEV10(lists, []string{"correo | RSI | ccn-ioc | 7"}, catalog.Message{}, now), verdict.Compliant, "", "ccn-ioc")
	check(t, "advisories missing", JudgeEV10(lists, []string{"correo | RSI | otra | 7"}, catalog.Message{}, now), verdict.NonCompliant, "", "otra")
}
