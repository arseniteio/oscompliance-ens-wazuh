package run

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func configWith(t *testing.T, raw string) *params.Config {
	t.Helper()
	var c params.Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func configurationGap(m catalog.Message) verdict.Judgement {
	return verdict.Explain(verdict.NotEvaluable, verdict.CauseConfiguration, m)
}

var web01 = verdict.Agent{ID: "001", Name: "web01"}

func TestUnsetParameterNamesMachineAndParameter(t *testing.T) {

	got := explainConfiguration(configWith(t, `{}`), "op.acc.1", web01, configurationGap(catalog.Says("param.not_set", "param", "P-03")))

	if got.Message.Code != "configuration.parameter_unset" {
		t.Fatalf("code %s", got.Message.Code)
	}
	if want := "configuración en web01 (001): P-03 sin valor"; !strings.Contains(got.Message.Render("es"), want) {
		t.Errorf("reason %q lacks %q", got.Message.Render("es"), want)
	}
	if got.Status != verdict.NotEvaluable || got.Cause != verdict.CauseConfiguration {
		t.Errorf("status %s cause %s", got.Status, got.Cause)
	}
}

func TestInvalidParameterShowsConfiguredValueAndSource(t *testing.T) {

	policy := configWith(t, `{"controls":[{"controlId":"op.acc.1","parameters":[{"id":"P-03","value":"svc_.*(","matchMode":"regex"}]}]}`)
	detail := catalog.Says("param.invalid", "param", "P-03", "error", "missing closing )")

	got := explainConfiguration(policy, "op.acc.1", web01, configurationGap(detail)).Message.Render("es")

	for _, want := range []string{"web01 (001)", "P-03 configurado: «svc_.*(»", "valor de la organización", "missing closing )"} {
		if !strings.Contains(got, want) {
			t.Errorf("reason %q lacks %q", got, want)
		}
	}
}

func TestLongListsAreCounted(t *testing.T) {

	policy := configWith(t, `{"controls":[{"controlId":"op.acc.1","parameters":[{"id":"P-03","value":["a","b","c","d","e","f","g"]}]}]}`)

	got := explainConfiguration(policy, "op.acc.1", web01, configurationGap(catalog.Says("findings_semicolon", "list", []catalog.Message{catalog.Says("param.invalid", "param", "P-03", "error", "x")}))).Message.Render("es")

	if !strings.Contains(got, "«a, b, c, d, e» y 2 más") {
		t.Errorf("reason %q", got)
	}
}

func TestGapWithoutParameterKeepsDetail(t *testing.T) {

	got := explainConfiguration(configWith(t, `{}`), "mp.info.6", verdict.Agent{ID: "002"}, configurationGap(catalog.Says("mpinfo6.no_interval", "name", "db"))).Message

	if got.Code != "configuration.gap" || !strings.HasPrefix(got.Render("es"), "falta configuración en 002:") {
		t.Errorf("got %s %q", got.Code, got.Render("es"))
	}
}

func TestOtherJudgementsAreUntouched(t *testing.T) {

	in := verdict.Explain(verdict.NotEvaluable, verdict.CauseCollection, catalog.Says("gap.no_auth_events"))

	if got := explainConfiguration(configWith(t, `{}`), "op.acc.1", web01, in); got.Message.Code != "gap.no_auth_events" {
		t.Errorf("code %s", got.Message.Code)
	}
}
