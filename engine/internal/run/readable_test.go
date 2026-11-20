package run

import (
	"os"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func TestEveryFactTypeHasALabel(t *testing.T) {
	entries, err := os.ReadDir("../../../catalog/schemas/facts")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name, isSchema := strings.CutSuffix(e.Name(), ".v1.json")
		if !isSchema || name == "envelope" {
			continue
		}
		for _, lang := range []string{"en", "es"} {
			if _, ok := catalog.Messages(lang)["fact."+name]; !ok {
				t.Errorf("fact %s has no %s label", name, lang)
			}
		}
	}
}

func TestCollectionGapsNameTheFactInPlainWords(t *testing.T) {
	gap := verdict.Explain(verdict.NotEvaluable, verdict.CauseCollection,
		catalog.Says("findings_semicolon", "list", []catalog.Message{catalog.Says("gap.no_fact", "fact", "identity_snapshot")}))

	got := readableFacts(gap).Message.Render("es")

	if !strings.Contains(got, "el inventario de cuentas") || strings.Contains(got, "identity_snapshot") {
		t.Errorf("reason %q", got)
	}
}
