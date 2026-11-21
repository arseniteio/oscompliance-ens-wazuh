package store

import (
	"encoding/json"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func TestMappingCoversEveryVerdictField(t *testing.T) {
	one, level := 1, 4
	v := verdict.Verdict{
		Evidenced: new(bool), Score: &one, Coverage: &one, ApplicableRequirements: &one, MeasuredRequirements: &one,
		UnmeasuredRequirements: []string{"r"}, ReasonArgs: map[string]any{"a": 1}, Cause: verdict.CauseCollection,
		Reason: "x", ReasonCode: "x", RunID: "x", Requirement: "r", Evidence: "e", Attested: true,
		Maturity: &verdict.Maturity{Accredited: &one},
		Tally:    &verdict.TallyResult{Met: 1, Total: 1, Percent: 100, Level: &level},
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}

	properties := mapping["mappings"].(map[string]any)["properties"].(map[string]any)
	for field := range fields {
		if _, ok := properties[field]; !ok {
			t.Errorf("field %s is not in the strict mapping: the indexer rejects the verdict", field)
		}
	}
	tally := properties["tally"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"met", "total", "percent", "level"} {
		if _, ok := tally[field]; !ok {
			t.Errorf("tally.%s is not mapped", field)
		}
	}
}
