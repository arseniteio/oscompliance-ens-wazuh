package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func TestDocumentID(t *testing.T) {
	agent := verdict.Agent{ID: "001", Name: "a"}
	ts := "2026-10-22T15:20:00Z"

	cases := map[string]verdict.Verdict{
		"001/op.acc.1/EV-01/r1":              {Scope: verdict.ScopeEvidence, Agent: agent, Control: "op.acc.1", Evidence: "EV-01", RunID: "r1", Timestamp: ts},
		"001/op.acc.1/EV-03/none":            {Scope: verdict.ScopeEvidence, Agent: agent, Control: "op.acc.1", Evidence: "EV-03", Timestamp: ts},
		"001/op.acc.1/op.acc.1.4/2026-10-22": {Scope: verdict.ScopeRequirement, Agent: agent, Control: "op.acc.1", Requirement: "op.acc.1.4", Timestamp: ts},
		"001/op.acc.1/2026-10-22":            {Scope: verdict.ScopeControl, Agent: agent, Control: "op.acc.1", Timestamp: ts},
		"organization/ENS/2026-10-22":        {Scope: verdict.ScopeOrganization, Agent: verdict.Agent{ID: verdict.OrganizationAgent}, Control: verdict.AllMeasures, Timestamp: ts},
	}

	for want, v := range cases {
		if got := DocumentID(v); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

func TestDocumentIDOfASystem(t *testing.T) {
	agent := verdict.Agent{ID: "001", Name: "a"}
	control := verdict.Verdict{Scope: verdict.ScopeControl, Agent: agent, Control: "op.acc.1", Timestamp: "2026-10-22T15:20:00Z"}

	control.System = verdict.DefaultSystem
	if got := DocumentID(control); got != "001/op.acc.1/2026-10-22" {
		t.Errorf("the default system changed the document id: %s", got)
	}

	control.System = "pilot"
	if got := DocumentID(control); got != "pilot/001/op.acc.1/2026-10-22" {
		t.Errorf("got %s", got)
	}
}

func TestDegreeBucket(t *testing.T) {
	raw := `{"key":{"agent":"001"},
	  "controls":{"control":{"buckets":[
	    {"latest":{"hits":{"hits":[{"_source":{"score":100,"measured_requirements":4}}]}}},
	    {"latest":{"hits":{"hits":[{"_source":{"score":50,"measured_requirements":0}}]}}},
	    {"latest":{"hits":{"hits":[{"_source":{"score":75}}]}}},
	    {"latest":{"hits":{"hits":[]}}}]}},
	  "unconfigured":{"control":{"buckets":[{"key":"op.exp.9"},{"key":"op.acc.5"}]}}}`

	var b degreeBucket
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	d := b.degree()
	if d.Controls != 3 || d.Measured != 1 || d.Score != 75 || strings.Join(d.Unconfigured, ",") != "op.exp.9,op.acc.5" {
		t.Errorf("degree: %+v", d)
	}
}
