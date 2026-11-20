package catalog

import (
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestVerdictSchema(t *testing.T) {
	raw, err := os.Open("schemas/verdicts/verdict.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(raw)
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}

	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("verdict.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("verdict.json")
	if err != nil {
		t.Fatal(err)
	}

	const base = `"oscompliance_verdict":"1","@timestamp":"2026-10-22T12:00:00Z","control":"op.acc.1","agent":{"id":"001","name":"a"},"window_start":"2026-10-21T10:00:00Z","window_end":"2026-10-22T12:00:00Z","engine_version":"x"`

	const ev = `"scope":"evidence","evidence":"EV-07",`
	const rq = `"scope":"requirement","requirement":"op.acc.1.4",`
	const ct = `"scope":"control",`

	cases := []struct {
		name  string
		extra string
		valid bool
	}{
		{"compliant", ev + `"status":"COMPLIANT"`, true},
		{"compliant with reason", ev + `"status":"COMPLIANT","reason":"2 accounts"`, true},
		{"non compliant", ev + `"status":"NON_COMPLIANT","reason":"x"`, true},
		{"non compliant without reason", ev + `"status":"NON_COMPLIANT"`, false},
		{"not evaluable", ev + `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, true},
		{"not evaluable without cause", ev + `"status":"NOT_EVALUABLE","reason":"x"`, false},
		{"not applicable", ev + `"status":"NOT_APPLICABLE","reason":"EV-07 applies at MEDIO, ALTO; active ENS level BAJO"`, true},
		{"not applicable without reason", ev + `"status":"NOT_APPLICABLE"`, false},
		{"not applicable with cause", ev + `"status":"NOT_APPLICABLE","cause":"CONFIGURATION","reason":"x"`, false},
		{"unknown status", ev + `"status":"CUMPLE"`, false},
		{"no scope", `"evidence":"EV-07","status":"COMPLIANT"`, false},
		{"evidence scope without evidence", `"scope":"evidence","status":"COMPLIANT"`, false},
		{"requirement not evidenced", rq + `"status":"NON_COMPLIANT","reason":"not evidenced: EV-04 (CONFIGURATION)","evidenced":false`, true},
		{"requirement attested", rq + `"status":"COMPLIANT","evidenced":true,"attested":true,"reason":"attested by document: x"`, true},
		{"requirement never NOT_EVALUABLE", rq + `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, false},
		{"requirement never PARTIAL", rq + `"status":"PARTIAL","reason":"x"`, false},
		{"requirement with evidence field", rq + `"evidence":"EV-01","status":"COMPLIANT"`, false},
		{"evidence tally", ev + `"status":"NON_COMPLIANT","reason":"x","tally":{"met":36,"total":40,"percent":90,"level":4}`, true},
		{"evidence tally without level", ev + `"status":"NON_COMPLIANT","reason":"x","tally":{"met":36,"total":40,"percent":90}`, true},
		{"tally of nothing", ev + `"status":"COMPLIANT","tally":{"met":0,"total":0,"percent":0}`, false},
		{"tally level above L5", ev + `"status":"COMPLIANT","tally":{"met":1,"total":1,"percent":100,"level":6}`, false},
		{"control partial", ct + `"status":"PARTIAL","reason":"6 of 8","score":75,"coverage":75,"applicable_requirements":8,"measured_requirements":6,"unmeasured_requirements":["op.acc.1.5","op.acc.1.r1.1"]`, true},
		{"control not applicable without score", ct + `"status":"NOT_APPLICABLE","reason":"no requirement applies"`, true},
		{"control score out of range", ct + `"status":"COMPLIANT","score":101`, false},
		{"control never NOT_EVALUABLE", ct + `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, false},
		{"partial evidence", ev + `"status":"PARTIAL","reason":"x"`, false},
		{"control with accredited maturity", ct + `"status":"COMPLIANT","score":100,"maturity":{"accredited":2,"working_days":30,"period_days":30}`, true},
		{"accredited maturity above 2", ct + `"status":"COMPLIANT","maturity":{"accredited":3}`, false},
		{"evidence without status", ev + `"reason":"x"`, false},
	}

	const org = `"oscompliance_verdict":"1","@timestamp":"2026-10-22T12:00:00Z","agent":{"id":"organization","name":""},"window_start":"2026-10-22T12:00:00Z","window_end":"2026-10-22T12:00:00Z","engine_version":"x","scope":"organization",`
	orgCases := []struct {
		name  string
		extra string
		valid bool
	}{
		{"measure", `"control":"op.acc.1","maturity":{"accredited":1,"assessed":3,"target":3,"incoherent":true,"machines":4}`, true},
		{"summary", `"control":"ENS","maturity":{"applicable":2,"unmeasured":0,"unassessed":1,"accredited_counts":[0,1,1,0,0,0],"assessed_counts":[0,0,0,1,0,0],"global_accredited":1,"global_assessed":0}`, true},
		{"organization with status", `"control":"op.acc.1","status":"COMPLIANT","maturity":{"accredited":1}`, false},
		{"organization without maturity", `"control":"op.acc.1"`, false},
		{"assessed above 5", `"control":"org.2","maturity":{"assessed":6}`, false},
	}
	for _, tc := range orgCases {
		v, err := jsonschema.UnmarshalJSON(strings.NewReader("{" + org + tc.extra + "}"))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(v); (err == nil) != tc.valid {
			t.Errorf("%s: valid=%v, error %v", tc.name, tc.valid, err)
		}
	}

	for _, tc := range cases {
		v, err := jsonschema.UnmarshalJSON(strings.NewReader("{" + base + "," + tc.extra + "}"))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(v); (err == nil) != tc.valid {
			t.Errorf("%s: valid=%v, error %v", tc.name, tc.valid, err)
		}
	}
}
