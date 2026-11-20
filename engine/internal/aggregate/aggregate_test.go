package aggregate

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var (
	ok       = verdict.Judgement{Status: verdict.Compliant}
	fail     = verdict.Judgement{Status: verdict.NonCompliant, Reason: "x"}
	gap      = verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseConfiguration, Reason: "x"}
	excluded = verdict.Judgement{Status: verdict.NotApplicable, Reason: "x"}
)

func TestEvaluateRequirement(t *testing.T) {
	base := catalog.Requirement{ID: "r", Levels: []string{"BAJO", "MEDIO", "ALTO"}, EvidenceIDs: []string{"EV-01", "EV-02"}}
	r1 := catalog.Requirement{ID: "r1", Levels: []string{"MEDIO", "ALTO"}, EvidenceIDs: []string{"EV-07"}, ApplicabilityReason: "Refuerzo R1"}
	doc := catalog.Requirement{ID: "doc", Levels: []string{"BAJO", "MEDIO", "ALTO"}}

	good := &Attestation{Reference: "Política eIDAS", Links: []string{"https://intranet/eidas.pdf"}}
	noLink := &Attestation{Reference: "Política eIDAS"}

	cases := []struct {
		name      string
		req       catalog.Requirement
		level     string
		enabled   bool
		evidences map[string]verdict.Judgement
		att       *Attestation
		status    verdict.Status
		evidenced bool
		attested  bool
		reason    string
	}{
		{"all compliant", base, "MEDIO", true, map[string]verdict.Judgement{"EV-01": ok, "EV-02": ok}, nil, verdict.Compliant, true, false, "EV-01, EV-02"},
		{"one failure fails it", base, "MEDIO", true, map[string]verdict.Judgement{"EV-01": fail, "EV-02": gap}, nil, verdict.NonCompliant, true, false, "non-compliant evidence: EV-01"},
		{"a gap is not evidenced", base, "MEDIO", true, map[string]verdict.Judgement{"EV-01": ok, "EV-02": gap}, nil, verdict.NonCompliant, false, false, "EV-02 (CONFIGURATION)"},
		{"missing verdict counts as a collection gap", base, "MEDIO", true, map[string]verdict.Judgement{"EV-01": ok}, nil, verdict.NonCompliant, false, false, "EV-02 (COLLECTION)"},
		{"not applicable evidence is skipped", base, "MEDIO", true, map[string]verdict.Judgement{"EV-01": ok, "EV-02": excluded}, nil, verdict.Compliant, true, false, ""},
		{"all evidences not applicable", base, "MEDIO", true, map[string]verdict.Judgement{"EV-01": excluded, "EV-02": excluded}, nil, verdict.NotApplicable, false, false, "applies"},
		{"reinforcement at BAJO", r1, "BAJO", true, nil, nil, verdict.NotApplicable, false, false, "Refuerzo R1"},
		{"reinforcement at MEDIO", r1, "MEDIO", true, map[string]verdict.Judgement{"EV-07": ok}, nil, verdict.Compliant, true, false, ""},
		{"no level: nothing ruled out", r1, "", true, map[string]verdict.Judgement{"EV-07": ok}, nil, verdict.Compliant, true, false, ""},
		{"disabled control", base, "MEDIO", false, nil, nil, verdict.NotApplicable, false, false, "disabled"},
		{"documentary, attested", doc, "BAJO", true, nil, good, verdict.Compliant, true, true, "Política eIDAS"},
		{"documentary, attestation without link", doc, "BAJO", true, nil, noLink, verdict.NonCompliant, false, false, "P-ATT"},
		{"documentary, nothing declared", doc, "BAJO", true, nil, nil, verdict.NonCompliant, false, false, "P-ATT"},
		{"attestation never covers a technical requirement", base, "BAJO", true, map[string]verdict.Judgement{"EV-01": fail, "EV-02": ok}, good, verdict.NonCompliant, true, false, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateRequirement(c.req, c.level, c.enabled, c.evidences, c.att)
			if got.Status != c.status || got.Evidenced != c.evidenced || got.Attested != c.attested {
				t.Errorf("got %s evidenced=%v attested=%v, want %s %v %v (%q)", got.Status, got.Evidenced, got.Attested, c.status, c.evidenced, c.attested, got.Reason)
			}
			if !strings.Contains(got.Reason, c.reason) {
				t.Errorf("reason %q does not contain %q", got.Reason, c.reason)
			}
		})
	}
}

func req(id string, status verdict.Status, evidenced bool) Requirement {
	return Requirement{ID: id, Status: status, Evidenced: evidenced}
}

func TestEvaluateControl(t *testing.T) {
	na := req("na", verdict.NotApplicable, false)

	cases := []struct {
		name       string
		reqs       []Requirement
		status     verdict.Status
		score      int
		coverage   int
		unmeasured string
	}{
		{"all compliant", []Requirement{req("a", verdict.Compliant, true), req("b", verdict.Compliant, true), na}, verdict.Compliant, 100, 100, ""},
		{"all failing", []Requirement{req("a", verdict.NonCompliant, true), req("b", verdict.NonCompliant, false)}, verdict.NonCompliant, 0, 50, "b"},
		{"mix", []Requirement{req("a", verdict.Compliant, true), req("b", verdict.NonCompliant, true), req("c", verdict.NonCompliant, false)}, verdict.Partial, 33, 67, "c"},
		{"two of three", []Requirement{req("a", verdict.Compliant, true), req("b", verdict.Compliant, true), req("c", verdict.NonCompliant, true)}, verdict.Partial, 67, 100, ""},
		{"nothing applies", []Requirement{na}, verdict.NotApplicable, -1, 0, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateControl(c.reqs)
			score := -1
			if got.Score != nil {
				score = *got.Score
			}
			if got.Status != c.status || score != c.score || got.Coverage != c.coverage || strings.Join(got.Unmeasured, ",") != c.unmeasured {
				t.Errorf("got %+v score %d", got, score)
			}
		})
	}
}

func TestParseAttestations(t *testing.T) {
	got := ParseAttestations([]string{
		"op.acc.1.5 | Política eIDAS | https://intranet/eidas.pdf, file:///srv/doc.pdf texto | 2026-05-12 | RSEG",
		"op.acc.1.r1.1 | Copia | https://EJEMPLO.invalido/x.pdf",
		"op.acc.1.r1.2 |  | https://x/y",
		"",
	})

	a := got["op.acc.1.5"]
	if !a.Sufficient() || len(a.Links) != 2 || a.Date != "2026-05-12" || a.Responsible != "RSEG" {
		t.Errorf("full row: %+v", a)
	}
	if b := got["op.acc.1.r1.1"]; b.Sufficient() {
		t.Errorf("placeholder link proves nothing: %+v", b)
	}
	if _, ok := got["op.acc.1.r1.2"]; ok {
		t.Error("row without reference must be ignored")
	}
}

func TestOpAcc1EndToEnd(t *testing.T) {
	control, _ := catalog.LookupControl("op.acc.1")

	all := map[string]verdict.Judgement{}
	for _, e := range control.Evidences {
		all[e.ID] = ok
	}

	var reqs []Requirement
	for _, r := range control.Requirements {
		reqs = append(reqs, EvaluateRequirement(r, "MEDIO", true, all, nil))
	}

	got := EvaluateControl(reqs)
	if got.Status != verdict.Partial || *got.Score != 75 || got.Applicable != 8 || strings.Join(got.Unmeasured, ",") != "op.acc.1.5,op.acc.1.r1.1" {
		t.Errorf("MEDIO without attestations: %+v score %d", got, *got.Score)
	}

	reqs = nil
	for _, r := range control.Requirements {
		reqs = append(reqs, EvaluateRequirement(r, "BAJO", true, all, nil))
	}
	if got := EvaluateControl(reqs); got.Applicable != 5 || *got.Score != 80 {
		t.Errorf("BAJO: %+v score %d", got, *got.Score)
	}
}

func TestFromDecision(t *testing.T) {

	cases := []struct {
		in        verdict.Judgement
		status    verdict.Status
		evidenced bool
	}{
		{verdict.Judgement{Status: verdict.NotApplicable, Reason: "P-01 is R2"}, verdict.NotApplicable, false},
		{verdict.Judgement{Status: verdict.Compliant}, verdict.Compliant, true},
		{verdict.Judgement{Status: verdict.NonCompliant}, verdict.NonCompliant, true},
		{verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseConfiguration, Reason: "P-01 not set"}, verdict.NonCompliant, false},
	}

	for _, c := range cases {
		got := FromDecision("r", c.in)
		if got.Status != c.status || got.Evidenced != c.evidenced || got.Attested {
			t.Errorf("%+v: got %+v", c.in, got)
		}
	}
}

func TestAttestedRequirementCarriesItsLinks(t *testing.T) {
	doc := catalog.Requirement{ID: "doc", Levels: []string{"MEDIO"}}
	links := []string{"https://intranet/eidas.pdf", `\\nas\politicas\eidas.pdf`}

	got := EvaluateRequirement(doc, "MEDIO", true, nil, &Attestation{Reference: "Política eIDAS", Links: links})

	if args := got.Message.Args; args["reference"] != "Política eIDAS" || len(args["links"].([]string)) != 2 {
		t.Errorf("args %+v", args)
	}
	if !strings.Contains(got.Message.Render("es"), "https://intranet/eidas.pdf") {
		t.Errorf("reason %q", got.Message.Render("es"))
	}
}
