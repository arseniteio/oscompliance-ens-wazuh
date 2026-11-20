package aggregate

import (
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Attestation struct {
	Reference   string
	Links       []string
	Date        string
	Responsible string
}

func (a Attestation) Sufficient() bool {
	return a.Reference != "" && len(a.Links) > 0
}

type Requirement struct {
	ID        string
	Status    verdict.Status
	Evidenced bool
	Attested  bool
	Reason    string
	Message   catalog.Message
}

func (r *Requirement) says(m catalog.Message) {
	r.Message, r.Reason = m, m.Render("en")
}

func Cause(c verdict.Cause) catalog.Message {
	return catalog.Says("cause." + string(c))
}

func reasonOf(j verdict.Judgement) any {
	if j.Message.IsZero() {
		return j.Reason
	}
	return j.Message
}

type Control struct {
	Status     verdict.Status
	Score      *int
	Coverage   int
	Applicable int
	Measured   int
	Unmeasured []string
}

func EvaluateRequirement(req catalog.Requirement, level string, controlEnabled bool, evidences map[string]verdict.Judgement, attestation *Attestation) Requirement {

	out := Requirement{ID: req.ID}

	if !controlEnabled {
		out.Status = verdict.NotApplicable
		out.says(catalog.Says("requirement.control_disabled"))
		return out
	}
	if level != "" && !req.AppliesAt(level) {
		out.Status = verdict.NotApplicable
		if req.ApplicabilityReason != "" {
			out.says(catalog.Says("requirement.declared_out_of_level", "reason", req.ApplicabilityReason))
		} else {
			out.says(catalog.Says("requirement.out_of_level", "levels", req.Levels, "level", catalog.CategoryLabel(level)))
		}
		return out
	}

	if len(req.EvidenceIDs) == 0 {
		if attestation != nil && attestation.Sufficient() {
			out.Status, out.Evidenced, out.Attested = verdict.Compliant, true, true
			out.says(catalog.Says("requirement.attested", "reference", attestation.Reference, "links", attestation.Links))
			return out
		}
		out.Status = verdict.NonCompliant
		out.says(catalog.Says("requirement.no_attestation"))
		return out
	}

	var failing, compliant []string
	var unmeasured []catalog.Message

	for _, id := range req.EvidenceIDs {

		j, ok := evidences[id]
		if !ok {
			j = verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseCollection}
		}

		switch j.Status {
		case verdict.NotApplicable:
		case verdict.NonCompliant:
			failing = append(failing, id)
		case verdict.Compliant:
			compliant = append(compliant, id)
		default:
			unmeasured = append(unmeasured, catalog.Says("requirement.evidence_cause", "evidence", id, "cause", Cause(j.Cause)))
		}
	}

	switch {
	case len(failing) > 0:

		out.Status, out.Evidenced = verdict.NonCompliant, true
		out.says(catalog.Says("requirement.non_compliant", "evidences", failing))
	case len(unmeasured) > 0:
		out.Status = verdict.NonCompliant
		out.says(catalog.Says("requirement.not_evidenced", "evidences", unmeasured))
	case len(compliant) > 0:
		out.Status, out.Evidenced = verdict.Compliant, true
		out.says(catalog.Says("requirement.compliant", "evidences", compliant))
	default:
		out.Status = verdict.NotApplicable
		out.says(catalog.Says("requirement.none_applies", "evidences", req.EvidenceIDs))
	}

	return out
}

func FromDecision(id string, d verdict.Judgement) Requirement {

	out := Requirement{ID: id, Status: d.Status, Reason: d.Reason, Message: d.Message}

	switch d.Status {
	case verdict.Compliant, verdict.NonCompliant:
		out.Evidenced = true
	case verdict.NotApplicable:
	default:
		out.Status = verdict.NonCompliant
		if d.Cause != "" {
			out.says(catalog.Says("requirement.decision_gap_cause", "cause", Cause(d.Cause), "reason", reasonOf(d)))
		} else {
			out.says(catalog.Says("requirement.decision_gap", "reason", reasonOf(d)))
		}
	}

	return out
}

func EvaluateControl(reqs []Requirement) Control {

	var applicable []Requirement

	for _, r := range reqs {
		if r.Status != verdict.NotApplicable {
			applicable = append(applicable, r)
		}
	}

	if len(applicable) == 0 {
		return Control{Status: verdict.NotApplicable}
	}

	out := Control{Applicable: len(applicable)}
	sum, compliant := 0, 0

	for _, r := range applicable {
		if r.Evidenced {
			out.Measured++
		} else {
			out.Unmeasured = append(out.Unmeasured, r.ID)
		}
		if r.Status == verdict.Compliant {
			compliant++
			sum += 100
		}
	}

	out.Coverage = roundDiv(out.Measured*100, out.Applicable)

	score := roundDiv(sum, out.Applicable)
	out.Score = &score

	switch compliant {
	case out.Applicable:
		out.Status = verdict.Compliant
	case 0:
		out.Status = verdict.NonCompliant
	default:
		out.Status = verdict.Partial
	}

	return out
}

func roundDiv(a, b int) int {
	return (2*a + b) / (2 * b)
}

func ParseAttestations(rows []string) map[string]Attestation {

	out := map[string]Attestation{}

	for _, row := range rows {

		cells := strings.Split(row, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		for len(cells) < 5 {
			cells = append(cells, "")
		}

		if cells[0] == "" || cells[1] == "" {
			continue
		}

		var links []string
		for _, link := range strings.FieldsFunc(cells[2], func(r rune) bool { return r == ' ' || r == ',' || r == ';' || r == '\t' }) {
			if usableLink(link) {
				links = append(links, link)
			}
		}

		out[cells[0]] = Attestation{Reference: cells[1], Links: links, Date: cells[3], Responsible: cells[4]}
	}

	return out
}

var placeholderHosts = []string{"ejemplo.invalido", "example.invalid"}

func usableLink(link string) bool {

	lower := strings.ToLower(link)

	if slices.ContainsFunc(placeholderHosts, func(h string) bool { return strings.Contains(lower, h) }) {
		return false
	}

	for _, prefix := range []string{"http://", "https://", "file://"} {
		if strings.HasPrefix(lower, prefix) && len(link) > len(prefix) {
			return true
		}
	}

	return strings.HasPrefix(link, `\\`) && len(link) > 2 || strings.HasPrefix(link, "/") && len(link) > 1
}
