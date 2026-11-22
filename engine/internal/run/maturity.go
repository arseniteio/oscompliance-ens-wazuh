package run

import (
	"slices"
	"sync"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/maturity"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func accredit(v *verdict.Verdict, workingDaysBefore int) {

	if v.Status == verdict.NotApplicable {
		return
	}
	workingToday := v.MeasuredRequirements != nil && *v.MeasuredRequirements > 0 && v.Score != nil && *v.Score > 0
	level := maturity.Accredit(workingToday, workingDaysBefore)
	days := workingDaysBefore
	if workingToday {
		days++
	}
	v.Maturity = &verdict.Maturity{Accredited: &level, WorkingDays: &days, PeriodDays: maturity.PeriodDays}
}

type levels struct {
	mu        sync.Mutex
	byControl map[string][]int
	machines  map[string]*verdict.Tally
}

func newLevels() *levels {
	return &levels{byControl: map[string][]int{}, machines: map[string]*verdict.Tally{}}
}

func (l *levels) add(control string, v verdict.Verdict) {
	if v.Status == verdict.NotApplicable {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.machines[control]
	if !ok {
		t = &verdict.Tally{}
		l.machines[control] = t
	}
	t.Total++
	if v.Status == verdict.Compliant {
		t.Met++
	}
	if v.Maturity != nil && v.Maturity.Accredited != nil {
		l.byControl[control] = append(l.byControl[control], *v.Maturity.Accredited)
	}
}

func scored(t *verdict.Tally, scales maturity.Scales, control, agentID string) *verdict.TallyResult {
	if t == nil || t.Total <= 0 {
		return nil
	}
	out := &verdict.TallyResult{Met: t.Met, Total: t.Total, Percent: t.Percent()}
	scale, _ := scales.For(control, agentID)
	level := scale.Level(out.Percent)
	out.Level = &level
	return out
}

func judgedByLevel(j verdict.Judgement, tally *verdict.TallyResult, controlLevel string) verdict.Judgement {

	// A count is not all or nothing: the share of items that meet the evidence gives a CMM
	// level, and that level meets the control when it reaches the one its category asks for.

	required, known := maturity.Required(controlLevel)
	if tally == nil || tally.Level == nil || !known || (j.Status != verdict.Compliant && j.Status != verdict.NonCompliant) {
		return j
	}

	detail := j.Message
	if detail.IsZero() {
		detail = catalog.Raw(j.Reason)
	}
	args := []any{"met", tally.Met, "total", tally.Total, "percent", tally.Percent, "level", *tally.Level,
		"required", required, "category", catalog.CategoryLabel(controlLevel), "detail", detail}

	out := j
	if *tally.Level >= required {
		out = verdict.Explain(verdict.Compliant, "", catalog.Says("tally.meets_level", args...))
	} else {
		out = verdict.Explain(verdict.NonCompliant, "", catalog.Says("tally.below_level", args...))
	}
	out.Tally = j.Tally
	return out
}

func organizationBase(system string, now time.Time, engineVersion string) verdict.Verdict {
	stamp := now.UTC().Format(time.RFC3339)
	return verdict.Verdict{
		OSComplianceVerdict: verdict.SchemaVersion,
		System:              system,
		Timestamp:           stamp,
		Scope:               verdict.ScopeOrganization,
		Agent:               verdict.Agent{ID: verdict.OrganizationAgent},
		WindowStart:         stamp,
		WindowEnd:           stamp,
		EngineVersion:       engineVersion,
	}
}

func organizationVerdicts(controls []evaluator.Evaluator, judged *levels, assessments []maturity.Assessment, scales maturity.Scales, base verdict.Verdict) []verdict.Verdict {

	// One verdict per judged control with the lowest level of its machines and the declared
	// assessment, one per assessed measure the engine does not judge, and one for the ENS.

	declared := map[string]maturity.Assessment{}
	for _, a := range assessments {
		if a.Valid() {
			declared[a.Measure] = a
		}
	}

	var out []verdict.Verdict
	var measures []maturity.Measure
	seen := map[string]bool{}

	for _, ev := range controls {
		id := ev.Control()
		seen[id] = true
		perMachine := judged.byControl[id]
		if len(perMachine) == 0 {
			continue
		}
		level, _ := maturity.Organization(perMachine)
		m := measureVerdict(base, id, &level, declared[id])
		m.Maturity.Machines = len(perMachine)
		m.Tally = scored(judged.machines[id], scales, id, "")
		out = append(out, m)
		measures = append(measures, maturity.Measure{ID: id, Accredited: &level, Assessed: declared[id].Level, Target: declared[id].Target})
	}

	var undeclared []string
	for id := range declared {
		if !seen[id] {
			undeclared = append(undeclared, id)
		}
	}
	slices.Sort(undeclared)
	for _, id := range undeclared {
		if _, judgedByEngine := catalog.LookupControl(id); judgedByEngine {
			continue
		}
		out = append(out, measureVerdict(base, id, nil, declared[id]))
		measures = append(measures, maturity.Measure{ID: id, Assessed: declared[id].Level, Target: declared[id].Target})
	}

	return append(out, summaryVerdict(base, maturity.Summarize(measures)))
}

func measureVerdict(base verdict.Verdict, id string, accredited *int, a maturity.Assessment) verdict.Verdict {
	v := base
	v.Control = id
	v.Maturity = &verdict.Maturity{
		Accredited: accredited, PeriodDays: maturity.PeriodDays,
		Assessed: a.Level, Target: a.Target, AssessedBy: a.AssessedBy, AssessedAt: a.AssessedAt,
		References: a.References, Note: a.Note,
		Incoherent: maturity.Incoherent(accredited, a.Level),
	}
	return v
}

func summaryVerdict(base verdict.Verdict, s maturity.Summary) verdict.Verdict {
	v := base
	v.Control = verdict.AllMeasures
	v.Maturity = &verdict.Maturity{
		PeriodDays:       maturity.PeriodDays,
		Applicable:       &s.Applicable,
		Unmeasured:       &s.Unmeasured,
		Unassessed:       &s.Unassessed,
		BelowTarget:      s.BelowTarget,
		AccreditedCounts: s.Accredited[:],
		AssessedCounts:   s.Assessed[:],
		GlobalAccredited: &s.GlobalAccredited,
		GlobalAssessed:   &s.GlobalAssessed,
	}
	return v
}

func judgeControlByLevel(v *verdict.Verdict, scales maturity.Scales, control, agentID, controlLevel string) {

	// The ENS valuation of a measure is its CMM level: 7 of 8 requirements (87 %) is L3 and meets
	// a MEDIO system, so the control is COMPLIANT there instead of PARTIAL.

	if v.Score == nil {
		return
	}
	scale, _ := scales.For(control, agentID)
	c, known := maturity.Judge(*v.Score, scale, controlLevel)
	if !known {
		return
	}
	v.Status = c.Status
	v.Compliance = &verdict.ComplianceResult{Percent: c.Percent, Level: c.Level, Required: c.Required, Category: catalog.CategoryLabel(controlLevel)}
}
