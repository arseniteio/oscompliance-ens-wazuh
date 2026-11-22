package opmon2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	AgentPasses(ctx context.Context, since time.Time) (map[string]fact.AgentPass, error)
}

type Degrees interface {
	ImplementationDegrees(ctx context.Context, system string, since time.Time) (map[string]verdict.Degree, error)
}

const control = "op.mon.2"

type Evaluator struct {
	facts   Facts
	degrees Degrees

	pass      evaluator.Pass
	manager   *source.Manager
	reporting map[string]source.Reporting
	passes    map[string]fact.AgentPass

	measured   map[string]verdict.Degree
	degreesErr error
}

func NewEvaluator(facts Facts, degrees Degrees) *Evaluator {
	return &Evaluator{facts: facts, degrees: degrees}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.manager, _ = e.facts.Manager(ctx)
	var err error
	if e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); err != nil {
		return fmt.Errorf("reporting: %w", err)
	}
	if e.passes, err = e.facts.AgentPasses(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("agent passes: %w", err)
	}
	// The verdicts of the previous passes: this pass writes its own only when it ends.
	e.measured, e.degreesErr = e.degrees.ImplementationDegrees(ctx, pass.System, pass.WindowStart)
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	days, daysProblem := passes.Whole(policy, agent.ID, control, "P-02", "param.not_days")
	margin, err := policy.Number(agent.ID, control, "P-03")
	if errors.Is(err, params.ErrNotSet) {
		margin, err = 0, nil
	}
	if err != nil && daysProblem.IsZero() {
		daysProblem = passes.Param("P-03", err)
	}
	people, peopleErr := policy.List(agent.ID, control, "P-05")
	register, registerErr := policy.List(agent.ID, control, "P-06")
	registerProblem := passes.ParamProblem("P-06", registerErr)
	if peopleErr != nil {
		registerProblem = passes.Param("P-05", peopleErr)
	}

	cycle := func(scope string, resources bool) verdict.Judgement {
		j, _ := passes.Review(Cycles(register, Validators(people, scope), resources), registerProblem, "P-06", days+int(margin), daysProblem, "P-02", now)
		return j
	}
	put("EV-02", cycle(ScopeMetrics, false))
	put("EV-06", cycle(ScopeResources, true))

	put("EV-03", func() verdict.Judgement {
		if !daysProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, daysProblem)
		}
		indicators, err := policy.List(agent.ID, control, "P-04")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-04", err))
		}
		rows, err := policy.List(agent.ID, opexp7.Control, opexp7.RegisterParam)
		if err != nil && !errors.Is(err, params.ErrNotSet) {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("op.exp.7 P-13", err))
		}
		return JudgeEV03(Period(opexp7.ParseRegister(rows), now.AddDate(0, 0, -days)), indicators)
	}())

	applicability, applicabilityErr := policy.List(agent.ID, control, "P-01")
	var degree *verdict.Degree
	if d, ok := e.measured[agent.ID]; ok {
		degree = &d
	}
	put("EV-01", JudgeEV01(Applicable(applicability), passes.ParamProblem("P-01", applicabilityErr), degree, e.degreesErr))
	put("EV-05", JudgeEV05(degree, e.degreesErr))

	var last *fact.AgentPass
	if p, ok := e.passes[agent.ID]; ok {
		last = &p
	}
	put("EV-04", JudgeEV04(opmon1.ReportingOf(agent.ID, e.reporting, e.manager, now), last, e.pass.WindowStart))

	return results, nil
}

func Period(incidents []opexp7.Incident, since time.Time) []opexp7.Incident {
	var out []opexp7.Incident
	for _, in := range incidents {
		if !in.Opened().Before(since) {
			out = append(out, in)
		}
	}
	return out
}
