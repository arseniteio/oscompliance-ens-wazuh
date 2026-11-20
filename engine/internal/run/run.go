package run

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/aggregate"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/batch"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/maturity"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Agents interface {
	Agents(ctx context.Context, since time.Time) ([]verdict.Agent, error)
	RegisteredAgents(ctx context.Context, since time.Time) ([]verdict.Agent, error)
}

type Scope interface {
	Evaluable(agentID string) bool
	Excluded(controlID, agentID string) bool
}

type Sink interface {
	Write(ctx context.Context, v verdict.Verdict) error
}

type Config struct {
	Window time.Duration

	Lookback      time.Duration
	EngineVersion string

	Scope func(ctx context.Context, since time.Time) (Scope, error)

	Plan func(agents []verdict.Agent)

	Flush func(ctx context.Context) error

	WorkingDays func(ctx context.Context, control string, now time.Time) (map[string]int, error)

	Assessments []maturity.Assessment

	Scales maturity.Scales
}

func Once(ctx context.Context, agentList Agents, controls []evaluator.Evaluator, policy params.Lister, sink Sink, cfg Config, now time.Time) (int, error) {

	pass := evaluator.Pass{Now: now, WindowStart: now.Add(-cfg.Window), LookbackStart: now.Add(-cfg.Lookback)}

	agents, err := judgedAgents(ctx, agentList, pass.LookbackStart)

	if err != nil {
		return 0, err
	}

	excluded := func(string, string) bool { return false }
	if cfg.Scope != nil {
		scope, err := cfg.Scope(ctx, pass.LookbackStart)
		if err != nil {
			return 0, fmt.Errorf("scope: %w", err)
		}
		agents = slices.DeleteFunc(agents, func(a verdict.Agent) bool { return !scope.Evaluable(a.ID) })
		excluded = scope.Excluded
	}

	if cfg.Plan != nil {
		cfg.Plan(agents)
	}

	var mu sync.Mutex
	var errs []error
	written := 0

	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
	}

	store := func(v verdict.Verdict) {
		mu.Lock()
		defer mu.Unlock()
		if err := sink.Write(ctx, v); err != nil {
			errs = append(errs, fmt.Errorf("agent %s %s %s %s%s: write: %w", v.Agent.ID, v.Control, v.Scope, v.Requirement, v.Evidence, err))
			return
		}
		written++
	}

	levels := newLevels()

	judge := func(ctx context.Context, ev evaluator.Evaluator) {

		control, ok := catalog.LookupControl(ev.Control())
		if !ok {
			fail(fmt.Errorf("%s: not in the catalog", ev.Control()))
			return
		}

		begun := true
		if err := ev.Begin(ctx, pass); err != nil {
			fail(fmt.Errorf("%s: %w", control.Control, err))
			begun = false
		}

		base := func(agent verdict.Agent, scope string) verdict.Verdict {
			return verdict.Verdict{
				OSComplianceVerdict: verdict.SchemaVersion,
				Timestamp:           now.UTC().Format(time.RFC3339),
				Scope:               scope,
				Control:             control.Control,
				Agent:               agent,
				WindowStart:         pass.WindowStart.UTC().Format(time.RFC3339),
				WindowEnd:           now.UTC().Format(time.RFC3339),
				EngineVersion:       cfg.EngineVersion,
			}
		}

		var history map[string]int
		if cfg.WorkingDays != nil {
			var err error
			if history, err = cfg.WorkingDays(ctx, control.Control, now); err != nil {
				fail(fmt.Errorf("%s: maturity history: %w", control.Control, err))
			}
		}

		for _, agent := range agents {

			results := map[string]evaluator.Result{}
			var decisions map[string]verdict.Judgement
			out := excluded(control.Control, agent.ID)
			if begun {
				var err error
				if results, err = ev.Agent(ctx, agent, policy); err != nil && !out {
					fail(fmt.Errorf("%s agent %s: %w", control.Control, agent.ID, err))
				}
				if d, ok := ev.(evaluator.Decider); ok {
					decisions = explainDecisions(policy, control.Control, agent, d.Decisions(agent.ID))
				}
			}

			var why catalog.Message
			if out {
				why = catalog.Says("scope.excluded_by_group", "group", catalog.ExclusionGroup(control.Control))
				results, decisions = excludedFrom(control, why)
			}

			evidences := map[string]verdict.Judgement{}

			for _, e := range control.Evidences {

				r, judged := results[e.ID]
				na, notApp := notApplicable(policy, control, agent.ID, e.ID)

				switch {
				case notApp:
					r.Judgement = na
				case !judged:
					continue
				}

				r.Judgement = explainConfiguration(policy, control.Control, agent, r.Judgement)
				tally := scored(r.Judgement.Tally, cfg.Scales, control.Control, agent.ID)
				r.Judgement = judgedByLevel(r.Judgement, tally, controlLevel(policy, control.Control, agent.ID).Level)
				evidences[e.ID] = r.Judgement

				v := base(agent, verdict.ScopeEvidence)
				v.Evidence, v.Status, v.Cause, v.RunID = e.ID, r.Judgement.Status, r.Judgement.Cause, r.RunID
				v.Explained(r.Judgement.Message, r.Judgement.Reason)
				v.Tally = tally
				store(v)
			}

			for _, v := range aggregateVerdicts(policy, control, agent, evidences, decisions, base) {
				if out && v.Scope == verdict.ScopeControl {
					v.Explained(why, "")
				}
				if v.Scope == verdict.ScopeControl && history != nil {
					accredit(&v, history[agent.ID])
					levels.add(control.Control, v)
				}
				store(v)
			}
		}
	}

	done := map[string]chan struct{}{}
	for _, ev := range controls {
		done[ev.Control()] = make(chan struct{})
	}

	var wg sync.WaitGroup
	for _, ev := range controls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(done[ev.Control()])
			if f, ok := ev.(evaluator.Follower); ok {
				for _, id := range f.After() {
					if ch, ok := done[id]; ok && id != ev.Control() {
						<-ch
					}
				}
			}
			judge(batch.WithScope(ctx, ev.Control()), ev)
		}()
	}
	wg.Wait()

	if cfg.WorkingDays != nil {
		for _, v := range organizationVerdicts(controls, levels, cfg.Assessments, cfg.Scales, organizationBase(now, cfg.EngineVersion)) {
			store(v)
		}
	}

	if f, ok := sink.(interface{ Flush(context.Context) error }); ok {
		if err := f.Flush(ctx); err != nil {
			errs = append(errs, fmt.Errorf("write: %w", err))
		}
	}

	if cfg.Flush != nil {
		if err := cfg.Flush(ctx); err != nil {
			errs = append(errs, fmt.Errorf("flush: %w", err))
		}
	}

	return written, errors.Join(errs...)
}

func excludedFrom(control catalog.Control, why catalog.Message) (map[string]evaluator.Result, map[string]verdict.Judgement) {

	out := verdict.Explain(verdict.NotApplicable, "", why)

	results := map[string]evaluator.Result{}
	for _, e := range control.Evidences {
		results[e.ID] = evaluator.Result{Judgement: out}
	}

	decisions := map[string]verdict.Judgement{}
	for _, r := range control.Requirements {
		decisions[r.ID] = out
	}

	return results, decisions
}

func judgedAgents(ctx context.Context, list Agents, since time.Time) ([]verdict.Agent, error) {

	senders, err := list.Agents(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("agents: %w", err)
	}

	registered, err := list.RegisteredAgents(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("registered agents: %w", err)
	}

	seen := map[string]int{}
	var agents []verdict.Agent

	for _, a := range append(senders, registered...) {
		if i, ok := seen[a.ID]; ok {
			if agents[i].Name == "" {
				agents[i].Name = a.Name
			}
			continue
		}
		seen[a.ID] = len(agents)
		agents = append(agents, a)
	}

	return agents, nil
}

func aggregateVerdicts(policy params.Lister, control catalog.Control, agent verdict.Agent, evidences, decisions map[string]verdict.Judgement, base func(verdict.Agent, string) verdict.Verdict) []verdict.Verdict {

	level := controlLevel(policy, control.Control, agent.ID)
	enabled := policy.ControlEnabled(control.Control)

	rows, _ := policy.List(agent.ID, control.Control, "P-ATT")
	attestations := aggregate.ParseAttestations(rows)

	var out []verdict.Verdict
	var reqs []aggregate.Requirement

	for _, req := range control.Requirements {

		var att *aggregate.Attestation
		if a, ok := attestations[req.ID]; ok {
			att = &a
		}

		r := aggregate.EvaluateRequirement(req, level.Level, enabled, evidences, att)
		if level.Adjusted != nil && r.Message.Code == "requirement.out_of_level" {
			r.Message = catalog.Says("requirement.out_of_adjusted_level", "levels", req.Levels, "level", level.Level, "reason", level.Adjusted.Reason)
			r.Reason = r.Message.Render("en")
		}

		if d, ok := decisions[req.ID]; ok && r.Status != verdict.NotApplicable {
			r = aggregate.FromDecision(req.ID, d)
		}
		reqs = append(reqs, r)

		v := base(agent, verdict.ScopeRequirement)
		v.Requirement, v.Status, v.Attested = req.ID, r.Status, r.Attested
		v.Explained(r.Message, r.Reason)
		if r.Status != verdict.NotApplicable {
			evidenced := r.Evidenced
			v.Evidenced = &evidenced
		}
		out = append(out, v)
	}

	c := aggregate.EvaluateControl(reqs)

	v := base(agent, verdict.ScopeControl)
	v.Status, v.Score = c.Status, c.Score

	if c.Status == verdict.NotApplicable {
		v.Explained(catalog.Says("control.none_applies"), "")
		if !enabled {
			v.Explained(catalog.Says("control.disabled"), "")
		}
	} else {
		coverage, applicable, measured := c.Coverage, c.Applicable, c.Measured
		v.Coverage, v.ApplicableRequirements, v.MeasuredRequirements = &coverage, &applicable, &measured
		v.UnmeasuredRequirements = c.Unmeasured
		v.Explained(catalog.Says("control.summary", "compliant", countCompliant(reqs), "applicable", applicable, "measured", measured), "")
	}

	return append(out, v)
}

func countCompliant(reqs []aggregate.Requirement) int {
	n := 0
	for _, r := range reqs {
		if r.Status == verdict.Compliant {
			n++
		}
	}
	return n
}

func notApplicable(policy params.Lister, control catalog.Control, agentID, evidenceID string) (verdict.Judgement, bool) {

	if !policy.ControlEnabled(control.Control) {
		return verdict.Explain(verdict.NotApplicable, "", catalog.Says("evidence.control_disabled", "control", control.Control)), true
	}

	level := controlLevel(policy, control.Control, agentID)
	evidence, known := control.Evidence(evidenceID)

	if level.Level == "" || !known || evidence.AppliesAt(level.Level) {
		return verdict.Judgement{}, false
	}

	if level.Adjusted != nil {
		return verdict.Explain(verdict.NotApplicable, "", catalog.Says("evidence.out_of_adjusted_level", "evidence", evidenceID, "levels", evidence.Levels, "level", level.Level, "reason", level.Adjusted.Reason)), true
	}

	return verdict.Explain(verdict.NotApplicable, "", catalog.Says("evidence.out_of_level", "evidence", evidenceID, "levels", evidence.Levels, "level", catalog.CategoryLabel(level.Level))), true
}

type levelAdjuster interface {
	ControlLevel(controlID, agentID string) params.ControlLevel
}

func controlLevel(policy params.Lister, controlID, agentID string) params.ControlLevel {
	if adjuster, ok := policy.(levelAdjuster); ok {
		return adjuster.ControlLevel(controlID, agentID)
	}
	return params.ControlLevel{Level: policy.Level()}
}
