package run

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type parameterExplainer interface {
	Explain(agentID, controlID, paramID string) (params.Resolution, bool)
}

var parameterID = regexp.MustCompile(`^P-[0-9A-Z]+$`)

const shownListItems = 5

func explainConfiguration(policy params.Lister, control string, agent verdict.Agent, j verdict.Judgement) verdict.Judgement {

	if j.Status != verdict.NotEvaluable || j.Cause != verdict.CauseConfiguration {
		return j
	}

	detail := j.Message
	if detail.IsZero() {
		detail = catalog.Raw(j.Reason)
	}

	return verdict.Explain(j.Status, j.Cause, configurationReason(policy, control, agent, detail))
}

func explainDecisions(policy params.Lister, control string, agent verdict.Agent, decisions map[string]verdict.Judgement) map[string]verdict.Judgement {
	out := make(map[string]verdict.Judgement, len(decisions))
	for id, d := range decisions {
		out[id] = explainConfiguration(policy, control, agent, d)
	}
	return out
}

func configurationReason(policy params.Lister, control string, agent verdict.Agent, detail catalog.Message) catalog.Message {

	machine := machineLabel(agent)

	id, found := parameterIn(detail)
	if !found {
		return catalog.Says("configuration.gap", "machine", machine, "detail", detail)
	}

	explainer, canExplain := policy.(parameterExplainer)
	if !canExplain {
		return catalog.Says("configuration.parameter_gap", "machine", machine, "param", id, "detail", detail)
	}

	r, set := explainer.Explain(agent.ID, control, id)
	if !set || emptyValue(r.Value) {
		return catalog.Says("configuration.parameter_unset", "machine", machine, "param", id)
	}

	return catalog.Says("configuration.parameter_value", "machine", machine, "param", id,
		"value", describeValue(r.Value), "source", sourcesOf(r.Sources), "detail", detail)
}

func machineLabel(agent verdict.Agent) string {
	if agent.Name == "" || agent.Name == agent.ID {
		return agent.ID
	}
	return fmt.Sprintf("%s (%s)", agent.Name, agent.ID)
}

func parameterIn(m catalog.Message) (string, bool) {

	if id, ok := m.Args["param"].(string); ok && parameterID.MatchString(id) {
		return id, true
	}

	for _, arg := range m.Args {
		switch v := arg.(type) {
		case catalog.Message:
			if id, ok := parameterIn(v); ok {
				return id, true
			}
		case []catalog.Message:
			for _, nested := range v {
				if id, ok := parameterIn(nested); ok {
					return id, true
				}
			}
		}
	}

	return "", false
}

func emptyValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	case []string:
		return len(v) == 0
	}
	return false
}

func describeValue(value any) catalog.Message {

	var items []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			items = append(items, fmt.Sprint(item))
		}
	case []string:
		items = v
	default:
		return catalog.Says("configuration.value", "value", fmt.Sprint(v))
	}

	// Lists such as P-07 can hold thousands of accounts; the reason names a few and counts
	// the rest so it stays readable in a table row.
	if len(items) <= shownListItems {
		return catalog.Says("configuration.value", "value", strings.Join(items, ", "))
	}
	return catalog.Says("configuration.value_more", "value", strings.Join(items[:shownListItems], ", "), "more", len(items)-shownListItems)
}

func sourcesOf(sources []params.Source) []catalog.Message {
	out := make([]catalog.Message, 0, len(sources))
	for _, s := range sources {
		out = append(out, sourceOf(s))
	}
	return out
}

func sourceOf(s params.Source) catalog.Message {
	switch s.Kind {
	case "agent":
		return catalog.Says("configuration.source_agent")
	case "template":
		return catalog.Says("configuration.source_template", "id", s.ID)
	case "profile":
		return catalog.Says("configuration.source_profile", "id", s.ID)
	}
	return catalog.Says("configuration.source_organisation")
}
