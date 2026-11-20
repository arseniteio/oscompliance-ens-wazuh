package run

import (
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

// Collection gaps name the fact type the agent should have sent (identity_snapshot,
// sudo_grant); the auditor reads its catalog label instead of the internal name.
func readableFacts(j verdict.Judgement) verdict.Judgement {
	if j.Message.IsZero() {
		return j
	}
	m := labelFacts(j.Message)
	out := verdict.Explain(j.Status, j.Cause, m)
	out.Tally = j.Tally
	return out
}

func labelFacts(m catalog.Message) catalog.Message {
	if len(m.Args) == 0 {
		return m
	}
	args := make(map[string]any, len(m.Args))
	for key, arg := range m.Args {
		switch v := arg.(type) {
		case string:
			if key == "fact" {
				if _, known := catalog.Messages("en")["fact."+v]; known {
					args[key] = catalog.Says("fact." + v)
					continue
				}
			}
			args[key] = v
		case catalog.Message:
			args[key] = labelFacts(v)
		case []catalog.Message:
			nested := make([]catalog.Message, len(v))
			for i, n := range v {
				nested[i] = labelFacts(n)
			}
			args[key] = nested
		default:
			args[key] = arg
		}
	}
	return catalog.Message{Code: m.Code, Args: args}
}
