package evaluator

import (
	"context"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Pass struct {
	System        string
	Now           time.Time
	WindowStart   time.Time
	LookbackStart time.Time
}

type Result struct {
	Judgement verdict.Judgement
	RunID     string
}

type Evaluator interface {
	Control() string

	Begin(ctx context.Context, pass Pass) error

	Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]Result, error)
}

type Decider interface {
	Decisions(agentID string) map[string]verdict.Judgement
}

type Follower interface {
	After() []string
}
