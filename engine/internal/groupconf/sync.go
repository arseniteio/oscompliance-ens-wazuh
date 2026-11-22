package groupconf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

type API interface {
	GroupAgents(ctx context.Context, group string) ([]wazuhapi.Agent, error)
	GroupConfiguration(ctx context.Context, group string) (string, error)
	PutGroupConfiguration(ctx context.Context, group, conf string) error
}

type Change struct {
	Group   string    `json:"group"`
	At      time.Time `json:"@timestamp"`
	Applied bool      `json:"applied"`
	Before  string    `json:"before"`
	After   string    `json:"after"`
	Agents  int       `json:"agents"`
}

func Sync(ctx context.Context, api API, policy Policy, groups []string, apply bool, now time.Time) ([]Change, error) {

	var changes []Change
	var errs []error
	seen := map[string]bool{}

	for _, group := range slices.Sorted(slices.Values(groups)) {

		change, err := syncGroup(ctx, api, policy, group, seen, apply, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("group %s: %w", group, err))
			continue
		}
		if change != nil {
			changes = append(changes, *change)
		}
	}

	return changes, errors.Join(errs...)
}

func syncGroup(ctx context.Context, api API, policy Policy, group string, seen map[string]bool, apply bool, now time.Time) (*Change, error) {

	members, err := api.GroupAgents(ctx, group)
	if err != nil {
		return nil, err
	}

	agents := make([]Agent, 0, len(members))
	for _, m := range members {
		if seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		agents = append(agents, Agent{Name: m.Name, Machine: ForAgent(policy, m.ID, m.Name, m.OS.Platform)})
	}

	current, err := api.GroupConfiguration(ctx, group)
	if err != nil {
		return nil, err
	}

	region := Region(agents)
	if Same(Current(current), region) {
		return nil, nil
	}

	change := &Change{Group: group, At: now, Before: Current(current), After: region, Agents: len(agents)}
	if !apply {
		return change, nil
	}

	if err := api.PutGroupConfiguration(ctx, group, Merge(current, region)); err != nil {
		return nil, err
	}
	change.Applied = true

	return change, nil
}
