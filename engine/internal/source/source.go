package source

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/batch"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

const FactRule = "119001"

const pageSize = 1000

type Source struct {
	client     *indexer.Client
	index      string
	monitoring string
	states     string
	pass       passState

	managerInventory freshCache[*Inventory]
	manager          freshCache[*Manager]
	managerNetwork   func(ctx context.Context, tools []string) (*Network, error)
	networks         networkCache
	vulnerabilities  vulnerabilityCache
	managerName      func(ctx context.Context) (string, error)
}

// UseManagerName names agent 000 from the manager API. Every node of a
// cluster has its own agent 000, so the alerts can carry a worker's name.
func (s *Source) UseManagerName(read func(ctx context.Context) (string, error)) {
	s.managerName = read
}

func (s *Source) nameManager(ctx context.Context, agents []verdict.Agent) []verdict.Agent {
	if s.managerName == nil || !slices.ContainsFunc(agents, func(a verdict.Agent) bool { return a.ID == ManagerID }) {
		return agents
	}
	name, err := s.managerName(ctx)
	if err != nil || strings.TrimSpace(name) == "" {
		return agents
	}
	out := slices.DeleteFunc(slices.Clone(agents), func(a verdict.Agent) bool { return a.ID == ManagerID })
	return append(out, verdict.Agent{ID: ManagerID, Name: strings.TrimSpace(name)})
}

func New(client *indexer.Client, index, monitoring, states string) *Source {
	return &Source{client: client, index: index, monitoring: monitoring, states: states}
}

const ManagerID = "000"

func (s *Source) RegisteredAgents(ctx context.Context, since time.Time) ([]verdict.Agent, error) {

	monitoring, err := s.agentNames(ctx, s.monitoring, "id", "name", []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	})

	if err != nil {
		return nil, fmt.Errorf("monitoring: %w", err)
	}

	manager, err := s.agentNames(ctx, s.index, "agent.id", "agent.name", []any{
		map[string]any{"term": map[string]any{"agent.id": ManagerID}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	})

	if err != nil {
		return nil, fmt.Errorf("manager: %w", err)
	}

	return s.nameManager(ctx, append(monitoring, manager...)), nil
}

func (s *Source) Platforms(ctx context.Context, since time.Time) (map[string]string, error) {

	filter := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}}}
	sub := map[string]any{"last": map[string]any{"top_hits": map[string]any{
		"size": 1, "sort": []any{map[string]any{"timestamp": "desc"}}, "_source": []string{"os.platform"},
	}}}

	platforms := map[string]string{}

	err := s.compositeIn(ctx, s.monitoring, filter, []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": "id"}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Last struct {
					Hits struct {
						Hits []struct {
							Source struct {
								OS struct {
									Platform string `json:"platform"`
								} `json:"os"`
							} `json:"_source"`
						} `json:"hits"`
					} `json:"hits"`
				} `json:"last"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			if len(c.Last.Hits.Hits) > 0 {
				platforms[keyString(key, "a")] = c.Last.Hits.Hits[0].Source.OS.Platform
			}
			return nil
		})

	platforms[ManagerID] = ""
	return platforms, err
}

func (s *Source) agentNames(ctx context.Context, index, idField, nameField string, filter []any) ([]verdict.Agent, error) {

	sub := map[string]any{"name": map[string]any{"terms": map[string]any{"field": nameField, "size": 1}}}

	var agents []verdict.Agent

	err := s.compositeIn(ctx, index, filter, []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": idField}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Name struct {
					Buckets []struct {
						Key string `json:"key"`
					} `json:"buckets"`
				} `json:"name"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			a := verdict.Agent{ID: keyString(key, "a")}
			if len(c.Name.Buckets) > 0 {
				a.Name = c.Name.Buckets[0].Key
			}
			agents = append(agents, a)
			return nil
		})

	return agents, err
}

type hit struct {
	ID     string          `json:"_id"`
	Sort   []any           `json:"sort"`
	Source json.RawMessage `json:"_source"`
}

type alert struct {
	Timestamp string         `json:"timestamp"`
	Agent     verdict.Agent  `json:"agent"`
	Data      map[string]any `json:"data"`
}

func factFilter(name string, since time.Time) []any {
	return []any{
		map[string]any{"term": map[string]any{"rule.id": FactRule}},
		map[string]any{"term": map[string]any{"data.fact": name}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
}

func (s *Source) Agents(ctx context.Context, since time.Time) ([]verdict.Agent, error) {
	agents, err := s.agentNames(ctx, s.index, "agent.id", "agent.name", []any{
		map[string]any{"term": map[string]any{"rule.id": FactRule}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	})
	if err != nil {
		return nil, err
	}
	return s.nameManager(ctx, agents), nil
}

func newest[T any](ctx context.Context, s *Source, name string, since time.Time) (map[string]T, error) {

	lists, err := latestFacts[T](ctx, s, name, since, 1)

	if err != nil {
		return nil, err
	}

	out := map[string]T{}

	for agentID, list := range lists {
		out[agentID] = list[0]
	}

	return out, nil
}

func (s *Source) SweepSnapshots(ctx context.Context, since time.Time) (map[string]fact.FileSweepSnapshot, error) {
	return newest[fact.FileSweepSnapshot](ctx, s, fact.FileSweepSnapshotFact, since)
}

func (s *Source) SpecialFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SpecialFile, error) {
	return passRecords[fact.SpecialFile](ctx, s, fact.SpecialFileFact, agentID, runID, since)
}

func (s *Source) UmaskSnapshots(ctx context.Context, since time.Time) (map[string]fact.UmaskSnapshot, error) {
	return newest[fact.UmaskSnapshot](ctx, s, fact.UmaskSnapshotFact, since)
}

func (s *Source) SudoersSnapshots(ctx context.Context, since time.Time) (map[string]fact.SudoersSnapshot, error) {
	return newest[fact.SudoersSnapshot](ctx, s, fact.SudoersSnapshotFact, since)
}

func (s *Source) SudoGrants(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SudoGrant, error) {
	return passRecords[fact.SudoGrant](ctx, s, fact.SudoGrantFact, agentID, runID, since)
}

func (s *Source) ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error) {
	return newest[fact.ConfigSnapshot](ctx, s, fact.ConfigSnapshotFact, since)
}

func (s *Source) ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error) {
	return passRecords[fact.ConfigFile](ctx, s, fact.ConfigFileFact, agentID, runID, since)
}

func (s *Source) PAMSnapshots(ctx context.Context, since time.Time) (map[string]fact.PAMSnapshot, error) {
	return newest[fact.PAMSnapshot](ctx, s, fact.PAMSnapshotFact, since)
}

func (s *Source) PAMRules(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PAMRule, error) {
	return passRecords[fact.PAMRule](ctx, s, fact.PAMRuleFact, agentID, runID, since)
}

func (s *Source) GroupSnapshots(ctx context.Context, since time.Time) (map[string]fact.GroupSnapshot, error) {

	newest, err := latestFacts[fact.GroupSnapshot](ctx, s, fact.GroupSnapshotFact, since, 1)

	if err != nil {
		return nil, err
	}

	snapshots := map[string]fact.GroupSnapshot{}

	for agentID, list := range newest {
		snapshots[agentID] = list[0]
	}

	return snapshots, nil
}

func (s *Source) GroupRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.GroupRecord, error) {
	return passRecords[fact.GroupRecord](ctx, s, fact.GroupRecordFact, agentID, runID, since)
}

func (s *Source) IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error) {
	return latestFacts[fact.IdentitySnapshot](ctx, s, fact.IdentitySnapshotFact, since, n)
}

func latestFacts[T any](ctx context.Context, s *Source, name string, since time.Time, n int) (map[string][]T, error) {
	all, err := batch.Once(ctx, &s.pass.plan, fmt.Sprint("latest|", name, "|", sinceKey(since), "|", n), func(ctx context.Context) (map[string][]T, error) {
		return readLatest[T](ctx, s, name, since, n)
	})
	return maps.Clone(all), err
}

func readLatest[T any](ctx context.Context, s *Source, name string, since time.Time, n int) (map[string][]T, error) {

	from := since
	var held map[string]heldPass
	if quietFacts[name] {
		from = since.Add(-reach)
		var err error
		if held, err = s.inForce(ctx, since); err != nil {
			return nil, fmt.Errorf("agent passes: %w", err)
		}
	}

	sub := map[string]any{"latest": map[string]any{
		"top_hits": map[string]any{"size": n, "sort": []any{map[string]any{"timestamp": "desc"}}},
	}}

	out := map[string][]T{}

	err := s.composite(ctx, factFilter(name, from), []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": "agent.id"}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Latest struct {
					Hits struct {
						Hits []hit `json:"hits"`
					} `json:"hits"`
				} `json:"latest"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			agentID := keyString(key, "a")
			for i, h := range c.Latest.Hits.Hits {
				var v T
				a, err := decodeAlert(h, &v)
				if err != nil {
					return err
				}
				if from.Before(since) {
					at, err := alertTime(a.Timestamp)
					if err != nil {
						return fmt.Errorf("alert %s: %w", h.ID, err)
					}

					run, _ := a.Data["run_id"].(string)
					p, named := held[agentID]
					named = named && i == 0 && run != "" && p.runs[name] == run
					if at.Before(since) && !named {
						break
					}

					if named {
						if s, ok := any(&v).(interface{ Seen(string) }); ok {
							s.Seen(p.ts)
						}
					}
				}
				s.want(name, agentID, v)
				out[agentID] = append(out[agentID], v)
			}
			return nil
		})

	return out, err
}

const reach = 4 * 24 * time.Hour

var quietFacts = map[string]bool{
	fact.IdentitySnapshotFact:   true,
	fact.GroupSnapshotFact:      true,
	fact.UmaskSnapshotFact:      true,
	fact.SudoersSnapshotFact:    true,
	fact.ConfigSnapshotFact:     true,
	fact.PAMSnapshotFact:        true,
	fact.ListeningSnapshotFact:  true,
	fact.ServiceLogSnapshotFact: true,
	fact.WazuhAgentConfigFact:   true,
	fact.ACLSnapshotFact:        true,
	fact.AuditWatchSnapshotFact: true,
	fact.FirewallSnapshotFact:   true,

	fact.BackupSnapshotFact:      true,
	fact.DeviceSecurityFact:      true,
	fact.KeySnapshotFact:         true,
	fact.MalwareProtectionFact:   true,
	fact.NeighbourSnapshotFact:   true,
	fact.PackageSelectionFact:    true,
	fact.SnapshotListFact:        true,
	fact.TimeSyncFact:            true,
	fact.TransactionSnapshotFact: true,
	fact.UnitSnapshotFact:        true,
	fact.UpdateStatusFact:        true,
	fact.VirtualizationFact:      true,
}

type heldPass struct {
	ts   string
	runs map[string]string
}

func (s *Source) inForce(ctx context.Context, since time.Time) (map[string]heldPass, error) {
	return batch.Once(ctx, &s.pass.plan, "inforce|"+sinceKey(since), func(ctx context.Context) (map[string]heldPass, error) {

		passes, err := readLatest[fact.AgentPass](ctx, s, fact.AgentPassFact, since, 1)
		if err != nil {
			return nil, err
		}

		out := map[string]heldPass{}
		for agentID, list := range passes {
			p := heldPass{ts: list[0].TS, runs: map[string]string{}}
			for _, entry := range list[0].InForce {
				if name, run, ok := strings.Cut(entry, ":"); ok {
					p.runs[name] = run
				}
			}
			out[agentID] = p
		}
		return out, nil
	})
}

func (s *Source) IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error) {
	return passRecords[fact.IdentityRecord](ctx, s, fact.IdentityRecordFact, agentID, runID, since)
}

func (s *Source) page(ctx context.Context, filter []any, fn func(hit) error) error {

	var after []any

	for {
		query := map[string]any{
			"size":  pageSize,
			"query": map[string]any{"bool": map[string]any{"filter": filter}},

			"sort": []any{map[string]any{"timestamp": "asc"}, map[string]any{"_id": "asc"}},
		}
		if after != nil {
			query["search_after"] = after
		}

		var resp struct {
			Hits struct {
				Hits []hit `json:"hits"`
			} `json:"hits"`
		}

		if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
			return err
		}

		for _, h := range resp.Hits.Hits {
			if err := fn(h); err != nil {
				return err
			}
		}

		if len(resp.Hits.Hits) < pageSize {
			return nil
		}

		after = resp.Hits.Hits[len(resp.Hits.Hits)-1].Sort
	}
}
