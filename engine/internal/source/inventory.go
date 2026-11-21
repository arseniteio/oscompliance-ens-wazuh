package source

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"time"
)

type Inventory struct {
	System    *System
	Hardware  *Hardware
	Packages  map[string]int
	Vendors   []string
	Addresses []string
	Listening int
	Processes int
}

type System struct {
	OS           string
	Version      string
	Kernel       string
	Architecture string
}

type Hardware struct {
	Cores    int
	MemoryMB int
}

func (s *Source) Inventories(ctx context.Context) (map[string]*Inventory, error) {

	out := map[string]*Inventory{}
	of := func(id string) *Inventory {
		if out[id] == nil {
			out[id] = &Inventory{Packages: map[string]int{}}
		}
		return out[id]
	}

	steps := []struct {
		name string
		do   func() error
	}{
		{"system", func() error {
			return s.firstDocs(ctx, "system", []string{"host.os.name", "host.os.version", "host.os.kernel.release", "host.architecture"}, func(id string, src json.RawMessage) error {
				var d struct {
					Host struct {
						Architecture string `json:"architecture"`
						OS           struct {
							Name    string `json:"name"`
							Version string `json:"version"`
							Kernel  struct {
								Release string `json:"release"`
							} `json:"kernel"`
						} `json:"os"`
					} `json:"host"`
				}
				if err := json.Unmarshal(src, &d); err != nil {
					return err
				}
				of(id).System = &System{OS: d.Host.OS.Name, Version: d.Host.OS.Version, Kernel: d.Host.OS.Kernel.Release, Architecture: d.Host.Architecture}
				return nil
			})
		}},
		{"hardware", func() error {
			return s.firstDocs(ctx, "hardware", []string{"host.cpu.cores", "host.memory.total"}, func(id string, src json.RawMessage) error {
				var d struct {
					Host struct {
						CPU struct {
							Cores int `json:"cores"`
						} `json:"cpu"`
						Memory struct {
							Total int64 `json:"total"`
						} `json:"memory"`
					} `json:"host"`
				}
				if err := json.Unmarshal(src, &d); err != nil {
					return err
				}
				of(id).Hardware = &Hardware{Cores: d.Host.CPU.Cores, MemoryMB: int(d.Host.Memory.Total / (1 << 20))}
				return nil
			})
		}},
		{"packages", func() error {
			return s.inventoryCount(ctx, "packages", nil, terms("t", "package.type"), func(id string, key map[string]any, n int) {
				of(id).Packages[keyString(key, "t")] += n
			})
		}},
		{"networks", func() error {
			return s.inventoryCount(ctx, "networks", nil, terms("i", "network.ip"), func(id string, key map[string]any, n int) {
				if ip := keyString(key, "i"); ip != "" {
					of(id).Addresses = append(of(id).Addresses, ip)
				}
			})
		}},
		{"ports", func() error {
			listening := []any{map[string]any{"term": map[string]any{"interface.state": "listening"}}}
			return s.inventoryCount(ctx, "ports", listening, nil, func(id string, _ map[string]any, n int) { of(id).Listening += n })
		}},
		{"processes", func() error {
			return s.inventoryCount(ctx, "processes", nil, nil, func(id string, _ map[string]any, n int) { of(id).Processes += n })
		}},
	}

	for _, step := range steps {
		if err := step.do(); err != nil {
			return nil, fmt.Errorf("inventory %s: %w", step.name, err)
		}
	}

	if s.managerInventory.read != nil {
		inv, err := s.managerInventory.get(ctx)
		if err != nil {
			slog.Warn("manager inventory", "error", err)
		} else if inv != nil {
			out[ManagerID] = inv
		}
	}

	return out, nil
}

func (s *Source) UseManagerInventory(read func(ctx context.Context) (*Inventory, error)) {
	s.managerInventory.read = read
}

func (s *Source) inventoryIndex(kind string) string {
	return s.states + "inventory-" + kind + "-*"
}

func (s *Source) firstDocs(ctx context.Context, kind string, fields []string, fn func(id string, src json.RawMessage) error) error {

	sub := map[string]any{"doc": map[string]any{"top_hits": map[string]any{"size": 1, "_source": fields}}}

	return s.compositeIn(ctx, s.inventoryIndex(kind), []any{}, []any{terms("a", "agent.id")}, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Doc struct {
				Hits struct {
					Hits []struct {
						Source json.RawMessage `json:"_source"`
					} `json:"hits"`
				} `json:"hits"`
			} `json:"doc"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id := keyString(key, "a")
		if id == "" || len(c.Doc.Hits.Hits) == 0 {
			return nil
		}
		return fn(id, c.Doc.Hits.Hits[0].Source)
	})
}

func (s *Source) inventoryCount(ctx context.Context, kind string, filter []any, by any, fn func(id string, key map[string]any, n int)) error {

	if filter == nil {
		filter = []any{}
	}
	sources := []any{terms("a", "agent.id")}
	if by != nil {
		sources = append(sources, by)
	}

	return s.compositeIn(ctx, s.inventoryIndex(kind), filter, sources, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		if id := keyString(key, "a"); id != "" {
			fn(id, key, c.Count)
		}
		return nil
	})
}

type Reporting struct {
	Name          string
	Status        string
	LastKeepAlive time.Time
	IP            string
	Groups        []string
}

func (s *Source) Reporting(ctx context.Context, since time.Time) (map[string]Reporting, error) {

	fleet, err := s.FleetReporting(ctx, since)
	maps.DeleteFunc(fleet, func(id string, _ Reporting) bool { return !s.counts(ctx, id) })
	return fleet, err
}

func (s *Source) FleetReporting(ctx context.Context, since time.Time) (map[string]Reporting, error) {

	filter := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}}}
	sub := map[string]any{"last": map[string]any{"top_hits": map[string]any{
		"size": 1, "sort": []any{map[string]any{"timestamp": "desc"}}, "_source": []string{"name", "status", "lastKeepAlive", "ip", "group"},
	}}}

	out := map[string]Reporting{}

	err := s.compositeIn(ctx, s.monitoring, filter, []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": "id"}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Last struct {
					Hits struct {
						Hits []struct {
							Source struct {
								Name          string   `json:"name"`
								Status        string   `json:"status"`
								LastKeepAlive string   `json:"lastKeepAlive"`
								IP            string   `json:"ip"`
								Group         []string `json:"group"`
							} `json:"_source"`
						} `json:"hits"`
					} `json:"hits"`
				} `json:"last"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			if len(c.Last.Hits.Hits) == 0 {
				return nil
			}
			h := c.Last.Hits.Hits[0].Source
			r := Reporting{Name: h.Name, Status: h.Status, IP: h.IP, Groups: h.Group}
			if t, err := time.Parse(time.RFC3339, h.LastKeepAlive); err == nil {
				r.LastKeepAlive = t
			}
			out[keyString(key, "a")] = r
			return nil
		})

	return out, err
}

var packageChangeRules = []any{"2902", "2903", "2932", "2933", "2934"}

func (s *Source) PackageChanges(ctx context.Context, since time.Time) (map[string]map[time.Time]int, error) {

	filter := []any{
		map[string]any{"terms": map[string]any{"rule.id": packageChangeRules}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), map[string]any{"d": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "calendar_interval": "1d"}}}}

	out := map[string]map[time.Time]int{}

	err := s.composite(ctx, filter, sources, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		ms, ok := key["d"].(float64)
		id := keyString(key, "a")
		if !ok || id == "" {
			return nil
		}
		if out[id] == nil {
			out[id] = map[time.Time]int{}
		}
		out[id][time.UnixMilli(int64(ms)).UTC()] += c.Count
		return nil
	})

	return out, err
}

var installRules = []any{"2901"}

func (s *Source) NewPackages(ctx context.Context, since time.Time) (map[string][]string, error) {

	filter := []any{
		map[string]any{"terms": map[string]any{"rule.id": installRules}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	out := map[string][]string{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("p", "data.package")}, nil, func(key map[string]any, _ json.RawMessage) error {
		if id, p := keyString(key, "a"), keyString(key, "p"); id != "" && p != "" {
			out[id] = append(out[id], p)
		}
		return nil
	})

	return out, err
}

type AlertCount struct {
	Rule     string
	Count    int
	Examples []string
}

func (s *Source) RuleCounts(ctx context.Context, rules []string, field string, since time.Time) (map[string][]AlertCount, error) {

	ids := make([]any, len(rules))
	for i, r := range rules {
		ids[i] = r
	}
	filter := []any{
		map[string]any{"terms": map[string]any{"rule.id": ids}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sub := map[string]any{"x": map[string]any{"terms": map[string]any{"field": field, "size": 5}}}

	out := map[string][]AlertCount{}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("r", "rule.id")}, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
			X     struct {
				Buckets []struct {
					Key any `json:"key"`
				} `json:"buckets"`
			} `json:"x"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id := keyString(key, "a")
		if id == "" {
			return nil
		}
		a := AlertCount{Rule: keyString(key, "r"), Count: c.Count}
		for _, x := range c.X.Buckets {
			a.Examples = append(a.Examples, fmt.Sprint(x.Key))
		}
		out[id] = append(out[id], a)
		return nil
	})

	return out, err
}
