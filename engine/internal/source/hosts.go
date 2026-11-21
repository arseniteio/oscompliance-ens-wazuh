package source

import (
	"context"
	"encoding/json"
	"log/slog"
)

type HostInventory struct {
	OS           string
	Version      string
	Platform     string
	Hostname     string
	Architecture string
	Packages     []string
}

func (s *Source) HostInventories(ctx context.Context, exact, prefixes []string) (map[string]*HostInventory, error) {

	out := map[string]*HostInventory{}
	of := func(id string) *HostInventory {
		if out[id] == nil {
			out[id] = &HostInventory{}
		}
		return out[id]
	}

	fields := []string{"host.os.name", "host.os.version", "host.os.platform", "host.hostname", "host.architecture"}
	err := s.firstDocs(ctx, "system", fields, func(id string, src json.RawMessage) error {
		var d struct {
			Host struct {
				Hostname     string `json:"hostname"`
				Architecture string `json:"architecture"`
				OS           struct {
					Name     string `json:"name"`
					Version  string `json:"version"`
					Platform string `json:"platform"`
				} `json:"os"`
			} `json:"host"`
		}
		if err := json.Unmarshal(src, &d); err != nil {
			return err
		}
		h := of(id)
		h.OS, h.Version, h.Platform = d.Host.OS.Name, d.Host.OS.Version, d.Host.OS.Platform
		h.Hostname, h.Architecture = d.Host.Hostname, d.Host.Architecture
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(exact)+len(prefixes) > 0 {
		should := []any{}
		if len(exact) > 0 {
			should = append(should, map[string]any{"terms": map[string]any{"package.name": exact}})
		}
		for _, p := range prefixes {
			should = append(should, map[string]any{"prefix": map[string]any{"package.name": p}})
		}
		filter := []any{map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}}
		err = s.compositeIn(ctx, s.inventoryIndex("packages"), filter, []any{terms("a", "agent.id"), terms("p", "package.name")}, nil, func(key map[string]any, _ json.RawMessage) error {
			if id, name := keyString(key, "a"), keyString(key, "p"); id != "" && name != "" {
				of(id).Packages = append(of(id).Packages, name)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if s.managerInventory.read != nil {
		inv, err := s.managerInventory.get(ctx)
		switch {
		case err != nil:
			slog.Warn("manager inventory", "error", err)
		case inv != nil && inv.System != nil:
			h := of(ManagerID)
			h.OS, h.Version, h.Architecture = inv.System.OS, inv.System.Version, inv.System.Architecture
		}
	}

	return out, nil
}
