package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type Detection struct {
	Last  time.Time
	Count int
}

func (s *Source) Detections(ctx context.Context, since time.Time) (map[string]Detection, error) {

	filter := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"term": map[string]any{"rule.groups": "oscompliance"}}}}},
	}
	sub := map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}}

	out := map[string]Detection{}
	err := s.composite(ctx, filter, []any{terms("a", "agent.id")}, sub, func(key map[string]any, b json.RawMessage) error {
		d, err := detectionOf(b)
		if id := keyString(key, "a"); err == nil && id != "" {
			out[id] = d
		}
		return err
	})
	return out, err
}

func (s *Source) GroupDetections(ctx context.Context, groups []string, since time.Time) (Detection, error) {

	names := make([]any, len(groups))
	for i, g := range groups {
		names[i] = g
	}
	query := map[string]any{
		"size": 0, "track_total_hits": true,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"rule.groups": names}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		}}},
		"aggs": map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}},
	}
	var resp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations json.RawMessage `json:"aggregations"`
	}
	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return Detection{}, err
	}
	d, err := detectionOf(resp.Aggregations)
	d.Count = resp.Hits.Total.Value
	return d, err
}

func detectionOf(b json.RawMessage) (Detection, error) {
	var c struct {
		Count int `json:"doc_count"`
		Last  struct {
			Value *float64 `json:"value"`
		} `json:"last"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Detection{}, err
	}
	d := Detection{Count: c.Count}
	if c.Last.Value != nil {
		d.Last = time.UnixMilli(int64(*c.Last.Value)).UTC()
	}
	return d, nil
}

// Wazuh records every Windows event log as location "EventChannel"; the
// channel, which is what the agent's localfile names, is in data.win.system.channel.
const eventChannel = "EventChannel"

func (s *Source) LocationDetections(ctx context.Context, since time.Time) (map[string]map[string]time.Time, error) {

	filter := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}}}
	sub := map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}}
	sources := []any{terms("a", "agent.id"), terms("l", "location"), terms("c", "data.win.system.channel")}

	out := map[string]map[string]time.Time{}
	err := s.composite(ctx, filter, sources, sub, func(key map[string]any, b json.RawMessage) error {
		d, err := detectionOf(b)
		id, location := keyString(key, "a"), keyString(key, "l")
		if channel := keyString(key, "c"); location == eventChannel && channel != "" {
			location = channel
		}
		if err != nil || id == "" || location == "" {
			return err
		}
		if out[id] == nil {
			out[id] = map[string]time.Time{}
		}
		if d.Last.After(out[id][location]) {
			out[id][location] = d.Last
		}
		return nil
	})
	return out, err
}

func (s *Source) PackageCounts(ctx context.Context) (map[string]int, error) {

	out := map[string]int{}
	if err := s.inventoryCount(ctx, "packages", nil, nil, func(id string, _ map[string]any, n int) { out[id] += n }); err != nil {
		return nil, err
	}

	if s.managerInventory.read != nil {
		inv, err := s.managerInventory.get(ctx)
		if err != nil {
			return nil, fmt.Errorf("manager inventory: %w", err)
		}
		for _, n := range inv.Packages {
			out[ManagerID] += n
		}
	}
	return out, nil
}

func (s *Source) RuleHours(ctx context.Context, rules []string, since time.Time) (map[string][]time.Time, error) {

	out := map[string][]time.Time{}
	if len(rules) == 0 {
		return out, nil
	}
	ids := make([]any, len(rules))
	for i, r := range rules {
		ids[i] = r
	}
	filter := []any{
		map[string]any{"terms": map[string]any{"rule.id": ids}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), map[string]any{"h": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "fixed_interval": "1h"}}}}
	err := s.composite(ctx, filter, sources, nil, func(key map[string]any, _ json.RawMessage) error {
		id := keyString(key, "a")
		if ms, ok := key["h"].(float64); ok && id != "" {
			out[id] = append(out[id], time.UnixMilli(int64(ms)).UTC())
		}
		return nil
	})
	return out, err
}
