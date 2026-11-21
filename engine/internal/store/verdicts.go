package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var mapping = map[string]any{
	"settings": map[string]any{"index": map[string]any{"auto_expand_replicas": "0-1"}},
	"mappings": map[string]any{
		"dynamic": "strict",
		"properties": map[string]any{
			"oscompliance_verdict": kw(),
			"@timestamp":           date(),
			"scope":                kw(),
			"control":              kw(),
			"requirement":          kw(),
			"evidence":             kw(),
			"agent": map[string]any{"properties": map[string]any{
				"id":   kw(),
				"name": kw(),
			}},
			"status":                  kw(),
			"cause":                   kw(),
			"reason":                  map[string]any{"type": "keyword", "ignore_above": 2048},
			"reason_code":             kw(),
			"reason_args":             map[string]any{"type": "object", "enabled": false},
			"run_id":                  kw(),
			"window_start":            date(),
			"window_end":              date(),
			"engine_version":          kw(),
			"evidenced":               map[string]any{"type": "boolean"},
			"attested":                map[string]any{"type": "boolean"},
			"score":                   map[string]any{"type": "integer"},
			"coverage":                map[string]any{"type": "integer"},
			"applicable_requirements": map[string]any{"type": "integer"},
			"measured_requirements":   map[string]any{"type": "integer"},
			"unmeasured_requirements": kw(),
			"maturity": map[string]any{"properties": map[string]any{
				"accredited":        integer(),
				"working_days":      integer(),
				"period_days":       integer(),
				"assessed":          integer(),
				"target":            integer(),
				"assessed_by":       kw(),
				"assessed_at":       date(),
				"references":        map[string]any{"type": "keyword", "ignore_above": 2048},
				"note":              map[string]any{"type": "keyword", "ignore_above": 2048},
				"incoherent":        map[string]any{"type": "boolean"},
				"machines":          integer(),
				"applicable":        integer(),
				"unmeasured":        integer(),
				"unassessed":        integer(),
				"below_target":      kw(),
				"accredited_counts": integer(),
				"assessed_counts":   integer(),
				"global_accredited": integer(),
				"global_assessed":   integer(),
			}},
			"tally": map[string]any{"properties": map[string]any{
				"met":     integer(),
				"total":   integer(),
				"percent": integer(),
				"level":   integer(),
			}},
		},
	},
}

func kw() map[string]any      { return map[string]any{"type": "keyword"} }
func integer() map[string]any { return map[string]any{"type": "integer"} }
func date() map[string]any    { return map[string]any{"type": "date"} }

type Verdicts struct {
	client  *indexer.Client
	index   string
	pending []verdict.Verdict
}

const bulkSize = 500

func NewVerdicts(ctx context.Context, client *indexer.Client, index string) (*Verdicts, error) {

	if err := client.EnsureIndex(ctx, index, mapping); err != nil {
		return nil, err
	}
	if err := client.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_mapping", mapping["mappings"], nil); err != nil {
		return nil, err
	}

	return &Verdicts{client: client, index: index}, nil
}

func (s *Verdicts) Write(ctx context.Context, v verdict.Verdict) error {

	s.pending = append(s.pending, v)
	if len(s.pending) < bulkSize {
		return nil
	}

	return s.Flush(ctx)
}

func (s *Verdicts) Flush(ctx context.Context) error {

	if len(s.pending) == 0 {
		return nil
	}

	var body bytes.Buffer
	for _, v := range s.pending {
		action, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": s.index, "_id": DocumentID(v)}})
		doc, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body.Write(action)
		body.WriteByte('\n')
		body.Write(doc)
		body.WriteByte('\n')
	}

	s.pending = s.pending[:0]
	return s.client.Bulk(ctx, body.Bytes())
}

func DocumentID(v verdict.Verdict) string {

	day := v.Timestamp
	if len(day) >= 10 {
		day = day[:10]
	}

	switch v.Scope {
	case verdict.ScopeRequirement:
		return strings.Join([]string{v.Agent.ID, v.Control, v.Requirement, day}, "/")
	case verdict.ScopeControl:
		return strings.Join([]string{v.Agent.ID, v.Control, day}, "/")
	case verdict.ScopeOrganization:
		return strings.Join([]string{verdict.ScopeOrganization, v.Control, day}, "/")
	}

	pass := v.RunID
	if pass == "" {
		pass = "none"
	}

	return strings.Join([]string{v.Agent.ID, v.Control, v.Evidence, pass}, "/")
}

func (s *Verdicts) WorkingDays(ctx context.Context, control string, now time.Time, days int) (map[string]int, error) {

	// One control verdict is kept per machine and day, so each document counted is a day on
	// which the control had at least one requirement met with evidence.

	today := now.UTC().Truncate(24 * time.Hour)
	out := map[string]int{}
	var after any

	for {
		composite := map[string]any{
			"size":    pageSize,
			"sources": []any{map[string]any{"agent": map[string]any{"terms": map[string]any{"field": "agent.id"}}}},
		}
		if after != nil {
			composite["after"] = after
		}
		query := map[string]any{
			"size": 0,
			"query": map[string]any{"bool": map[string]any{"filter": []any{
				map[string]any{"term": map[string]any{"scope": verdict.ScopeControl}},
				map[string]any{"term": map[string]any{"control": control}},
				map[string]any{"range": map[string]any{"@timestamp": map[string]any{
					"gte": today.AddDate(0, 0, -days).Format(time.RFC3339),
					"lt":  today.Format(time.RFC3339),
				}}},
				map[string]any{"range": map[string]any{"measured_requirements": map[string]any{"gte": 1}}},
				map[string]any{"range": map[string]any{"score": map[string]any{"gte": 1}}},
			}}},
			"aggs": map[string]any{"agents": map[string]any{"composite": composite}},
		}

		var resp struct {
			Aggregations struct {
				Agents struct {
					AfterKey any `json:"after_key"`
					Buckets  []struct {
						Key      struct{ Agent string } `json:"key"`
						DocCount int                    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"agents"`
			} `json:"aggregations"`
		}
		if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
			return nil, err
		}

		buckets := resp.Aggregations.Agents.Buckets
		for _, b := range buckets {
			out[b.Key.Agent] = b.DocCount
		}
		if len(buckets) < pageSize {
			return out, nil
		}
		after = resp.Aggregations.Agents.AfterKey
	}
}

func (s *Verdicts) ImplementationDegrees(ctx context.Context, since time.Time) (map[string]verdict.Degree, error) {

	out := map[string]verdict.Degree{}
	var after any

	for {
		composite := map[string]any{
			"size":    pageSize,
			"sources": []any{map[string]any{"agent": map[string]any{"terms": map[string]any{"field": "agent.id"}}}},
		}
		if after != nil {
			composite["after"] = after
		}
		query := map[string]any{
			"size":  0,
			"query": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
			"aggs": map[string]any{"agents": map[string]any{
				"composite": composite,
				"aggs": map[string]any{
					"controls": map[string]any{
						"filter": map[string]any{"bool": map[string]any{
							"filter":   []any{map[string]any{"term": map[string]any{"scope": verdict.ScopeControl}}},
							"must_not": []any{map[string]any{"term": map[string]any{"status": verdict.NotApplicable}}},
						}},
						"aggs": map[string]any{"control": map[string]any{
							"terms": map[string]any{"field": "control", "size": 100},
							"aggs": map[string]any{"latest": map[string]any{"top_hits": map[string]any{
								"size": 1, "sort": []any{map[string]any{"@timestamp": "desc"}},
								"_source": []string{"score", "measured_requirements"},
							}}},
						}},
					},
					"unconfigured": map[string]any{
						"filter": map[string]any{"bool": map[string]any{"filter": []any{
							map[string]any{"term": map[string]any{"scope": verdict.ScopeEvidence}},
							map[string]any{"term": map[string]any{"cause": verdict.CauseConfiguration}},
						}}},
						"aggs": map[string]any{"control": map[string]any{"terms": map[string]any{"field": "control", "size": 100}}},
					},
				},
			}},
		}

		var resp struct {
			Aggregations struct {
				Agents struct {
					AfterKey any            `json:"after_key"`
					Buckets  []degreeBucket `json:"buckets"`
				} `json:"agents"`
			} `json:"aggregations"`
		}
		if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
			return nil, err
		}

		buckets := resp.Aggregations.Agents.Buckets
		for _, b := range buckets {
			out[b.Key.Agent] = b.degree()
		}
		if len(buckets) < pageSize {
			return out, nil
		}
		after = resp.Aggregations.Agents.AfterKey
	}
}

type degreeBucket struct {
	Key      struct{ Agent string } `json:"key"`
	Controls struct {
		Control struct {
			Buckets []struct {
				Latest struct {
					Hits struct {
						Hits []struct {
							Source struct {
								Score    *int `json:"score"`
								Measured *int `json:"measured_requirements"`
							} `json:"_source"`
						} `json:"hits"`
					} `json:"hits"`
				} `json:"latest"`
			} `json:"buckets"`
		} `json:"control"`
	} `json:"controls"`
	Unconfigured struct {
		Control struct {
			Buckets []struct {
				Key string `json:"key"`
			} `json:"buckets"`
		} `json:"control"`
	} `json:"unconfigured"`
}

func (b degreeBucket) degree() verdict.Degree {

	d := verdict.Degree{}
	sum := 0
	for _, c := range b.Controls.Control.Buckets {
		if len(c.Latest.Hits.Hits) == 0 {
			continue
		}
		src := c.Latest.Hits.Hits[0].Source
		d.Controls++
		if src.Measured != nil && *src.Measured > 0 {
			d.Measured++
		}
		if src.Score != nil {
			sum += *src.Score
		}
	}
	if d.Controls > 0 {
		d.Score = (2*sum + d.Controls) / (2 * d.Controls)
	}
	for _, c := range b.Unconfigured.Control.Buckets {
		d.Unconfigured = append(d.Unconfigured, c.Key)
	}
	return d
}
