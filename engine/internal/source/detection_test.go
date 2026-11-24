package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
)

func TestLocationDetectionsNameWindowsChannels(t *testing.T) {

	security := time.Date(2026, 11, 23, 19, 0, 0, 0, time.UTC)
	system := security.Add(-time.Hour)
	authLog := security.Add(-2 * time.Hour)
	bucket := func(agent, location string, channel any, at time.Time) map[string]any {
		return map[string]any{"key": map[string]any{"a": agent, "l": location, "c": channel}, "doc_count": 1, "last": map[string]any{"value": at.UnixMilli()}}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var query map[string]any
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			t.Error(err)
		}
		var buckets []any
		if !strings.Contains(mustJSON(t, query), `"after"`) {
			buckets = []any{
				bucket("045", eventChannel, "Security", security),
				bucket("045", eventChannel, "System", system),
				bucket("017", "/var/log/auth.log", nil, authLog),
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"aggregations": map[string]any{"c": map[string]any{"buckets": buckets}}})
	}))
	t.Cleanup(server.Close)
	client, err := indexer.New(server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	got, err := New(client, "alerts", "monitoring", "states").LocationDetections(context.Background(), security.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		agent, location string
		want            time.Time
	}{{"045", "Security", security}, {"045", "System", system}, {"017", "/var/log/auth.log", authLog}} {
		if !got[c.agent][c.location].Equal(c.want) {
			t.Errorf("%s %s: got %v, want %v", c.agent, c.location, got[c.agent][c.location], c.want)
		}
	}
	if _, ok := got["045"][eventChannel]; ok {
		t.Errorf("a Windows channel kept the EventChannel location: %v", got["045"])
	}
}
