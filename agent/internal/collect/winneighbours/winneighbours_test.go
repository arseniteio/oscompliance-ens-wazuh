package winneighbours

import (
	"errors"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

const table = `{"neighbours":[
{"ip":"10.50.0.9","mac":"AA-BB-CC-DD-EE-01","interface":"Ethernet","state":"Stale"},
{"ip":"10.50.0.1","mac":"AA-BB-CC-DD-EE-FF","interface":"Ethernet","state":"Reachable"},
{"ip":"10.50.0.1","mac":"AA-BB-CC-DD-EE-FF","interface":"Ethernet","state":"Reachable"},
{"ip":"10.50.0.2","mac":"00-00-00-00-00-00","interface":"Ethernet","state":"Unreachable"},
{"ip":"10.50.0.3","mac":"AA-BB-CC-DD-EE-03","interface":"Ethernet","state":"Incomplete"},
{"ip":"10.50.0.255","mac":"FF-FF-FF-FF-FF-FF","interface":"Ethernet","state":"Permanent"},
{"ip":"224.0.0.22","mac":"01-00-5E-00-00-16","interface":"Ethernet","state":"Permanent"},
{"ip":"10.50.0.4","mac":"52-54-00-00-00-00","interface":"Ethernet","state":"Stale"},
{"ip":"10.50.0.5","mac":"","interface":"Ethernet","state":"Stale"}]}`

func TestCollect(t *testing.T) {

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(table)) })

	got := facts[0]["neighbours"].([]any)
	if facts[0]["status"] != "read" || len(got) != 2 {
		t.Fatalf("snapshot: %v", facts[0])
	}
	first := got[0].(map[string]any)
	if first["ip"] != "10.50.0.1" || first["mac"] != "aa:bb:cc:dd:ee:ff" || first["interface"] != "Ethernet" {
		t.Errorf("first neighbour: %v", got)
	}
}

func TestCollectUnreadable(t *testing.T) {

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Failing(errors.New("access denied"))) })

	if facts[0]["status"] != "unreadable" || facts[0]["error"] != "access denied" {
		t.Errorf("snapshot: %v", facts[0])
	}
}
