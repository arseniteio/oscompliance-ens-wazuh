package scope

import (
	"encoding/json"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
)

func TestFleet(t *testing.T) {
	f := FleetOf(map[string]source.Reporting{"001": {Name: "Web01"}, "002": {Name: "db01"}})
	if !f.Has("web01") || f.Has("mail01") {
		t.Error("has")
	}
	if id, ok := f.ID("DB01"); !ok || id != "002" {
		t.Errorf("id %s", id)
	}
	if len(f.IDs()) != 3 || !f.Any(func(id string) bool { return id == source.ManagerID }) {
		t.Errorf("ids %v", f.IDs())
	}
	if !Carrier("000") || Carrier("001") {
		t.Error("carrier")
	}
}

func TestMachinesWithUnknownGroups(t *testing.T) {
	reporting := map[string]source.Reporting{"001": {Groups: []string{"ens", "ens-excluir-mp.com.4"}}}

	tests := []struct {
		name          string
		mode          string
		controlGroups bool
		unresolved    bool
	}{
		{name: "every machine, no exclusions", mode: "all"},
		{name: "every machine with exclusions", mode: "all", controlGroups: true, unresolved: true},
		{name: "scope by group", mode: "group", unresolved: true},
		{name: "scope by agent, no exclusions", mode: "agent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &params.Config{}
			config.Scope.Mode, config.Scope.ControlGroups = tt.mode, tt.controlGroups
			config.Scope.GroupIDs, config.Scope.AgentIDs = []string{"ens"}, []string{"001", "002"}
			m := MachinesOf(config, reporting)

			if got := m.Unresolved("002") != ""; got != tt.unresolved {
				t.Errorf("unresolved = %v, want %v", got, tt.unresolved)
			}
			if tt.unresolved && m.Evaluable("002") {
				t.Error("a machine with unknown groups is evaluable")
			}
			if m.Unresolved("001") != "" || m.Unresolved(source.ManagerID) != "" {
				t.Error("a machine with known groups, or the manager, is unresolved")
			}
		})
	}
}

func TestPartitionGivesEachMachineOneSystem(t *testing.T) {

	config := func(mode string, groups, agents []string) *params.Config {
		c := &params.Config{}
		c.Scope.Mode, c.Scope.GroupIDs, c.Scope.AgentIDs = mode, groups, agents
		return c
	}
	systems := []params.System{
		{ID: "default", Config: config("all", nil, nil)},
		{ID: "lab", Config: config("agent", nil, []string{"003", "004"})},
		{ID: "pilot", Config: config("group", []string{"pilot"}, nil)},
	}
	reporting := map[string]source.Reporting{
		"001": {Groups: []string{"ens"}},
		"002": {Groups: []string{"ens", "pilot"}},
		"003": {Groups: []string{"ens"}},
		"004": {Groups: []string{"pilot"}},
	}
	p := PartitionOf(systems, reporting)

	tests := []struct {
		agent, judgedBy, unresolved string
	}{
		{agent: "001", judgedBy: "default"},
		{agent: "002", judgedBy: "pilot"},
		{agent: "003", judgedBy: "lab"},
		{agent: "004", unresolved: "in the scope of systems lab, pilot"},
		{agent: "005", unresolved: "groups unknown"},
	}

	for _, tt := range tests {
		for _, s := range systems {
			m := p.Machines(s.ID)
			if got := m.Evaluable(tt.agent); got != (s.ID == tt.judgedBy) {
				t.Errorf("agent %s evaluable in %s = %v", tt.agent, s.ID, got)
			}
			if got := m.Unresolved(tt.agent); got != tt.unresolved {
				t.Errorf("agent %s unresolved in %s = %q, want %q", tt.agent, s.ID, got, tt.unresolved)
			}
		}
	}

	for _, s := range systems {
		if !p.Machines(s.ID).Evaluable(source.ManagerID) {
			t.Errorf("the manager is not judged in %s", s.ID)
		}
	}
}

func TestPartitionReadsTheParametersOfTheMachineSystem(t *testing.T) {

	config := func(mode string, groups []string, value string) *params.Config {
		var c params.Config
		doc := `{"scope": {"mode": "` + mode + `"}, "controls": [{"controlId": "op.acc.3", "parameters": [{"id": "P-03", "value": ["` + value + `"]}]}]}`
		if err := json.Unmarshal([]byte(doc), &c); err != nil {
			t.Fatal(err)
		}
		c.Scope.GroupIDs = groups
		return &c
	}
	p := PartitionOf([]params.System{
		{ID: "default", Config: config("all", nil, "production")},
		{ID: "pilot", Config: config("group", []string{"pilot"}, "pilot")},
	}, map[string]source.Reporting{"001": {Groups: []string{"ens"}}, "002": {Groups: []string{"pilot"}}})

	for agent, want := range map[string]string{"001": "production", "002": "pilot", "009": "production"} {
		rows, err := p.List(agent, "op.acc.3", "P-03")
		if err != nil || len(rows) != 1 || rows[0] != want {
			t.Errorf("agent %s: %v %v, want %s", agent, rows, err, want)
		}
	}
}
