package scope

import (
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

			if got := m.Unresolved("002"); got != tt.unresolved {
				t.Errorf("unresolved = %v, want %v", got, tt.unresolved)
			}
			if tt.unresolved && m.Evaluable("002") {
				t.Error("a machine with unknown groups is evaluable")
			}
			if m.Unresolved("001") || m.Unresolved(source.ManagerID) {
				t.Error("a machine with known groups, or the manager, is unresolved")
			}
		})
	}
}
