package scope

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Partition struct {
	systems   []params.System
	reporting map[string]source.Reporting
	byGroup   bool
}

func PartitionOf(systems []params.System, reporting map[string]source.Reporting) Partition {
	p := Partition{systems: systems, reporting: reporting}
	for _, s := range systems {
		p.byGroup = p.byGroup || s.Config.ScopesByGroup()
	}
	return p
}

func (p Partition) Owner(agentID string) (string, []string) {

	// The systems other than the default claim their machines first and may not share one;
	// the default takes the rest of its scope.
	groups := p.reporting[agentID].Groups
	var claims []string
	for _, s := range p.systems[1:] {
		if s.Config.Evaluates(agentID, groups) {
			claims = append(claims, s.ID)
		}
	}

	switch {
	case len(claims) == 1:
		return claims[0], nil
	case len(claims) > 1:
		return "", claims
	case p.systems[0].Config.Evaluates(agentID, groups):
		return p.systems[0].ID, nil
	}
	return "", nil
}

func (p Partition) List(agentID, controlID, paramID string) ([]string, error) {
	// The Wazuh group configuration of a machine follows the parameters of its system; a
	// machine of no system, or of two, takes those of the default system.
	config := p.systems[0].Config
	if owner, _ := p.Owner(agentID); owner != "" {
		config = p.Machines(owner).system.Config
	}
	return config.List(agentID, controlID, paramID)
}

func (p Partition) unresolved(agentID string) string {
	if agentID == source.ManagerID {
		return ""
	}
	// Judging an agent whose groups are unknown could silently ignore its exclusion or put
	// it in the wrong system.
	if _, known := p.reporting[agentID]; !known && p.byGroup {
		return "groups unknown"
	}
	if _, shared := p.Owner(agentID); len(shared) > 0 {
		return "in the scope of systems " + strings.Join(shared, ", ")
	}
	return ""
}

func (p Partition) Machines(systemID string) Machines {
	for _, s := range p.systems {
		if s.ID == systemID {
			return Machines{partition: p, system: s}
		}
	}
	return Machines{partition: p, system: params.System{ID: systemID, Config: &params.Config{}}}
}

type Machines struct {
	partition Partition
	system    params.System
}

func MachinesOf(config *params.Config, reporting map[string]source.Reporting) Machines {
	system := params.System{ID: verdict.DefaultSystem, Config: config}
	return PartitionOf([]params.System{system}, reporting).Machines(system.ID)
}

func (m Machines) Evaluable(agentID string) bool {
	if m.Unresolved(agentID) != "" {
		return false
	}
	// The manager carries the measures every system relies on, so each system judges it.
	if agentID == source.ManagerID {
		return true
	}
	owner, _ := m.partition.Owner(agentID)
	return owner == m.system.ID
}

func (m Machines) Unresolved(agentID string) string {
	return m.partition.unresolved(agentID)
}

func (m Machines) Excluded(controlID, agentID string) bool {
	return m.system.Config.Excludes(controlID, m.partition.reporting[agentID].Groups)
}

type Fleet struct {
	ids map[string]string
}

func FleetOf(reporting map[string]source.Reporting) Fleet {
	f := Fleet{ids: map[string]string{}}
	for id, r := range reporting {
		f.ids[strings.ToLower(r.Name)] = id
	}
	return f
}

func (f Fleet) Has(name string) bool {
	_, ok := f.ids[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func (f Fleet) ID(name string) (string, bool) {
	id, ok := f.ids[strings.ToLower(strings.TrimSpace(name))]
	return id, ok
}

func (f Fleet) IDs() []string {
	out := []string{source.ManagerID}
	for _, id := range f.ids {
		if id != source.ManagerID {
			out = append(out, id)
		}
	}
	return out
}

func (f Fleet) Any(test func(id string) bool) bool {
	for _, id := range f.IDs() {
		if test(id) {
			return true
		}
	}
	return false
}

func Carrier(agentID string) bool { return agentID == source.ManagerID }
