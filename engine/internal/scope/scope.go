package scope

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
)

type Machines struct {
	config    *params.Config
	reporting map[string]source.Reporting
}

func MachinesOf(config *params.Config, reporting map[string]source.Reporting) Machines {
	return Machines{config: config, reporting: reporting}
}

func (m Machines) Evaluable(agentID string) bool {
	return !m.Unresolved(agentID) && m.config.Evaluates(agentID, m.reporting[agentID].Groups)
}

func (m Machines) Unresolved(agentID string) bool {
	// Judging an agent whose groups are unknown could silently ignore its exclusion.
	if agentID == source.ManagerID || !m.config.ScopesByGroup() {
		return false
	}
	_, known := m.reporting[agentID]
	return !known
}

func (m Machines) Excluded(controlID, agentID string) bool {
	return m.config.Excludes(controlID, m.reporting[agentID].Groups)
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
