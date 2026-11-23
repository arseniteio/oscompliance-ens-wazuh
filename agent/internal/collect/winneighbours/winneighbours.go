package winneighbours

import (
	_ "embed"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/neighbours"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed neighbours.ps1
var script string

type entry struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	State     string `json:"state"`
}

type output struct {
	Neighbours []entry `json:"neighbours"`
}

// Unreachable and Incomplete entries have no resolved MAC, like the entries
// without ATF_COM the Linux collector leaves out.
var unresolvedStates = map[string]bool{"Unreachable": true, "Incomplete": true}

func Collect(e *emit.Emitter, run winps.Runner) error {

	s := fact.NeighbourSnapshot{Envelope: e.Envelope(fact.NeighbourSnapshotFact), Status: fact.SourceRead, Neighbours: []fact.Neighbour{}}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	s.Neighbours = resolved(out.Neighbours)
	return e.Emit(s)
}

func resolved(entries []entry) []fact.Neighbour {

	seen := map[string]bool{}
	out := []fact.Neighbour{}

	for _, n := range entries {
		mac := strings.ToLower(strings.ReplaceAll(n.MAC, "-", ":"))
		if n.IP == "" || mac == "" || unresolvedStates[n.State] || neighbours.NotAHost(mac) || seen[n.IP+n.Interface] {
			continue
		}
		seen[n.IP+n.Interface] = true
		out = append(out, fact.Neighbour{IP: n.IP, MAC: mac, Interface: n.Interface})
	}

	neighbours.Sort(out)
	return out
}
