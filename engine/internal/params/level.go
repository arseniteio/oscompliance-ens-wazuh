package params

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
)

type LevelAdjustment struct {
	ControlID string `json:"controlId"`
	AgentID   string `json:"agentId"`
	Level     string `json:"level"`
	Reason    string `json:"reason"`
}

type ControlLevel struct {
	Level    string
	Adjusted *LevelAdjustment
}

var levelRank = map[string]int{"BAJO": 1, "MEDIO": 2, "ALTO": 3}

// An adjustment only lowers the level a control is judged at: raising it above the system
// category would demand more than the ENS asks of the system, which needs no exception.
func usableAdjustment(a LevelAdjustment, category string) bool {
	level := catalog.CategoryRank(a.Level)
	return a.ControlID != "" && strings.TrimSpace(a.Reason) != "" && level != "" && levelRank[level] <= levelRank[category]
}

func (c *Config) ControlLevel(controlID, agentID string) ControlLevel {

	category := c.Level()
	var general *LevelAdjustment

	for i, a := range c.LevelAdjustments {
		if a.ControlID != controlID || !usableAdjustment(a, category) {
			continue
		}
		if a.AgentID != "" && a.AgentID == agentID {
			return ControlLevel{Level: catalog.CategoryRank(a.Level), Adjusted: &c.LevelAdjustments[i]}
		}
		if a.AgentID == "" && general == nil {
			general = &c.LevelAdjustments[i]
		}
	}

	if general != nil {
		return ControlLevel{Level: catalog.CategoryRank(general.Level), Adjusted: general}
	}
	return ControlLevel{Level: category}
}
