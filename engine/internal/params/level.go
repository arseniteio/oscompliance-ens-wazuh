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

func (c *Config) dimensionLevel(dimension string) string {
	declared := map[string]string{
		"C": c.Global.ConfidentialityLevel,
		"I": c.Global.IntegrityLevel,
		"T": c.Global.TraceabilityLevel,
		"A": c.Global.AuthenticityLevel,
		"D": c.Global.AvailabilityLevel,
	}[dimension]
	if level := catalog.CategoryRank(declared); level != "" {
		return level
	}
	return c.Level()
}

// A control applies at the highest level of the dimensions it protects; a dimension without a
// declared level takes the system category, as the plugin does.
func (c *Config) applicableLevel(controlID string) string {
	control, known := catalog.LookupControl(controlID)
	if !known || len(control.LevelDimension) == 0 {
		return c.Level()
	}
	highest := ""
	for _, dimension := range control.LevelDimension {
		if level := c.dimensionLevel(dimension); levelRank[level] > levelRank[highest] {
			highest = level
		}
	}
	return highest
}

func (c *Config) ControlLevel(controlID, agentID string) ControlLevel {

	category := c.applicableLevel(controlID)
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
