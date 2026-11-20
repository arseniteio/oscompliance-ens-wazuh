package params

import "testing"

func adjusted(category string, adjustments ...LevelAdjustment) *Config {
	c := &Config{LevelAdjustments: adjustments}
	c.Global.EnsLevel = category
	return c
}

func TestControlLevelFollowsTheCategoryWithoutAdjustment(t *testing.T) {
	if got := adjusted("ALTO").ControlLevel("op.acc.1", "001"); got.Level != "ALTO" || got.Adjusted != nil {
		t.Errorf("got %+v", got)
	}
}

func TestMachineAdjustmentWinsOverControlAdjustment(t *testing.T) {
	c := adjusted("ALTO",
		LevelAdjustment{ControlID: "op.acc.1", Level: "MEDIO", Reason: "acta 12"},
		LevelAdjustment{ControlID: "op.acc.1", AgentID: "001", Level: "BAJO", Reason: "laboratorio"},
	)

	if got := c.ControlLevel("op.acc.1", "001"); got.Level != "BAJO" || got.Adjusted.Reason != "laboratorio" {
		t.Errorf("001: %+v", got)
	}
	if got := c.ControlLevel("op.acc.1", "002"); got.Level != "MEDIO" {
		t.Errorf("002: %+v", got)
	}
	if got := c.ControlLevel("op.acc.2", "001"); got.Level != "ALTO" || got.Adjusted != nil {
		t.Errorf("op.acc.2: %+v", got)
	}
}

func TestUnusableAdjustmentsAreIgnored(t *testing.T) {
	c := adjusted("MEDIO",
		LevelAdjustment{ControlID: "op.acc.1", Level: "ALTO", Reason: "raises"},
		LevelAdjustment{ControlID: "op.acc.2", Level: "BAJO"},
		LevelAdjustment{ControlID: "op.acc.3", Level: "MUY BAJO", Reason: "x"},
	)

	for _, id := range []string{"op.acc.1", "op.acc.2", "op.acc.3"} {
		if got := c.ControlLevel(id, "001"); got.Level != "MEDIO" || got.Adjusted != nil {
			t.Errorf("%s: %+v", id, got)
		}
	}
}

func TestAdjustmentAcceptsTheCategoryWord(t *testing.T) {
	if got := adjusted("MEDIO", LevelAdjustment{ControlID: "op.acc.1", Level: "BÁSICO", Reason: "x"}).ControlLevel("op.acc.1", ""); got.Level != "BAJO" {
		t.Errorf("got %+v", got)
	}
}
