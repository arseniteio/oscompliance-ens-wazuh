package maturity

import (
	"slices"
	"testing"
)

func level(l int) *int { return &l }

func TestAccredit(t *testing.T) {

	cases := []struct {
		name   string
		today  bool
		before int
		want   int
	}{
		{"no evidence in the period", false, 0, 0},
		{"evidence today only", true, 0, 1},
		{"evidence before but not today", false, 29, 1},
		{"26 of 30 days", true, 25, 1},
		{"27 of 30 days is continuous", true, 26, 2},
		{"every day", true, 29, 2},
	}
	for _, c := range cases {
		if got := Accredit(c.today, c.before); got != c.want {
			t.Errorf("%s: L%d, want L%d", c.name, got, c.want)
		}
	}
}

func TestIncoherent(t *testing.T) {
	if !Incoherent(level(1), level(3)) || Incoherent(level(2), level(4)) || Incoherent(level(0), level(2)) || Incoherent(nil, level(5)) || Incoherent(level(0), nil) {
		t.Error("only a declared L3 or more over an accredited L0 or L1 is incoherent")
	}
}

func TestOrganizationTakesTheLowestMachine(t *testing.T) {
	if l, ok := Organization([]int{2, 1, 2}); !ok || l != 1 {
		t.Errorf("L%d %v", l, ok)
	}
	if _, ok := Organization(nil); ok {
		t.Error("no machine, no level")
	}
}

func TestGlobalIsTheLevelOfEightyPercent(t *testing.T) {
	cases := []struct {
		levels []int
		want   int
	}{
		{nil, 0},
		{[]int{3, 3, 3, 3, 0}, 3},
		{[]int{3, 3, 3, 0, 0}, 0},
		{[]int{4, 4, 3, 2, 2}, 2},
		{[]int{5, 5, 5, 4, 4}, 4},
	}
	for _, c := range cases {
		if got := Global(c.levels); got != c.want {
			t.Errorf("%v: L%d, want L%d", c.levels, got, c.want)
		}
	}
}

func TestSummarize(t *testing.T) {

	s := Summarize([]Measure{
		{ID: "op.acc.1", Accredited: level(2), Assessed: level(3), Target: level(3)},
		{ID: "op.exp.8", Accredited: level(1), Target: level(2)},
		{ID: "org.2", Assessed: level(2), Target: level(3)},
	})

	if s.Applicable != 3 || s.Unmeasured != 1 || s.Unassessed != 1 {
		t.Errorf("counts: %+v", s)
	}
	if s.Accredited != [6]int{0, 1, 1, 0, 0, 0} || s.Assessed != [6]int{0, 0, 1, 1, 0, 0} {
		t.Errorf("distribution: %v %v", s.Accredited, s.Assessed)
	}
	if !slices.Equal(s.BelowTarget, []string{"op.exp.8", "org.2"}) {
		t.Errorf("below target: %v", s.BelowTarget)
	}
	if s.GlobalAccredited != 1 || s.GlobalAssessed != 0 {
		t.Errorf("global: L%d L%d", s.GlobalAccredited, s.GlobalAssessed)
	}

	// A measure without engine has no accredited level: it must not pull the accredited global down.
	judged := Summarize([]Measure{{ID: "op.acc.1", Accredited: level(1)}, {ID: "org.2", Assessed: level(2)}})
	if judged.GlobalAccredited != 1 {
		t.Errorf("declared-only measure lowered the accredited global to L%d", judged.GlobalAccredited)
	}
}

func TestAssessmentValid(t *testing.T) {
	if !(Assessment{Measure: "org.2", Level: level(3)}).Valid() || (Assessment{Measure: "", Level: level(3)}).Valid() || (Assessment{Measure: "org.2", Target: level(6)}).Valid() {
		t.Error("an assessment needs a measure and levels from 0 to 5")
	}
}

func TestScaleLevel(t *testing.T) {

	s := Scale{Control: "mp.info.6", Thresholds: []int{20, 40, 60, 80, 95}}

	for percent, want := range map[int]int{0: 0, 19: 0, 20: 1, 59: 2, 90: 4, 95: 5, 100: 5} {
		if got := s.Level(percent); got != want {
			t.Errorf("%d %%: L%d, want L%d", percent, got, want)
		}
	}
}

func TestScaleValid(t *testing.T) {

	for name, c := range map[string]struct {
		scale Scale
		want  bool
	}{
		"five rising thresholds": {Scale{Control: "mp.info.6", Thresholds: []int{10, 20, 30, 40, 50}}, true},
		"no control":             {Scale{Thresholds: []int{10, 20, 30, 40, 50}}, false},
		"four thresholds":        {Scale{Control: "mp.info.6", Thresholds: []int{10, 20, 30, 40}}, false},
		"falling":                {Scale{Control: "mp.info.6", Thresholds: []int{10, 30, 20, 40, 50}}, false},
		"over 100":               {Scale{Control: "mp.info.6", Thresholds: []int{10, 20, 30, 40, 101}}, false},
	} {
		if got := c.scale.Valid(); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestMachineScaleWinsOverControlScale(t *testing.T) {

	general := Scale{Control: "mp.info.6", Thresholds: []int{10, 20, 30, 40, 50}}
	web01 := Scale{Control: "mp.info.6", Agent: "001", Thresholds: []int{50, 60, 70, 80, 90}}
	scales := Scales{general, web01, {Control: "mp.info.6", Agent: "002", Thresholds: []int{1}}}

	if got, _ := scales.For("mp.info.6", "001"); got.Agent != "001" {
		t.Errorf("001 got %+v", got)
	}
	if got, ok := scales.For("mp.info.6", "002"); !ok || got.Agent != "" {
		t.Errorf("an invalid machine scale falls back to the control scale, got %+v", got)
	}
	if _, ok := scales.For("op.acc.1", "001"); ok {
		t.Error("no scale for op.acc.1")
	}
}

func TestDefaultScaleAndRequiredLevels(t *testing.T) {
	if got, configured := (Scales{}).For("mp.info.6", "001"); configured || got.Level(90) != 4 || got.Level(100) != 5 || got.Level(79) != 3 {
		t.Errorf("default scale: %+v", got)
	}
	for level, want := range map[string]int{"BAJO": 2, "MEDIO": 3, "ALTO": 4} {
		if got, ok := Required(level); !ok || got != want {
			t.Errorf("%s needs L%d, got L%d", level, want, got)
		}
	}
}
