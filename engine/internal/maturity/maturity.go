package maturity

import (
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

const (
	PeriodDays    = 30
	MaxAccredited = 2
	MaxLevel      = 5

	continuousShare = 0.9
	globalShare     = 0.8
)

func Accredit(workingToday bool, workingDaysBefore int) int {

	// The evidence alone shows a practice that exists (L1) or one that repeats without gaps
	// (L2). From L3 up the ENS asks for a written, measured and improved process: people
	// declare those levels and the engine only checks them against the evidence.

	days := workingDaysBefore
	if workingToday {
		days++
	}
	switch {
	case days == 0:
		return 0
	case workingToday && float64(days) >= continuousShare*PeriodDays:
		return MaxAccredited
	}
	return 1
}

type Assessment struct {
	Measure    string `json:"measureId"`
	Level      *int   `json:"level"`
	Target     *int   `json:"target"`
	AssessedBy string `json:"assessedBy"`
	AssessedAt string `json:"assessedAt"`
	References string `json:"references"`
	Note       string `json:"note"`
}

func (a Assessment) Valid() bool {
	inRange := func(l *int) bool { return l == nil || (*l >= 0 && *l <= MaxLevel) }
	return strings.TrimSpace(a.Measure) != "" && inRange(a.Level) && inRange(a.Target)
}

type Scale struct {
	Control    string `json:"controlId"`
	Agent      string `json:"agentId"`
	Thresholds []int  `json:"thresholds"`
}

func (s Scale) Valid() bool {
	if strings.TrimSpace(s.Control) == "" || len(s.Thresholds) != MaxLevel {
		return false
	}
	previous := 0
	for _, t := range s.Thresholds {
		if t < previous || t > 100 {
			return false
		}
		previous = t
	}
	return true
}

func (s Scale) Level(percent int) int {
	level := 0
	for i, threshold := range s.Thresholds {
		if percent >= threshold {
			level = i + 1
		}
	}
	return level
}

type Scales []Scale

// The CCN table (CCN-STIC 844) until the configuration sets another scale: 36 of 40 copies
// (90 %) is L4.
var DefaultScale = Scale{Thresholds: catalog.Maturity().DefaultScale()}

// CCN-STIC 808: a measure at L2 meets a BÁSICO system, L3 a MEDIO one and L4 an ALTO one.
func Required(level string) (int, bool) {
	required, ok := catalog.Maturity().Required[level]
	return required, ok
}

type Compliance struct {
	Percent  int
	Level    int
	Required int
	Status   verdict.Status
}

func Judge(percent int, scale Scale, controlLevel string) (Compliance, bool) {
	required, known := Required(controlLevel)
	if !known {
		return Compliance{}, false
	}
	c := Compliance{Percent: percent, Level: scale.Level(percent), Required: required}
	switch {
	case percent <= 0:
		c.Status = verdict.NonCompliant
	case c.Level >= required:
		c.Status = verdict.Compliant
	default:
		c.Status = verdict.Partial
	}
	return c, true
}

func (ss Scales) For(control, agent string) (Scale, bool) {
	var general *Scale
	for i, s := range ss {
		if s.Control != control || !s.Valid() {
			continue
		}
		if s.Agent == agent && agent != "" {
			return s, true
		}
		if s.Agent == "" && general == nil {
			general = &ss[i]
		}
	}
	if general == nil {
		return DefaultScale, false
	}
	return *general, true
}

func Incoherent(accredited, assessed *int) bool {
	// A declared L3 or higher needs a practice the evidence sees repeating; on L0 or L1 it is
	// reported, not corrected.
	return accredited != nil && assessed != nil && *assessed >= 3 && *accredited < MaxAccredited
}

func Organization(perMachine []int) (int, bool) {
	if len(perMachine) == 0 {
		return 0, false
	}
	return slices.Min(perMachine), true
}

type Measure struct {
	ID         string
	Accredited *int
	Assessed   *int
	Target     *int
}

func (m Measure) effective() int {
	switch {
	case m.Assessed != nil:
		return *m.Assessed
	case m.Accredited != nil:
		return *m.Accredited
	}
	return 0
}

type Summary struct {
	Applicable       int
	Unmeasured       int
	Unassessed       int
	BelowTarget      []string
	Accredited       [MaxLevel + 1]int
	Assessed         [MaxLevel + 1]int
	GlobalAccredited int
	GlobalAssessed   int
}

func Summarize(measures []Measure) Summary {

	s := Summary{Applicable: len(measures)}
	var accredited, assessed []int

	for _, m := range measures {
		if m.Accredited == nil {
			s.Unmeasured++
		} else {
			s.Accredited[*m.Accredited]++
			accredited = append(accredited, *m.Accredited)
		}
		a := 0
		if m.Assessed == nil {
			s.Unassessed++
		} else {
			s.Assessed[*m.Assessed]++
			a = *m.Assessed
		}
		assessed = append(assessed, a)
		if m.Target != nil && m.effective() < *m.Target {
			s.BelowTarget = append(s.BelowTarget, m.ID)
		}
	}

	slices.Sort(s.BelowTarget)
	s.GlobalAccredited = Global(accredited)
	s.GlobalAssessed = Global(assessed)
	return s
}

func Global(levels []int) int {
	// The level reached by at least 80 % of the applicable measures: an average such as L2.6
	// is not a CMM level, and one lagging measure should not sink the whole organization.
	if len(levels) == 0 {
		return 0
	}
	for level := MaxLevel; level > 0; level-- {
		reached := 0
		for _, l := range levels {
			if l >= level {
				reached++
			}
		}
		if float64(reached) >= globalShare*float64(len(levels)) {
			return level
		}
	}
	return 0
}
