package verdict

import "github.com/arseniteio/oscompliance-ens-wazuh/catalog"

type Status string

const (
	Compliant    Status = "COMPLIANT"
	NonCompliant Status = "NON_COMPLIANT"
	NotEvaluable Status = "NOT_EVALUABLE"

	NotApplicable Status = "NOT_APPLICABLE"

	Partial Status = "PARTIAL"
)

const (
	ScopeEvidence     = "evidence"
	ScopeRequirement  = "requirement"
	ScopeControl      = "control"
	ScopeOrganization = "organization"
)

const (
	OrganizationAgent = "organization"
	AllMeasures       = "ENS"
)

const DefaultSystem = "default"

type Cause string

const (
	CauseCollection Cause = "COLLECTION"

	CauseConfiguration Cause = "CONFIGURATION"

	CauseEvidence Cause = "EVIDENCE"
)

type Judgement struct {
	Status  Status
	Cause   Cause
	Reason  string
	Message catalog.Message
	Tally   *Tally
}

type Tally struct {
	Met   int
	Total int
}

func (j Judgement) Counting(met, total int) Judgement {
	if total > 0 {
		j.Tally = &Tally{Met: met, Total: total}
	}
	return j
}

func (t Tally) Percent() int {
	// Floor, not round: 89.6 % must not reach a 90 % threshold of the maturity scale.
	return t.Met * 100 / t.Total
}

func Explain(status Status, cause Cause, m catalog.Message) Judgement {
	return Judgement{Status: status, Cause: cause, Reason: m.Render("en"), Message: m}
}

const SchemaVersion = "1"

type Verdict struct {
	OSComplianceVerdict string         `json:"oscompliance_verdict"`
	Timestamp           string         `json:"@timestamp"`
	System              string         `json:"system,omitempty"`
	Scope               string         `json:"scope"`
	Control             string         `json:"control"`
	Requirement         string         `json:"requirement,omitempty"`
	Evidence            string         `json:"evidence,omitempty"`
	Agent               Agent          `json:"agent"`
	Status              Status         `json:"status"`
	Cause               Cause          `json:"cause,omitempty"`
	Reason              string         `json:"reason,omitempty"`
	ReasonCode          string         `json:"reason_code,omitempty"`
	ReasonArgs          map[string]any `json:"reason_args,omitempty"`
	RunID               string         `json:"run_id,omitempty"`
	WindowStart         string         `json:"window_start"`
	WindowEnd           string         `json:"window_end"`
	EngineVersion       string         `json:"engine_version"`

	Evidenced *bool `json:"evidenced,omitempty"`
	Attested  bool  `json:"attested,omitempty"`

	Score                  *int     `json:"score,omitempty"`
	Coverage               *int     `json:"coverage,omitempty"`
	ApplicableRequirements *int     `json:"applicable_requirements,omitempty"`
	MeasuredRequirements   *int     `json:"measured_requirements,omitempty"`
	UnmeasuredRequirements []string `json:"unmeasured_requirements,omitempty"`

	Maturity *Maturity `json:"maturity,omitempty"`

	Tally *TallyResult `json:"tally,omitempty"`

	Compliance *ComplianceResult `json:"compliance,omitempty"`
}

type ComplianceResult struct {
	Percent  int    `json:"percent"`
	Level    int    `json:"level"`
	Required int    `json:"required"`
	Category string `json:"category"`
}

type TallyResult struct {
	Met     int  `json:"met"`
	Total   int  `json:"total"`
	Percent int  `json:"percent"`
	Level   *int `json:"level,omitempty"`
}

type Maturity struct {
	Accredited  *int `json:"accredited,omitempty"`
	WorkingDays *int `json:"working_days,omitempty"`
	PeriodDays  int  `json:"period_days,omitempty"`

	Assessed   *int   `json:"assessed,omitempty"`
	Target     *int   `json:"target,omitempty"`
	AssessedBy string `json:"assessed_by,omitempty"`
	AssessedAt string `json:"assessed_at,omitempty"`
	References string `json:"references,omitempty"`
	Note       string `json:"note,omitempty"`
	Incoherent bool   `json:"incoherent,omitempty"`
	Machines   int    `json:"machines,omitempty"`

	Applicable       *int     `json:"applicable,omitempty"`
	Unmeasured       *int     `json:"unmeasured,omitempty"`
	Unassessed       *int     `json:"unassessed,omitempty"`
	BelowTarget      []string `json:"below_target,omitempty"`
	AccreditedCounts []int    `json:"accredited_counts,omitempty"`
	AssessedCounts   []int    `json:"assessed_counts,omitempty"`
	GlobalAccredited *int     `json:"global_accredited,omitempty"`
	GlobalAssessed   *int     `json:"global_assessed,omitempty"`
}

type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (v *Verdict) Explained(m catalog.Message, fallback string) {
	if m.IsZero() {
		v.Reason = fallback
		return
	}
	v.Reason, v.ReasonCode, v.ReasonArgs = m.Render("en"), m.Code, m.Args
}

type Degree struct {
	Controls     int
	Measured     int
	Score        int
	Unconfigured []string
}
