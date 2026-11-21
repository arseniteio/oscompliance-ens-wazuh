package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

//go:embed controls templates messages system-types.json default-configuration.json host-signals.json profiles maturity.json
var files embed.FS

type Control struct {
	Framework         string               `json:"framework"`
	Control           string               `json:"control"`
	Title             string               `json:"title"`
	Status            string               `json:"status"`
	Family            string               `json:"family,omitempty"`
	Category          string               `json:"category,omitempty"`
	Dimension         string               `json:"dimension,omitempty"`
	LevelDimension    []string             `json:"level_dimension,omitempty"`
	AnnexSection      string               `json:"annex_section,omitempty"`
	Description       string               `json:"description,omitempty"`
	Levels            []string             `json:"levels,omitempty"`
	MeasurementPlanes []string             `json:"measurement_planes,omitempty"`
	Source            *Source              `json:"source,omitempty"`
	Version           string               `json:"version,omitempty"`
	Requirements      []Requirement        `json:"requirements"`
	Evidences         []Evidence           `json:"evidences"`
	Parameters        map[string]Parameter `json:"parameters"`
	Report            []ReportField        `json:"report"`
}

type ReportField struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidences   []string `json:"evidences"`
	Parameters  []string `json:"parameters"`
}

type Source struct {
	Template string `json:"template"`
	Version  string `json:"version"`
	Date     string `json:"date,omitempty"`
}

type Requirement struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Kind                string   `json:"kind,omitempty"`
	Levels              []string `json:"levels"`
	ApplicabilityReason string   `json:"applicability_reason,omitempty"`
	Description         string   `json:"description,omitempty"`
	Interpretation      string   `json:"interpretation,omitempty"`
	EvidenceIDs         []string `json:"evidence_ids"`
	ParameterIDs        []string `json:"parameter_ids,omitempty"`
}

func (r Requirement) AppliesAt(level string) bool {
	return slices.Contains(r.Levels, level)
}

type Evidence struct {
	ID            string   `json:"id"`
	Title         string   `json:"title,omitempty"`
	Description   string   `json:"description,omitempty"`
	Levels        []string `json:"levels"`
	Requirements  []string `json:"requirements"`
	Category      string   `json:"category,omitempty"`
	Criticality   string   `json:"criticality,omitempty"`
	AuditQuestion string   `json:"audit_question,omitempty"`
}

const (
	ClassOrganisation = "organisation"

	ClassSystem = "system"

	ClassPlatform = "platform"
)

type Parameter struct {
	Class           string              `json:"class"`
	Name            string              `json:"name,omitempty"`
	Label           string              `json:"label,omitempty"`
	Description     string              `json:"description,omitempty"`
	Levels          []string            `json:"levels,omitempty"`
	Requirements    []string            `json:"requirements,omitempty"`
	Type            string              `json:"type,omitempty"`
	Pattern         bool                `json:"pattern,omitempty"`
	MatchMode       string              `json:"match_mode,omitempty"`
	Example         string              `json:"example,omitempty"`
	Options         []string            `json:"options,omitempty"`
	OptionsByLevel  map[string][]string `json:"options_by_level,omitempty"`
	Columns         []Column            `json:"columns,omitempty"`
	Required        bool                `json:"required,omitempty"`
	MinValue        *float64            `json:"min_value,omitempty"`
	MaxValue        *float64            `json:"max_value,omitempty"`
	DefaultValue    any                 `json:"default_value,omitempty"`
	InitialValue    any                 `json:"initial_value,omitempty"`
	AgentUsage      string              `json:"agent_usage,omitempty"`
	EngineUsage     string              `json:"engine_usage,omitempty"`
	EvidenceIDs     []string            `json:"evidence_ids,omitempty"`
	IfNotConfigured string              `json:"if_not_configured,omitempty"`
}

type Column struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Options  []string `json:"options,omitempty"`
	Variadic bool     `json:"variadic,omitempty"`
}

type Template struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Kind        string                       `json:"kind"`
	SystemType  string                       `json:"system_type"`
	TypeDefault bool                         `json:"type_default"`
	Values      map[string]map[string]any    `json:"values"`
	MatchModes  map[string]map[string]string `json:"match_modes,omitempty"`
}

var (
	controls  = map[string]Control{}
	templates []Template
)

func init() {

	err := fs.WalkDir(files, "controls", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".json" {
			return err
		}
		var c Control
		if err := decodeStrict(p, &c); err != nil {
			return err
		}
		controls[c.Control] = c
		return nil
	})
	if err != nil {
		panic(err)
	}

	entries, err := fs.ReadDir(files, "templates")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		var t Template
		if err := decodeStrict(path.Join("templates", e.Name()), &t); err != nil {
			panic(err)
		}
		templates = append(templates, t)
	}

	loadMessages()
	loadSystemTypes()
	loadHostSignals()
	loadProfiles()
}

func decodeStrict(p string, v any) error {

	raw, err := files.ReadFile(p)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("catalog %s: %w", p, err)
	}

	return nil
}

func Controls() []Control {

	var out []Control

	for _, c := range controls {
		out = append(out, c)
	}

	slices.SortFunc(out, func(a, b Control) int { return strings.Compare(a.Control, b.Control) })

	return out
}

func ExclusionGroup(controlID string) string {
	return "ens-excluir-" + controlID
}

func LookupControl(id string) (Control, bool) {
	c, ok := controls[id]
	return c, ok
}

func (c Control) Evidence(id string) (Evidence, bool) {
	for _, e := range c.Evidences {
		if e.ID == id {
			return e, true
		}
	}
	return Evidence{}, false
}

func (e Evidence) AppliesAt(level string) bool {
	return slices.Contains(e.Levels, level)
}

func ParameterClass(controlID, paramID string) string {
	return controls[controlID].Parameters[paramID].Class
}

func ParameterType(controlID, paramID string) string {
	return controls[controlID].Parameters[paramID].Type
}

func IsAgentLevel(controlID, paramID string) bool {
	class := ParameterClass(controlID, paramID)
	return class == ClassSystem || class == ClassPlatform
}

func BuiltinTemplate(id, controlID string) (Template, bool) {
	for _, t := range templates {
		if t.ID == id && t.Values[controlID] != nil {
			return t, true
		}
	}
	return Template{}, false
}

func TypeDefaultTemplate(controlID, systemType string) (Template, bool) {
	for _, t := range templates {
		if t.TypeDefault && t.SystemType == systemType && t.Values[controlID] != nil {
			return t, true
		}
	}
	return Template{}, false
}

var platformTypes = map[string]string{}

func loadSystemTypes() {
	raw, err := files.ReadFile("system-types.json")
	if err != nil {
		panic(err)
	}
	var byType map[string][]string
	if err := json.Unmarshal(raw, &byType); err != nil {
		panic(err)
	}
	for systemType, platforms := range byType {
		for _, p := range platforms {
			platformTypes[p] = systemType
		}
	}
}

func SystemTypeOf(agentID, platform string) string {
	if agentID == "000" {
		return "manager"
	}
	return platformTypes[strings.ToLower(strings.TrimSpace(platform))]
}
