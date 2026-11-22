package params

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

const (
	activeDocument = "ACTIVE_CONFIGURATION"
	systemDocument = "SYSTEM_CONFIGURATION"
	maxSystems     = 1000
)

var systemID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

type System struct {
	ID     string
	Name   string
	Config *Config
}

func (s System) Default() bool { return s.ID == verdict.DefaultSystem }

func LoadSystems(ctx context.Context, client *indexer.Client, index string) ([]System, []error, error) {

	query := map[string]any{
		"size":  maxSystems,
		"query": map[string]any{"terms": map[string]any{"documentType": []string{activeDocument, systemDocument}}},
	}

	var resp struct {
		Hits struct {
			Hits []struct {
				Source systemDocumentSource `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	err := client.Search(ctx, index, query, &resp)
	var missing *indexer.Error
	if errors.As(err, &missing) && missing.Status == http.StatusNotFound {
		return []System{defaultSystem(nil)}, nil, fmt.Errorf("%w: no index %s", ErrNotSaved, index)
	}
	if err != nil {
		return nil, nil, err
	}

	docs := make([]systemDocumentSource, 0, len(resp.Hits.Hits))
	for _, h := range resp.Hits.Hits {
		docs = append(docs, h.Source)
	}

	systems, problems := systemsOf(docs)
	if systems[0].Config == nil {
		systems[0] = defaultSystem(nil)
		return systems, problems, fmt.Errorf("%w: no %s in %s", ErrNotSaved, activeDocument, index)
	}
	return systems, problems, nil
}

type systemDocumentSource struct {
	DocumentType string `json:"documentType"`
	System       struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"system"`
	Configuration *Config `json:"configuration"`
}

func defaultSystem(config *Config) System {
	if config == nil {
		config = Default()
	}
	return System{ID: verdict.DefaultSystem, Name: verdict.DefaultSystem, Config: config}
}

func systemsOf(docs []systemDocumentSource) ([]System, []error) {

	systems := []System{{ID: verdict.DefaultSystem, Name: verdict.DefaultSystem}}
	var problems []error
	seen := map[string]bool{verdict.DefaultSystem: true}

	for _, d := range docs {
		if d.DocumentType == activeDocument {
			systems[0].Config = d.Configuration
			continue
		}
		s := System{ID: strings.TrimSpace(d.System.ID), Name: strings.TrimSpace(d.System.Name), Config: d.Configuration}
		if err := s.validate(seen); err != nil {
			problems = append(problems, err)
			continue
		}
		seen[s.ID] = true
		systems = append(systems, s)
	}

	slices.SortFunc(systems[1:], func(a, b System) int { return strings.Compare(a.ID, b.ID) })
	return systems, problems
}

func (s System) validate(seen map[string]bool) error {
	switch {
	case !systemID.MatchString(s.ID):
		return fmt.Errorf("system %q: the id takes 1 to 40 lowercase letters, digits or hyphens", s.ID)
	case seen[s.ID]:
		return fmt.Errorf("system %q: the id is already in use", s.ID)
	case s.Config == nil:
		return fmt.Errorf("system %q: no configuration", s.ID)
	case s.Config.Scope.Mode != "group" && s.Config.Scope.Mode != "agent":
		// Only the default system may take every machine; another one would claim the whole fleet.
		return fmt.Errorf("system %q: the scope must name groups or machines", s.ID)
	}
	return nil
}
