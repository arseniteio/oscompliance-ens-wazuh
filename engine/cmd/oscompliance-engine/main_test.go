package main

import (
	"context"
	"slices"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type namedControl string

func (c namedControl) Control() string { return string(c) }

func (namedControl) Begin(context.Context, evaluator.Pass) error { return nil }

func (namedControl) Agent(context.Context, verdict.Agent, params.Lister) (map[string]evaluator.Result, error) {
	return nil, nil
}

func TestSelectControls(t *testing.T) {
	all := []evaluator.Evaluator{namedControl("op.acc.1"), namedControl("op.acc.2"), namedControl("op.exp.1")}

	tests := []struct {
		name, names string
		want        []string
		wantErr     bool
	}{
		{name: "empty keeps every control", names: "", want: []string{"op.acc.1", "op.acc.2", "op.exp.1"}},
		{name: "one control", names: "op.acc.1", want: []string{"op.acc.1"}},
		{name: "spaces are ignored", names: "op.acc.1, op.exp.1", want: []string{"op.acc.1", "op.exp.1"}},
		{name: "unknown control stops the engine", names: "op.acc.9", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectControls(all, tt.names)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d controls, want %d", len(got), len(tt.want))
			}
			for i, ev := range got {
				if ev.Control() != tt.want[i] {
					t.Errorf("control %d = %s, want %s", i, ev.Control(), tt.want[i])
				}
			}
		})
	}
}

func TestCatalogControlsAreTheJudgedOnes(t *testing.T) {
	got := catalogControls([]evaluator.Evaluator{namedControl("op.acc.1"), namedControl("not.in.catalog")})

	if len(got) != 1 || got[0].Control != "op.acc.1" {
		t.Errorf("got %v", got)
	}
}

func TestScopeGroupsNamesEachGroupOnce(t *testing.T) {

	system := func(id string, groups ...string) params.System {
		c := &params.Config{}
		c.Scope.Mode, c.Scope.GroupIDs = "group", groups
		return params.System{ID: id, Config: c}
	}
	all := &params.Config{}
	all.Scope.Mode = "all"

	got := scopeGroups([]params.System{{ID: "default", Config: all}, system("pilot", "pilot", "shared"), system("lab", "lab", "shared")})

	if !slices.Equal(got, []string{"lab", "pilot", "shared"}) {
		t.Errorf("groups %v", got)
	}
}
