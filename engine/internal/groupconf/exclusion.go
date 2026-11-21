package groupconf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

type GroupMaker interface {
	GroupNames(ctx context.Context) ([]string, error)
	CreateGroup(ctx context.Context, name string) error
}

func CreateExclusionGroups(ctx context.Context, api GroupMaker, controls []catalog.Control, apply bool, now time.Time) ([]Change, error) {

	groups := make([]string, 0, len(controls))
	for _, control := range controls {
		groups = append(groups, catalog.ExclusionGroup(control.Control))
	}

	return CreateGroups(ctx, api, groups, apply, now)
}

func CreateGroups(ctx context.Context, api GroupMaker, groups []string, apply bool, now time.Time) ([]Change, error) {

	existing, err := api.GroupNames(ctx)
	if err != nil {
		return nil, err
	}

	var changes []Change
	var errs []error

	for _, group := range groups {

		if slices.Contains(existing, group) {
			continue
		}

		if apply {
			err := api.CreateGroup(ctx, group)
			if denied(err) {
				return changes, fmt.Errorf("group %s: the engine API user may not create groups; run catalog/wazuh/engine-users.sh to grant group:create: %w", group, err)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("group %s: %w", group, err))
				continue
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply})
	}

	return changes, errors.Join(errs...)
}

func denied(err error) bool {
	var apiErr *wazuhapi.Error
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden
}
