package params

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestLoadSystemsReadsTheActiveConfigurationAsTheDefault(t *testing.T) {

	client := indexerAnswering(t, http.StatusOK, `{"hits": {"hits": [
	  {"_source": {"documentType": "SYSTEM_CONFIGURATION", "system": {"id": "pilot", "name": "Piloto"},
	    "configuration": {"scope": {"mode": "group", "groupIds": ["pilot"]}}}},
	  {"_source": {"documentType": "ACTIVE_CONFIGURATION", "configuration": {"scope": {"mode": "all"}, "global": {"ensLevel": "MEDIO"}}}},
	  {"_source": {"documentType": "SYSTEM_CONFIGURATION", "system": {"id": "lab"},
	    "configuration": {"scope": {"mode": "agent", "agentIds": ["003"]}}}}]}}`)

	systems, problems, err := LoadSystems(context.Background(), client, "wazuh-ens-configuration")
	if err != nil || len(problems) != 0 {
		t.Fatalf("err %v, problems %v", err, problems)
	}

	var ids []string
	for _, s := range systems {
		ids = append(ids, s.ID)
	}
	if len(ids) != 3 || ids[0] != "default" || ids[1] != "lab" || ids[2] != "pilot" {
		t.Fatalf("systems %v, want default first and the rest by id", ids)
	}
	if !systems[0].Default() || systems[0].Config.Global.EnsLevel != "MEDIO" {
		t.Errorf("default system %+v", systems[0])
	}
	if systems[2].Name != "Piloto" {
		t.Errorf("name %q", systems[2].Name)
	}
}

func TestLoadSystemsLeavesOutSystemsItCannotJudgeSafely(t *testing.T) {

	client := indexerAnswering(t, http.StatusOK, `{"hits": {"hits": [
	  {"_source": {"documentType": "ACTIVE_CONFIGURATION", "configuration": {"scope": {"mode": "all"}}}},
	  {"_source": {"documentType": "SYSTEM_CONFIGURATION", "system": {"id": "everything"}, "configuration": {"scope": {"mode": "all"}}}},
	  {"_source": {"documentType": "SYSTEM_CONFIGURATION", "system": {"id": "default"}, "configuration": {"scope": {"mode": "agent"}}}},
	  {"_source": {"documentType": "SYSTEM_CONFIGURATION", "system": {"id": "Bad Id"}, "configuration": {"scope": {"mode": "agent"}}}},
	  {"_source": {"documentType": "SYSTEM_CONFIGURATION", "system": {"id": "empty"}}}]}}`)

	systems, problems, err := LoadSystems(context.Background(), client, "wazuh-ens-configuration")
	if err != nil {
		t.Fatal(err)
	}
	if len(systems) != 1 || len(problems) != 4 {
		t.Errorf("systems %d, problems %v", len(systems), problems)
	}
}

func TestLoadSystemsFallsBackToTheCatalogDefault(t *testing.T) {

	client := indexerAnswering(t, http.StatusOK, `{"hits": {"hits": []}}`)

	systems, _, err := LoadSystems(context.Background(), client, "wazuh-ens-configuration")
	if !errors.Is(err, ErrNotSaved) {
		t.Fatalf("err %v, want ErrNotSaved", err)
	}
	if len(systems) != 1 || !systems[0].Default() || systems[0].Config == nil {
		t.Errorf("systems %+v", systems)
	}
}
