package umask

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
)

func TestCollectUmask(t *testing.T) {
	dir := t.TempDir()
	collecttest.WriteFile(t, filepath.Join(dir, "login.defs"), "# UMASK 000\nUMASK\t022\n", 0o644)
	collecttest.WriteFile(t, filepath.Join(dir, "profile"), "umask\numask -S\numask 27 # restrictive\nif x; then umask 0077; fi\n[ $UID -gt 199 ] && umask 002\n", 0o644)
	collecttest.WriteFile(t, filepath.Join(dir, "profile.d/a.sh"), "umask u=rwx,g=rx,o=\numask $DEFAULT\n", 0o644)
	collecttest.WriteFile(t, filepath.Join(dir, "profile.d/notes.txt"), "umask 000\n", 0o644)
	collecttest.WriteFile(t, filepath.Join(dir, "profile.d/silent.sh"), "export LANG=C\n", 0o644)

	cfg := Config{Files: []string{filepath.Join(dir, "login.defs"), filepath.Join(dir, "profile"), filepath.Join(dir, "missing")}, ProfileDir: filepath.Join(dir, "profile.d")}
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, cfg) })

	sources := facts[0]["sources"].([]any)
	if len(sources) != 4 {
		t.Fatalf("want 4 sources (txt and silent script ignored), got %v", sources)
	}
	got, _ := json.Marshal(sources)
	for _, want := range []string{
		`"umasks":["022"]`,
		`"umasks":["027","077","002"]`,
		`"status":"absent"`,
		`"uninterpretable":["u=rwx,g=rx,o=","$DEFAULT"]`,
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}
