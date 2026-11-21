package catalog

import (
	"slices"
	"strings"
	"testing"
)

func TestOpAcc1(t *testing.T) {
	c, ok := LookupControl("op.acc.1")
	if !ok || len(c.Evidences) != 8 {
		t.Fatalf("op.acc.1: %v %+v", ok, c)
	}

	if c.Status != "ACTIVE" || len(c.Requirements) != 8 {
		t.Fatalf("requirements: %s %d", c.Status, len(c.Requirements))
	}

	ev07, _ := c.Evidence("EV-07")
	if ev07.AppliesAt("BAJO") || !ev07.AppliesAt("MEDIO") || !ev07.AppliesAt("ALTO") {
		t.Errorf("EV-07 levels: %v", ev07.Levels)
	}

	for param, want := range map[string]string{"P-03": ClassPlatform, "P-04": ClassOrganisation, "P-07": ClassSystem, "P-99": ""} {
		if got := ParameterClass("op.acc.1", param); got != want {
			t.Errorf("%s: class %q, want %q", param, got, want)
		}
	}
}

func TestTemplates(t *testing.T) {
	linux, ok := TypeDefaultTemplate("op.acc.1", "linux")
	if !ok || linux.ID != "linux-ubuntu" || linux.Values["op.acc.1"]["P-10"] != float64(1000) {
		t.Errorf("linux default: %v %+v", ok, linux)
	}

	if w, ok := TypeDefaultTemplate("op.acc.1", "windows"); !ok || w.Values["op.acc.1"]["P-03"] != nil {
		t.Errorf("windows: %v %+v", ok, w)
	}

	if m, ok := TypeDefaultTemplate("op.acc.1", "manager"); !ok || m.Values["op.acc.1"]["P-10"] == nil {
		t.Errorf("manager: the Linux values: %v %+v", ok, m)
	}

	if _, ok := BuiltinTemplate("windows-server", "op.acc.1"); !ok {
		t.Error("windows-server by id")
	}
}

func TestReportFieldsPointAtTheControl(t *testing.T) {
	for _, c := range Controls() {
		if len(c.Report) == 0 {
			t.Errorf("%s has no report", c.Control)
		}
		evidences := map[string]bool{}
		for _, e := range c.Evidences {
			evidences[e.ID] = true
		}
		for _, f := range c.Report {
			for _, id := range f.Evidences {
				if !evidences[id] {
					t.Errorf("%s report %s: unknown evidence %s", c.Control, f.ID, id)
				}
			}
			for _, id := range f.Parameters {
				if _, ok := c.Parameters[id]; !ok {
					t.Errorf("%s report %s: unknown parameter %s", c.Control, f.ID, id)
				}
			}
		}
	}
}

func TestSystemTypeOf(t *testing.T) {
	for _, c := range []struct{ id, platform, want string }{
		{"000", "", "manager"},
		{"001", "ubuntu", "linux"},
		{"002", "Windows", "windows"},
		{"003", "darwin", ""},
	} {
		if got := SystemTypeOf(c.id, c.platform); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.id, c.platform, got, c.want)
		}
	}
}

func TestCatalogConsistency(t *testing.T) {
	levels := map[string]bool{"BAJO": true, "MEDIO": true, "ALTO": true}
	classes := map[string]bool{ClassOrganisation: true, ClassSystem: true, ClassPlatform: true}

	all := Controls()
	if len(all) < 6 {
		t.Fatalf("want at least op.acc.1 to op.acc.6, got %d controls", len(all))
	}

	for _, c := range all {
		if c.Title == "" || c.Status == "" || len(c.Requirements) == 0 {
			t.Errorf("%s: title %q, status %q, %d requirements", c.Control, c.Title, c.Status, len(c.Requirements))
		}

		used := map[string]bool{}
		for _, r := range c.Requirements {
			for _, l := range r.Levels {
				if !levels[l] {
					t.Errorf("%s %s: level %q", c.Control, r.ID, l)
				}
			}
			for _, id := range r.EvidenceIDs {
				if _, ok := c.Evidence(id); !ok {
					t.Errorf("%s %s names unknown evidence %s", c.Control, r.ID, id)
				}
				used[id] = true
			}
		}

		for _, e := range c.Evidences {
			if !used[e.ID] {
				t.Errorf("%s %s accredits no requirement", c.Control, e.ID)
			}
		}

		for id, p := range c.Parameters {
			if !classes[p.Class] {
				t.Errorf("%s %s: class %q", c.Control, id, p.Class)
			}
		}
	}
}

func TestMessagesAgree(t *testing.T) {

	placeholders := func(s string) string {
		var found []string
		for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
			found = append(found, m[1])
		}
		slices.Sort(found)
		return strings.Join(slices.Compact(found), ",")
	}

	en, es := Messages("en"), Messages("es")
	for code, text := range en {
		other, ok := es[code]
		if !ok {
			t.Errorf("%s has no Spanish text", code)
			continue
		}
		if placeholders(text) != placeholders(other) {
			t.Errorf("%s: the Spanish text takes other values: %q / %q", code, text, other)
		}
	}
	for code := range es {
		if _, ok := en[code]; !ok {
			t.Errorf("%s has no English text", code)
		}
	}
}

func TestRender(t *testing.T) {

	m := Says("requirement.not_evidenced", "evidences", []Message{
		Says("requirement.evidence_cause", "evidence", "EV-01", "cause", Says("cause.CONFIGURATION")),
		Says("requirement.evidence_cause", "evidence", "EV-06", "cause", Says("cause.COLLECTION")),
	})
	if got := m.Render("es"); got != "no demostrado: EV-01 (sin configurar); EV-06 (sin recogida)" {
		t.Errorf("nested messages: %q", got)
	}
	if got := m.Render("en"); got != "not evidenced: EV-01 (CONFIGURATION); EV-06 (COLLECTION)" {
		t.Errorf("English: %q", got)
	}
}

func TestPluralPlaceholdersAgreeWithTheCount(t *testing.T) {
	messages["es"]["test.plural"] = "{logins#inicio de sesión|inicios de sesión} en la ventana"
	defer delete(messages["es"], "test.plural")

	for count, want := range map[int]string{0: "0 inicios de sesión en la ventana", 1: "1 inicio de sesión en la ventana", 3: "3 inicios de sesión en la ventana"} {
		if got := Says("test.plural", "logins", count).Render("es"); got != want {
			t.Errorf("%d: %q, want %q", count, got, want)
		}
	}
}
