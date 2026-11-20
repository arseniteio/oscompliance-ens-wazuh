package catalog

import "testing"

func TestCategoryRank(t *testing.T) {
	for in, want := range map[string]string{"BÁSICO": "BAJO", "basico": "BAJO", "BAJO": "BAJO", " MEDIO ": "MEDIO", "ALTO": "ALTO", "": "", "OTRO": ""} {
		if got := CategoryRank(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestCategoryLabel(t *testing.T) {
	for in, want := range map[string]string{"BAJO": "BÁSICO", "BÁSICO": "BÁSICO", "MEDIO": "MEDIO", "ALTO": "ALTO", "": ""} {
		if got := CategoryLabel(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
