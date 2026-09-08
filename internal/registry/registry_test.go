package registry

import "testing"

func TestCanonicalSources(t *testing.T) {
	for _, name := range []string{"nvd-canonical", "kevc-canonical", "osv-canonical"} {
		adapter, err := Canonical(name)
		if err != nil {
			t.Fatalf("Canonical(%q) error = %v", name, err)
		}
		if adapter == nil {
			t.Fatalf("Canonical(%q) returned nil adapter", name)
		}
	}
}

func TestCanonicalRejectsLegacyTarget(t *testing.T) {
	if _, err := Canonical("nvd"); err == nil {
		t.Fatal("Canonical(nvd) error = nil")
	}
}