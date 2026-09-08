package source

import (
	"context"
	"testing"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
)

type testAdapter struct{ name string }

func (a testAdapter) Name() string { return a.name }

func (testAdapter) Fetch(context.Context, State) (Batch, error) { return Batch{}, nil }

func (testAdapter) Normalize(context.Context, Record) ([]model.Vulnerability, error) {
	return nil, nil
}

func TestRegistryNamesAreStable(t *testing.T) {
	registry, err := NewRegistry(testAdapter{name: "zeta"}, testAdapter{name: "alpha"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	want := []string{"alpha", "zeta"}
	got := registry.Names()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
}

func TestRegistryRejectsDuplicateNames(t *testing.T) {
	if _, err := NewRegistry(testAdapter{name: "nvd"}, testAdapter{name: "nvd"}); err == nil {
		t.Fatal("NewRegistry() error = nil, want duplicate name error")
	}
}
