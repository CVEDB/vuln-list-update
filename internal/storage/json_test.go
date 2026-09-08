package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
)

func validVulnerability() model.Vulnerability {
	published := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return model.Vulnerability{
		SchemaVersion: model.SchemaVersion,
		ID:            "CVE-2026-0001",
		Published:     &published,
		Source: model.Source{
			Name:      "nvd",
			FetchedAt: published,
		},
	}
}

func TestJSONWriterSaveCreatesCanonicalDocument(t *testing.T) {
	root := t.TempDir()
	if err := NewJSONWriter(root).Save(validVulnerability()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path := filepath.Join(root, "nvd", "2026", "CVE-2026-0001.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var got model.Vulnerability
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.ID != "CVE-2026-0001" || got.SchemaVersion != model.SchemaVersion {
		t.Fatalf("saved vulnerability = %#v", got)
	}
}

func TestJSONWriterRejectsUnsafePathComponents(t *testing.T) {
	tests := []model.Vulnerability{
		func() model.Vulnerability {
			vulnerability := validVulnerability()
			vulnerability.Source.Name = "../outside"
			return vulnerability
		}(),
		func() model.Vulnerability {
			vulnerability := validVulnerability()
			vulnerability.ID = "../outside"
			return vulnerability
		}(),
	}

	for _, vulnerability := range tests {
		if err := NewJSONWriter(t.TempDir()).Save(vulnerability); err == nil {
			t.Fatalf("Save(%q) error = nil, want unsafe path error", vulnerability.ID)
		}
	}
}
