package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/internal/storage"
)

type fakeAdapter struct{}

func (fakeAdapter) Name() string { return "test" }

func (fakeAdapter) Fetch(context.Context, source.State) (source.Batch, error) {
	return source.Batch{Records: []source.Record{{ID: "CVE-2026-0001", Payload: json.RawMessage(`{}`)}}, State: source.State{Cursor: "done"}}, nil
}

func (fakeAdapter) Normalize(context.Context, source.Record) ([]model.Vulnerability, error) {
	published := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return []model.Vulnerability{{
		SchemaVersion: model.SchemaVersion,
		ID:            "CVE-2026-0001",
		Published:     &published,
		Source:        model.Source{Name: "test", FetchedAt: published},
	}}, nil
}

func TestRunWritesNormalizedRecords(t *testing.T) {
	root := t.TempDir()
	state, stats, err := Run(context.Background(), fakeAdapter{}, source.State{}, storage.NewJSONWriter(root))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if state.Cursor != "done" || stats.Fetched != 1 || stats.Normalized != 1 || stats.Written != 1 {
		t.Fatalf("Run() state=%#v stats=%#v", state, stats)
	}
	if _, err := os.Stat(filepath.Join(root, "test", "2026", "CVE-2026-0001.json")); err != nil {
		t.Fatalf("canonical record was not written: %v", err)
	}
}