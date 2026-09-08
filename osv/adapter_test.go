package osv_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/osv"
)

func TestAdapterNormalizesOSVAdvisory(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"id": "GO-2026-0001", "aliases": []string{"CVE-2026-0003"}, "summary": "Example issue",
		"affected": []any{map[string]any{
			"package": map[string]string{"ecosystem": "Go", "name": "example.com/project"},
			"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": "1.2.3"}}}},
		}},
		"references": []any{map[string]string{"type": "WEB", "url": "https://example.test/advisory"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := osv.NewAdapter().Normalize(context.Background(), source.Record{ID: "GO-2026-0001", Payload: payload})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(result) != 1 || result[0].Aliases[0] != "CVE-2026-0003" || result[0].Affected[0].FixedVersions[0] != "1.2.3" {
		t.Fatalf("Normalize() lost OSV data: %#v", result)
	}
}