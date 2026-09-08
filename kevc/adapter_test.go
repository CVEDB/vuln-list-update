package kevc_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/kevc"
)

func TestAdapterNormalizesKnownExploitedVulnerability(t *testing.T) {
	payload, err := json.Marshal(map[string]string{
		"cveID": "CVE-2026-0002", "vendorProject": "Example", "product": "Example Server",
		"shortDescription": "An exploited vulnerability", "requiredAction": "Apply the vendor fix",
		"dateAdded": "2026-01-02", "dueDate": "2026-01-23",
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := kevc.NewAdapter().Normalize(context.Background(), source.Record{ID: "CVE-2026-0002", Payload: payload})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(result) != 1 || result[0].ID != "CVE-2026-0002" {
		t.Fatalf("Normalize() = %#v", result)
	}
	if result[0].SourceData["exploited"] != true || result[0].Affected[0].Package != "Example Server" {
		t.Fatalf("Normalize() lost KEV metadata: %#v", result[0])
	}
}