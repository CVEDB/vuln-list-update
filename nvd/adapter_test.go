package nvd_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/nvd"
)

func TestAdapterNormalizesCVE(t *testing.T) {
	payload := []byte(`{"id":"CVE-2026-0001","published":"2026-01-01T00:00:00.000Z","lastModified":"2026-01-02T00:00:00.000Z","descriptions":[{"lang":"en","value":"Example vulnerability"}],"references":[{"url":"https://example.test/advisory","source":"Example"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"vectorString":"CVSS:3.1/AV:N"}}]}}`)
	adapter := nvd.NewAdapter(nil)
	result, err := adapter.Normalize(context.Background(), source.Record{ID: "CVE-2026-0001", Payload: json.RawMessage(payload)})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(result) != 1 || result[0].ID != "CVE-2026-0001" {
		t.Fatalf("Normalize() = %#v", result)
	}
	if result[0].Summary != "Example vulnerability" || len(result[0].Severity) != 1 {
		t.Fatalf("Normalize() lost CVE fields: %#v", result[0])
	}
}
