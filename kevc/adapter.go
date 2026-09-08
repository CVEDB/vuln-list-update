package kevc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/utils"
)

type Adapter struct {
	config Config
}

func NewAdapter(config ...Config) *Adapter {
	if len(config) == 0 {
		return &Adapter{config: NewConfig()}
	}
	return &Adapter{config: config[0]}
}

func (a *Adapter) Name() string { return "kevc" }

func (a *Adapter) Fetch(ctx context.Context, _ source.State) (source.Batch, error) {
	select {
	case <-ctx.Done():
		return source.Batch{}, ctx.Err()
	default:
	}
	payload, err := utils.FetchURL(a.config.url, "", a.config.retry)
	if err != nil {
		return source.Batch{}, fmt.Errorf("fetch KEV catalog: %w", err)
	}
	var catalog KEVC
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return source.Batch{}, fmt.Errorf("decode KEV catalog: %w", err)
	}
	if catalog.Count != len(catalog.Vulnerabilities) {
		return source.Batch{}, fmt.Errorf("KEV count mismatch: declared %d, got %d", catalog.Count, len(catalog.Vulnerabilities))
	}

	batch := source.Batch{Records: make([]source.Record, 0, len(catalog.Vulnerabilities))}
	for _, vulnerability := range catalog.Vulnerabilities {
		raw, err := json.Marshal(vulnerability)
		if err != nil {
			return source.Batch{}, fmt.Errorf("marshal KEV record %s: %w", vulnerability.CveID, err)
		}
		batch.Records = append(batch.Records, source.Record{ID: vulnerability.CveID, Payload: raw})
	}
	batch.State = source.State{Revision: catalog.CatalogVersion, LastUpdated: catalog.DateReleased}
	return batch, nil
}

func (a *Adapter) Normalize(_ context.Context, record source.Record) ([]model.Vulnerability, error) {
	var kev Vulnerability
	if err := json.Unmarshal(record.Payload, &kev); err != nil {
		return nil, fmt.Errorf("decode KEV record %s: %w", record.ID, err)
	}
	if kev.CveID == "" {
		return nil, fmt.Errorf("KEV record %s has no CVE ID", record.ID)
	}

	fetchedAt := time.Now().UTC()
	vulnerability := model.Vulnerability{
		SchemaVersion: model.SchemaVersion,
		ID:            kev.CveID,
		Summary:       kev.ShortDescription,
		Affected: []model.Affected{{
			Package: kev.Product,
		}},
		References: []model.Reference{{
			URL:  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			Type: "catalog",
		}},
		Source: model.Source{
			Name:      "kevc",
			URL:       kevcURL,
			FetchedAt: fetchedAt,
		},
		SourceData: map[string]any{
			"exploited":       true,
			"vendor_project":  kev.VendorProject,
			"vulnerability":   kev.VulnerabilityName,
			"required_action": kev.RequiredAction,
			"date_added":      kev.DateAdded,
			"due_date":        kev.DueDate,
		},
	}
	if err := vulnerability.Validate(); err != nil {
		return nil, err
	}
	return []model.Vulnerability{vulnerability}, nil
}