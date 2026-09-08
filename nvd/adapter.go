package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/utils"
)

// Adapter exposes NVD through the shared source lifecycle while the legacy
// updater continues to own file publication.
type Adapter struct {
	updater *Updater
}

func NewAdapter(updater *Updater) *Adapter {
	if updater == nil {
		updater = NewUpdater()
	}
	return &Adapter{updater: updater}
}

func (a *Adapter) Name() string { return "nvd" }

func (a *Adapter) Fetch(ctx context.Context, state source.State) (source.Batch, error) {
	lastUpdated := state.LastUpdated
	if lastUpdated.IsZero() {
		var err error
		lastUpdated, err = utils.GetLastUpdatedDate(apiDir)
		if err != nil {
			return source.Batch{}, fmt.Errorf("read NVD checkpoint: %w", err)
		}
	}

	endTime := time.Now().UTC()
	intervals := timeIntervals(lastUpdated, endTime)
	batch := source.Batch{Records: make([]source.Record, 0)}
	for _, interval := range intervals {
		for startIndex, totalResults := 0, 1; startIndex < totalResults; startIndex += a.updater.maxResultsPerPage {
			select {
			case <-ctx.Done():
				return source.Batch{}, ctx.Err()
			default:
			}

			entryURL, err := urlWithParams(a.updater.baseURL, startIndex, a.updater.maxResultsPerPage, interval)
			if err != nil {
				return source.Batch{}, fmt.Errorf("build NVD URL: %w", err)
			}
			entry, err := a.updater.fetchEntry(entryURL)
			if err != nil {
				return source.Batch{}, fmt.Errorf("fetch NVD page: %w", err)
			}
			totalResults = entry.TotalResults
			for _, vulnerability := range entry.Vulnerabilities {
				payload, err := json.Marshal(vulnerability.Cve)
				if err != nil {
					return source.Batch{}, fmt.Errorf("marshal %s: %w", vulnerability.Cve.ID, err)
				}
				batch.Records = append(batch.Records, source.Record{ID: vulnerability.Cve.ID, Payload: payload})
			}
		}
	}
	batch.State = source.State{LastUpdated: endTime, Revision: endTime.Format(time.RFC3339)}
	return batch, nil
}

func (a *Adapter) Normalize(_ context.Context, record source.Record) ([]model.Vulnerability, error) {
	var cve Cve
	if err := json.Unmarshal(record.Payload, &cve); err != nil {
		return nil, fmt.Errorf("decode NVD record %s: %w", record.ID, err)
	}
	if cve.ID == "" {
		return nil, fmt.Errorf("NVD record %s has no ID", record.ID)
	}

	vulnerability := model.Vulnerability{
		SchemaVersion: model.SchemaVersion,
		ID:            cve.ID,
		Summary:       englishDescription(cve.Descriptions),
		References:    make([]model.Reference, 0, len(cve.References)),
		Source: model.Source{
			Name:      "nvd",
			URL:       "https://nvd.nist.gov/vuln/detail/" + cve.ID,
			FetchedAt: time.Now().UTC(),
		},
		SourceData: map[string]any{"source_identifier": cve.SourceIdentifier},
	}

	if published, err := time.Parse(time.RFC3339, cve.Published); err == nil {
		vulnerability.Published = &published
	}
	if modified, err := time.Parse(time.RFC3339, cve.LastModified); err == nil {
		vulnerability.Modified = &modified
	}
	for _, reference := range cve.References {
		vulnerability.References = append(vulnerability.References, model.Reference{URL: reference.URL, Type: reference.Source})
	}
	for _, metric := range cve.Metrics.CvssMetricV40 {
		vulnerability.Severity = append(vulnerability.Severity, model.Severity{Type: "CVSS-4.0", Score: strconv.FormatFloat(metric.CVSSData.BaseScore, 'f', -1, 64), Vector: metric.CVSSData.VectorString})
	}
	for _, metric := range cve.Metrics.CvssMetricV31 {
		vulnerability.Severity = append(vulnerability.Severity, model.Severity{Type: "CVSS-3.1", Score: strconv.FormatFloat(metric.CvssData.BaseScore, 'f', -1, 64), Vector: metric.CvssData.VectorString})
	}
	if err := vulnerability.Validate(); err != nil {
		return nil, err
	}
	return []model.Vulnerability{vulnerability}, nil
}

func englishDescription(descriptions []LangString) string {
	for _, description := range descriptions {
		if description.Lang == "en" {
			return description.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}
