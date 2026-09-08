package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/utils"
)

type Adapter struct {
	url         string
	ecosystems  map[string]string
}

func NewAdapter() *Adapter {
	return &Adapter{
		url: securityTrackerURL,
		ecosystems: defaultEcosystemDirs,
	}
}

func (a *Adapter) Name() string { return "osv" }

func (a *Adapter) Fetch(ctx context.Context, _ source.State) (source.Batch, error) {
	batch := source.Batch{Records: make([]source.Record, 0)}
	for ecosystem := range a.ecosystems {
		select {
		case <-ctx.Done():
			return source.Batch{}, ctx.Err()
		default:
		}
		archive, err := utils.DownloadToTempDir(ctx, fmt.Sprintf(a.url, ecosystem))
		if err != nil {
			return source.Batch{}, fmt.Errorf("download OSV %s: %w", ecosystem, err)
		}
		defer os.RemoveAll(archive)
		err = filepath.WalkDir(archive, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var advisory OSV
			if err := json.Unmarshal(payload, &advisory); err != nil {
				return fmt.Errorf("decode %s: %w", path, err)
			}
			if advisory.ID == "" {
				return fmt.Errorf("OSV file %s has no ID", path)
			}
			batch.Records = append(batch.Records, source.Record{ID: advisory.ID, Payload: payload})
			return nil
		})
		if err != nil {
			return source.Batch{}, fmt.Errorf("walk OSV %s: %w", ecosystem, err)
		}
	}
	batch.State = source.State{LastUpdated: time.Now().UTC()}
	return batch, nil
}

func (a *Adapter) Normalize(_ context.Context, record source.Record) ([]model.Vulnerability, error) {
	var advisory OSV
	if err := json.Unmarshal(record.Payload, &advisory); err != nil {
		return nil, fmt.Errorf("decode OSV record %s: %w", record.ID, err)
	}
	if advisory.ID == "" {
		return nil, fmt.Errorf("OSV record %s has no ID", record.ID)
	}
	vulnerability := model.Vulnerability{
		SchemaVersion: model.SchemaVersion,
		ID:            advisory.ID,
		Aliases:       append([]string(nil), advisory.Aliases...),
		Summary:       advisory.Summary,
		Details:       advisory.Details,
		References:    make([]model.Reference, 0, len(advisory.References)),
		Source:        model.Source{Name: "osv", URL: "https://osv.dev/list", FetchedAt: time.Now().UTC()},
	}
	if published, err := time.Parse(time.RFC3339, advisory.Published); err == nil {
		vulnerability.Published = &published
	}
	if modified, err := time.Parse(time.RFC3339, advisory.Modified); err == nil {
		vulnerability.Modified = &modified
	}
	if withdrawn, err := time.Parse(time.RFC3339, advisory.Withdrawn); err == nil {
		vulnerability.Withdrawn = &withdrawn
	}
	for _, reference := range advisory.References {
		vulnerability.References = append(vulnerability.References, model.Reference{URL: reference.Url, Type: reference.Type})
	}
	for _, affected := range advisory.Affected {
		canonical := model.Affected{Ecosystem: affected.Package.Ecosystem, Package: affected.Package.Name, Ranges: make([]model.VersionRange, 0, len(affected.Ranges))}
		for _, advisoryRange := range affected.Ranges {
			versionRange := model.VersionRange{Type: advisoryRange.Type}
			for _, event := range advisoryRange.Events {
				versionRange.Events = append(versionRange.Events, model.Event{Introduced: event.Introduced, Fixed: event.Fixed, LastAffected: event.LastAffected})
				if event.Fixed != "" {
					canonical.FixedVersions = append(canonical.FixedVersions, event.Fixed)
				}
			}
			canonical.Ranges = append(canonical.Ranges, versionRange)
		}
		vulnerability.Affected = append(vulnerability.Affected, canonical)
		for _, severity := range affected.Severities {
			vulnerability.Severity = append(vulnerability.Severity, model.Severity{Type: severity.Type, Score: severity.Score})
		}
	}
	if err := vulnerability.Validate(); err != nil {
		return nil, err
	}
	return []model.Vulnerability{vulnerability}, nil
}