package pipeline

import (
	"context"
	"fmt"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
	"github.com/khulnasoft-lab/vuln-list-update/internal/source"
	"github.com/khulnasoft-lab/vuln-list-update/internal/storage"
)

type Stats struct {
	Fetched    int
	Normalized int
	Written    int
}

func Run(ctx context.Context, adapter source.Adapter, state source.State, writer *storage.JSONWriter) (source.State, Stats, error) {
	if adapter == nil {
		return state, Stats{}, fmt.Errorf("source adapter is nil")
	}
	if writer == nil {
		return state, Stats{}, fmt.Errorf("JSON writer is nil")
	}

	batch, err := adapter.Fetch(ctx, state)
	if err != nil {
		return state, Stats{}, fmt.Errorf("fetch %s: %w", adapter.Name(), err)
	}
	stats := Stats{Fetched: len(batch.Records)}
	normalized := make([]model.Vulnerability, 0)
	for _, record := range batch.Records {
		select {
		case <-ctx.Done():
			return state, stats, ctx.Err()
		default:
		}
		vulnerabilities, err := adapter.Normalize(ctx, record)
		if err != nil {
			return state, stats, fmt.Errorf("normalize %s record %s: %w", adapter.Name(), record.ID, err)
		}
		stats.Normalized += len(vulnerabilities)
		normalized = append(normalized, vulnerabilities...)
	}
	if err := writer.SaveBatch(normalized); err != nil {
		return state, stats, fmt.Errorf("write %s batch: %w", adapter.Name(), err)
	}
	stats.Written = len(normalized)
	return batch.State, stats, nil
}