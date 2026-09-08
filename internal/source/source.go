package source

import (
	"context"
	"encoding/json"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
)

type State struct {
	Cursor       string    `json:"cursor,omitempty"`
	LastUpdated  time.Time `json:"last_updated,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Revision     string    `json:"revision,omitempty"`
}

type Record struct {
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

type Batch struct {
	Records []Record
	State   State
}

// Adapter separates source-specific retrieval and normalization from storage.
type Adapter interface {
	Name() string
	Fetch(context.Context, State) (Batch, error)
	Normalize(context.Context, Record) ([]model.Vulnerability, error)
}
