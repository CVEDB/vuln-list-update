package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/khulnasoft-lab/vuln-list-update/internal/model"
)

type JSONWriter struct {
	root string
}

func NewJSONWriter(root string) *JSONWriter {
	return &JSONWriter{root: root}
}

func (w *JSONWriter) Save(vulnerability model.Vulnerability) error {
	if err := vulnerability.Validate(); err != nil {
		return fmt.Errorf("validate %s: %w", vulnerability.ID, err)
	}

	year := "unknown"
	if vulnerability.Published != nil {
		year = vulnerability.Published.Format("2006")
	}
	sourceName, err := safeName(vulnerability.Source.Name)
	if err != nil {
		return fmt.Errorf("invalid source name: %w", err)
	}
	directory := filepath.Join(w.root, sourceName, year)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	payload, err := json.MarshalIndent(vulnerability, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", vulnerability.ID, err)
	}
	file, err := os.CreateTemp(directory, ".vulnerability-*.json")
	if err != nil {
		return fmt.Errorf("create temporary output for %s: %w", vulnerability.ID, err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if _, err := file.Write(payload); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", vulnerability.ID, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", vulnerability.ID, err)
	}

	identifier, err := safeName(vulnerability.ID)
	if err != nil {
		return fmt.Errorf("invalid vulnerability ID: %w", err)
	}
	fileName := identifier + ".json"
	if err := os.Rename(temporaryPath, filepath.Join(directory, fileName)); err != nil {
		return fmt.Errorf("publish %s: %w", vulnerability.ID, err)
	}
	return nil
}

func (w *JSONWriter) SaveBatch(vulnerabilities []model.Vulnerability) error {
	for _, vulnerability := range vulnerabilities {
		if err := vulnerability.Validate(); err != nil {
			return fmt.Errorf("validate %s: %w", vulnerability.ID, err)
		}
	}
	for _, vulnerability := range vulnerabilities {
		if err := w.Save(vulnerability); err != nil {
			return err
		}
	}
	return nil
}

func safeName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return "", fmt.Errorf("%q is not a safe path component", value)
	}
	return name, nil
}