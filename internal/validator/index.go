// Package validator provides pack indexing for efficient validation.
package validator

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// PackIndex provides efficient artifact lookup by schema.
type PackIndex struct {
	BySchema   map[string][]IndexedArtifact
	PackDigest string
}

// IndexedArtifact is an artifact with pre-parsed body and timestamp.
type IndexedArtifact struct {
	Path        string
	Schema      string
	CollectedAt *time.Time // nil if not present in manifest
	Body        any        // Decoded JSON
}

// BuildPackIndex indexes all artifacts in the pack for efficient lookup.
func BuildPackIndex(pack *componentsdk.Pack) (*PackIndex, error) {
	index := &PackIndex{
		BySchema:   make(map[string][]IndexedArtifact),
		PackDigest: pack.Manifest().PackDigest,
	}

	for _, artifact := range pack.Artifacts() {
		// Skip artifacts without schema (cannot match any clause)
		if artifact.Schema == "" {
			continue
		}

		// Read artifact content
		data, err := pack.ReadArtifact(artifact.Path)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		// Decode JSON body - schema-bearing artifacts must have valid JSON
		var body any
		if err := json.Unmarshal(data, &body); err != nil {
			return nil, fmt.Errorf("artifact %s has schema %s but invalid JSON: %w", artifact.Path, artifact.Schema, err)
		}

		// Parse CollectedAt if present - malformed timestamp is an error
		var collectedAt *time.Time
		if artifact.CollectedAt != "" {
			t, err := time.Parse(time.RFC3339, artifact.CollectedAt)
			if err != nil {
				return nil, fmt.Errorf("artifact %s has malformed collected_at timestamp %q: %w", artifact.Path, artifact.CollectedAt, err)
			}
			collectedAt = &t
		}

		indexed := IndexedArtifact{
			Path:        artifact.Path,
			Schema:      artifact.Schema,
			CollectedAt: collectedAt,
			Body:        body,
		}

		index.BySchema[artifact.Schema] = append(index.BySchema[artifact.Schema], indexed)
	}

	return index, nil
}
