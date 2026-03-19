// Package fileref provides a file identity abstraction that combines
// path validation, symlink rejection, bounded read, and digest computation.
package fileref

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/limits"
	"github.com/locktivity/epack-tool-validate/internal/safefile"
)

// LocalFileRef owns the lifecycle of a local file read:
// path validation, symlink rejection, bounded read, and digest.
type LocalFileRef struct {
	Path     string // Original config path (for display/lockfile keys)
	Resolved string // Absolute path (for file ops only)
	Data     []byte // Bounded read result
	Digest   string // "sha256:<hex>" computed from Data
}

// Load validates the path, reads with bounds, and computes digest atomically.
// baseDir is the project root for containment checks.
// limit is the size cap (e.g., limits.ProfileFile).
func Load(baseDir, path string, limit limits.SizeLimit) (*LocalFileRef, error) {
	// 1. String-based containment check
	resolved, err := safefile.ValidatePath(baseDir, path)
	if err != nil {
		return nil, fmt.Errorf("path validation: %w", err)
	}

	// 2. Full path-component symlink rejection
	if _, err := safefile.ValidateRegularFile(baseDir, path); err != nil {
		return nil, fmt.Errorf("file validation: %w", err)
	}

	// 3. Race-free bounded read with O_NOFOLLOW at leaf
	data, err := safefile.ReadFile(resolved, limit)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// 4. Digest from same bytes (no separate unbounded read)
	h := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(h[:])

	return &LocalFileRef{
		Path:     path,
		Resolved: resolved,
		Data:     data,
		Digest:   digest,
	}, nil
}
