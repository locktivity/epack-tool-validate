// Package limits defines resource bounds for parsing and validation.
package limits

import "os"

// SizeLimit is a typed size limit for parsing operations.
type SizeLimit int64

// Bytes returns the limit as an int64.
func (s SizeLimit) Bytes() int64 {
	return int64(s)
}

// Size limit constants.
var (
	// ProfileFile is the limit for profile YAML files (1 MB).
	ProfileFile SizeLimit = 1 * 1024 * 1024

	// OverlayFile is the limit for overlay YAML files (1 MB).
	OverlayFile SizeLimit = 1 * 1024 * 1024
)

// File permission constants.
const (
	StandardDirMode  os.FileMode = 0755
	StandardFileMode os.FileMode = 0644
)

// Recursion and alias limits for DoS prevention.
const (
	MaxRecursionDepth     = 100
	MaxYAMLAliasExpansion = 10
)

// RecursionGuard prevents stack overflow from deep recursion.
type RecursionGuard struct {
	depth    int
	maxDepth int
}

// NewRecursionGuard creates a guard with the specified max depth.
func NewRecursionGuard(maxDepth int) *RecursionGuard {
	return &RecursionGuard{maxDepth: maxDepth}
}

// Enter increments depth and returns error if max exceeded.
func (g *RecursionGuard) Enter() error {
	if g.depth >= g.maxDepth {
		return &ErrRecursionLimitExceeded{Depth: g.depth + 1, MaxDepth: g.maxDepth}
	}
	g.depth++
	return nil
}

// Leave decrements depth.
func (g *RecursionGuard) Leave() {
	if g.depth > 0 {
		g.depth--
	}
}

// ErrRecursionLimitExceeded is returned when recursion depth exceeds the limit.
type ErrRecursionLimitExceeded struct {
	Depth    int
	MaxDepth int
}

func (e *ErrRecursionLimitExceeded) Error() string {
	return "recursion depth exceeded"
}
