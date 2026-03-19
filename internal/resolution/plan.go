// Package resolution provides profile resolution planning.
package resolution

// Plan describes what to load and verify.
type Plan struct {
	ProfilePath  string       // Single profile for MVP
	OverlayPaths []string     // Ordered overlay paths
	DigestCheck  *DigestCheck // nil if no verification needed
	Reason       string       // Why this resolution (for diagnostics)
}

// DigestCheck describes a digest verification to perform.
type DigestCheck struct {
	ExpectedDigest string // From manifest
	Source         string // Where the expectation came from
}
