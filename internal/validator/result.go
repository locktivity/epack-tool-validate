// Package validator provides result types for validation output.
package validator

// Result is the overall validation result.
type Result struct {
	Status           string                     `json:"status"` // "pass" | "fail"
	Profile          ProfileInfo                `json:"profile"`
	ValidatedAt      string                     `json:"validated_at"`       // RFC3339
	ValidatedAtLabel string                     `json:"validated_at_label"` // "just now", etc.
	PackDigest       string                     `json:"pack_digest"`
	Summary          Summary                    `json:"summary"`
	Requirements     []RequirementResult        `json:"requirements"`
	KeyFailures      []KeyFailure               `json:"key_failures,omitempty"`
	ByCategory       map[string]CategorySummary `json:"by_category,omitempty"`
}

// ProfileInfo describes the validated profile.
type ProfileInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

// Summary provides aggregate counts.
type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
}

// CategorySummary provides per-category counts.
type CategorySummary struct {
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// KeyFailure identifies a notable failure.
type KeyFailure struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// RequirementResult is the result for a single requirement.
type RequirementResult struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Control  string         `json:"control,omitempty"`
	Category string         `json:"category,omitempty"`
	Severity string         `json:"severity,omitempty"` // "critical" | "high" | "medium" | "low"
	Status   string         `json:"status"`             // "pass" | "fail"
	Expected *ExpectedValue `json:"expected,omitempty"` // Structured expected value
	Actual   any            `json:"actual,omitempty"`   // Actual value (typed)
	Delta    *float64       `json:"delta,omitempty"`    // For numeric comparisons
	Message  string         `json:"message,omitempty"`  // Human-readable detail
	Artifact string         `json:"artifact,omitempty"` // Path to artifact evaluated
	Path     string         `json:"path,omitempty"`     // JSONPath checked
}

// ExpectedValue represents a structured expected value with operator context.
type ExpectedValue struct {
	Op    string `json:"op"`              // Operator: "eq", "neq", "gt", "gte", "lt", "lte", "exists", "not_exists"
	Value any    `json:"value,omitempty"` // Expected value (omitted for exists/not_exists)
}
