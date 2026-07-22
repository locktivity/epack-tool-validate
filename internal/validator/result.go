// Package validator provides result types for validation output.
package validator

// Result is the overall validation result.
type Result struct {
	Status           string                     `json:"status"` // "pass" | "fail" | "unknown"
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

// Summary provides aggregate counts. Unknown counts requirements whose
// evidence was absent: they are neither passed nor failed.
type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Missing  int `json:"missing"`
	Unknown  int `json:"unknown"`
	Warnings int `json:"warnings"`
}

// CategorySummary provides per-category counts.
type CategorySummary struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Missing int `json:"missing"`
	Unknown int `json:"unknown"`
}

// KeyFailure identifies a notable failure.
type KeyFailure struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// RequirementResult is the result for a single requirement.
type RequirementResult struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Control     string         `json:"control,omitempty"`
	Category    string         `json:"category,omitempty"`
	Severity    string         `json:"severity,omitempty"`     // "critical" | "high" | "medium" | "low"
	Status      string         `json:"status"`                 // "pass" | "fail" | "unknown"
	FailureKind string         `json:"failure_kind,omitempty"` // "missing" | "stale" | "freshness_missing" | "condition" | "insufficient_evidence"
	Mode        string         `json:"mode,omitempty"`         // "any_of" | "all_of" - how clauses are evaluated
	Expected    *ExpectedValue `json:"expected,omitempty"`     // Structured expected value
	Actual      any            `json:"actual,omitempty"`       // Actual value (typed)
	Delta       *float64       `json:"delta,omitempty"`        // For numeric comparisons
	Message     string         `json:"message,omitempty"`      // Human-readable detail
	Artifact    string         `json:"artifact,omitempty"`     // Path to artifact evaluated
	Path        string         `json:"path,omitempty"`         // JSONPath checked
	Checks      []CheckResult  `json:"checks,omitempty"`
}

// CheckResult describes how one clause was evaluated.
type CheckResult struct {
	ClauseIndex int              `json:"clause_index"`
	Schema      string           `json:"schema"`
	Status      string           `json:"status"` // "pass" | "fail" | "unknown" | "missing" | "stale" | "freshness_missing"
	Severity    string           `json:"severity,omitempty"`
	Selected    bool             `json:"selected,omitempty"` // True if this check determined the requirement's outcome
	Artifact    string           `json:"artifact,omitempty"`
	Message     string           `json:"message,omitempty"`
	Conditions  []ConditionCheck `json:"conditions,omitempty"`
}

// ConditionCheck captures the result of one evaluated condition. Unknown true
// means the referenced value was absent so the condition could not be scored;
// Passed is false in that case but does not mean the condition failed.
type ConditionCheck struct {
	Path     string         `json:"path,omitempty"`
	Expected *ExpectedValue `json:"expected,omitempty"`
	Actual   any            `json:"actual,omitempty"`
	Delta    *float64       `json:"delta,omitempty"`
	Passed   bool           `json:"passed"`
	Unknown  bool           `json:"unknown,omitempty"`
}

// ExpectedValue represents a structured expected value with operator context.
type ExpectedValue struct {
	Op    string `json:"op"`              // Operator: "eq", "neq", "gt", "gte", "lt", "lte", "exists", "not_exists", "max_age_days"
	Value any    `json:"value,omitempty"` // Expected value (omitted for exists/not_exists)
}
