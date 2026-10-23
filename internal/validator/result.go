// Package validator provides result types for validation output.
package validator

// Result is the overall validation result.
type Result struct {
	Status           string                            `json:"status"` // "pass" | "fail" | "unknown"; manual and not_applicable requirements never change it
	Profile          ProfileInfo                       `json:"profile"`
	ValidatedAt      string                            `json:"validated_at"`       // RFC3339
	ValidatedAtLabel string                            `json:"validated_at_label"` // "just now", etc.
	PackDigest       string                            `json:"pack_digest"`
	Summary          Summary                           `json:"summary"`
	Requirements     []RequirementResult               `json:"requirements"`
	KeyFailures      []KeyFailure                      `json:"key_failures,omitempty"`
	ByCategory       map[string]CategorySummary        `json:"by_category,omitempty"`
	AssertedSupport  map[string][]AssertedSupportEntry `json:"asserted_support,omitempty"`
	Warnings         []WarningResult                   `json:"warnings,omitempty"`
}

// ProfileInfo describes the validated profile.
type ProfileInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

// Summary provides aggregate counts. Unknown counts requirements whose
// evidence was absent: they are neither passed nor failed. Manual counts
// requirements answered by asserted support and human review, and
// NotApplicable counts requirements no clause applied to. Neither is scored,
// so Total minus Manual minus NotApplicable is the machine-checked
// denominator.
type Summary struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Missing       int `json:"missing"`
	Unknown       int `json:"unknown"`
	Manual        int `json:"manual,omitempty"`
	NotApplicable int `json:"not_applicable,omitempty"`
	Warnings      int `json:"warnings"`
}

// CategorySummary provides per-category counts.
type CategorySummary struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Missing       int `json:"missing"`
	Unknown       int `json:"unknown"`
	Manual        int `json:"manual,omitempty"`
	NotApplicable int `json:"not_applicable,omitempty"`
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
	Description string         `json:"description,omitempty"`
	Category    string         `json:"category,omitempty"`
	Severity    string         `json:"severity,omitempty"`     // "critical" | "high" | "medium" | "low"
	Status      string         `json:"status"`                 // "pass" | "fail" | "unknown" | "manual" | "not_applicable"
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
	ClauseIndex    int              `json:"clause_index"`
	Schema         string           `json:"schema"`
	Status         string           `json:"status"` // "pass" | "fail" | "unknown" | "missing" | "stale" | "freshness_missing" | "not_applicable"
	Severity       string           `json:"severity,omitempty"`
	Selected       bool             `json:"selected,omitempty"` // True if this check determined the requirement's outcome
	Artifact       string           `json:"artifact,omitempty"`
	Message        string           `json:"message,omitempty"`
	ApplicableWhen *ApplicableWhen  `json:"applicable_when,omitempty"`
	Conditions     []ConditionCheck `json:"conditions,omitempty"`
}

// ApplicableWhen reports how a check's applicable_when was decided, on the
// artifact that decided the check. Conditions lists every gate condition in
// profile order. Skipped and Evaluated count list elements and appear only
// when the gate has cardinality each conditions.
type ApplicableWhen struct {
	Type       string           `json:"type"`
	Conditions []ConditionCheck `json:"conditions,omitempty"`
	Skipped    *int             `json:"skipped,omitempty"`
	Evaluated  *int             `json:"evaluated,omitempty"`
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

// WarningResult is a non-fatal issue noted during validation. Warnings never
// affect Status or any requirement outcome.
type WarningResult struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"` // Artifact path the warning concerns
}

// AssertedSupportEntry echoes one control mapping entry
// (evidencepack/control-mapping@v1) joined to a requirement of the validated
// profile. Asserted support is publisher-authored and reporting-only: it never
// changes any requirement outcome or the overall status.
type AssertedSupportEntry struct {
	Requirement   string           `json:"requirement,omitempty"`    // Join claimed by the entry: requirement id
	Control       string           `json:"control,omitempty"`        // Join claimed by the entry: control identifier
	Type          string           `json:"type,omitempty"`           // Join claimed by the entry: artifact schema
	RequirementID string           `json:"requirement_id,omitempty"` // Joined requirement's id in this profile (absent if the join matched nothing)
	Evidence      *SupportEvidence `json:"evidence,omitempty"`
	Label         string           `json:"label,omitempty"`
	Note          string           `json:"note,omitempty"`
	MappedAt      string           `json:"mapped_at,omitempty"`
	MappedBy      string           `json:"mapped_by,omitempty"`
	Resolution    string           `json:"resolution"`       // "resolved" | "document_only" | "unresolved"
	Value         any              `json:"value,omitempty"`  // Cited value when a pointer resolved to a scalar
	Stale         bool             `json:"stale,omitempty"`  // Mapping's profile digest differs from the profile validated
	Source        string           `json:"source,omitempty"` // Mapping artifact path in the pack
}

// SupportEvidence echoes a mapping entry's evidence reference.
type SupportEvidence struct {
	Artifact     string               `json:"artifact,omitempty"`
	Pointer      string               `json:"pointer,omitempty"`
	DocumentID   string               `json:"document_id,omitempty"`
	Quote        *SupportQuote        `json:"quote,omitempty"`
	TextPosition *SupportTextPosition `json:"text_position,omitempty"`
	Table        *SupportTable        `json:"table,omitempty"`
}

// SupportQuote echoes a quote anchor.
type SupportQuote struct {
	Exact  string `json:"exact"`
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
}

// SupportTextPosition echoes a byte-offset anchor into a document's extracted text.
type SupportTextPosition struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// SupportTable echoes a table anchor.
type SupportTable struct {
	Sheet   string         `json:"sheet,omitempty"`
	Where   map[string]any `json:"where,omitempty"`
	Columns []string       `json:"columns,omitempty"`
	Range   string         `json:"range,omitempty"`
}
