// Package compiled defines the immutable, execution-ready profile types.
// The validator ONLY consumes these types - never raw types.
package compiled

import (
	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/ohler55/ojg/jp"
)

// ClauseMode indicates how clauses should be evaluated.
type ClauseMode int

const (
	ClauseModeAny ClauseMode = iota // any_of: first matching clause wins
	ClauseModeAll                   // all_of: all clauses must match
)

func (m ClauseMode) String() string {
	switch m {
	case ClauseModeAny:
		return "any_of"
	case ClauseModeAll:
		return "all_of"
	default:
		return "unknown"
	}
}

// CompiledProfile is the immutable, execution-ready form of a profile.
type CompiledProfile struct {
	ID           string
	Name         string
	Version      string
	Requirements []CompiledRequirement
}

// CompiledRequirement is a single requirement ready for evaluation.
type CompiledRequirement struct {
	ID       string
	Control  string
	Name     string
	Category string
	Mode     ClauseMode // Normalized - no any_of/all_of branching needed
	Clauses  []CompiledClause
}

// CompiledClause is a single satisfaction clause ready for evaluation.
type CompiledClause struct {
	Schema     string              // Artifact schema to match (e.g., "evidencepack/idp-posture@v1")
	Severity   string              // "critical" | "high" | "medium" | "low" OR empty = pass
	MaxAgeDays *int                // nil = no freshness check
	Conditions []CompiledCondition // Pre-validated conditions
	Origin     Origin              // For diagnostics
}

// Cardinality specifies how multi-value JSONPath results should be evaluated.
type Cardinality int

const (
	CardinalitySingle Cardinality = iota // Default: path must return single value
	CardinalityAll                       // All values must satisfy condition
	CardinalityAny                       // At least one value must satisfy
	CardinalityNone                      // No value should satisfy (all must fail)
)

func (c Cardinality) String() string {
	switch c {
	case CardinalitySingle:
		return "single"
	case CardinalityAll:
		return "all"
	case CardinalityAny:
		return "any"
	case CardinalityNone:
		return "none"
	default:
		return "unknown"
	}
}

// ValidCardinalities are the allowed cardinality values.
var ValidCardinalities = map[string]Cardinality{
	"":       CardinalitySingle, // empty = single (default)
	"single": CardinalitySingle,
	"all":    CardinalityAll,
	"any":    CardinalityAny,
	"none":   CardinalityNone,
}

// CompiledCondition is a single condition ready for evaluation.
type CompiledCondition struct {
	Path        string             // Original path for error messages
	Expr        jp.Expr            // Pre-parsed JSONPath
	BaseExpr    jp.Expr            // Base array path for element count checks (cardinality:all, exists, not_exists)
	Op          condition.Operator // Enum - validator just calls Apply()
	Expected    any                // Value to compare against
	Cardinality Cardinality        // How to handle multi-value results
	IsMulti     bool               // True if path may return multiple values
}

// Origin tracks where a clause came from for diagnostics.
type Origin struct {
	RequirementID string
	ClauseIndex   int
	SourceFile    string // Which profile/overlay this came from
}

// ValidSeverities are the allowed severity values for clauses.
var ValidSeverities = map[string]bool{
	"":         true, // empty = pass
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// SeverityOrder defines severity ranking (higher index = more severe).
var SeverityOrder = map[string]int{
	"":         0, // pass has no severity
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// MaxSeverity returns the more severe of two severity strings.
func MaxSeverity(a, b string) string {
	if SeverityOrder[a] >= SeverityOrder[b] {
		return a
	}
	return b
}
