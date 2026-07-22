// Package validator provides clause evaluation types.
package validator

import "github.com/locktivity/epack-tool-validate/internal/profile/compiled"

// FailureKind identifies why a clause failed.
type FailureKind int

const (
	FailureKindNone                 FailureKind = iota // Clause matched
	FailureKindNoMatch                                 // No artifact matched schema
	FailureKindFreshness                               // Artifact too old
	FailureKindFreshnessMissing                        // No CollectedAt on artifact
	FailureKindCondition                               // Condition evaluation failed
	FailureKindInsufficientEvidence                    // Referenced value absent from the artifact
)

func (k FailureKind) String() string {
	switch k {
	case FailureKindNone:
		return "none"
	case FailureKindNoMatch:
		return "no_match"
	case FailureKindFreshness:
		return "freshness"
	case FailureKindFreshnessMissing:
		return "freshness_missing"
	case FailureKindCondition:
		return "condition"
	case FailureKindInsufficientEvidence:
		return "insufficient_evidence"
	default:
		return "unknown"
	}
}

// Verdict is the three-valued outcome of evaluating a condition. A value that
// is absent (or null) cannot pass or fail a comparison: it yields
// VerdictUnknown so missing evidence is never scored as if it were observed.
type Verdict int

const (
	VerdictFalse Verdict = iota
	VerdictTrue
	VerdictUnknown
)

// ClauseOutcome is the structured result of evaluating one clause.
// Matched and Unknown are mutually exclusive; both false means the clause
// definitively did not match.
type ClauseOutcome struct {
	Matched       bool            // Did conditions definitively match?
	Unknown       bool            // Evidence absent: conditions could not be evaluated
	Severity      string          // From clause - empty means pass, present means graded failure
	ArtifactPath  string          // Which artifact was evaluated (empty if no match)
	FailureKind   FailureKind     // Why conditions didn't match
	FailureDetail string          // Human-readable detail
	Origin        compiled.Origin // Which clause this came from

	// Condition evaluation details (populated for FailureKindCondition)
	ConditionPath     string         // JSONPath of the condition that failed
	ConditionExpected *ExpectedValue // Structured expected value
	ConditionActual   any            // Actual value (typed)
	ConditionDelta    *float64       // Delta for numeric comparisons (actual - expected)
	ConditionChecks   []ConditionCheck
}
