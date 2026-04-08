// Package validator provides the core validation logic.
package validator

import (
	"fmt"
	"time"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
)

// Validator evaluates compiled profiles against pack indexes.
type Validator struct{}

// New creates a new validator.
func New() *Validator {
	return &Validator{}
}

// Validate evaluates a compiled profile against a pack index.
func (v *Validator) Validate(ctx *Context, profile *compiled.CompiledProfile, pack *PackIndex, profileDigest string) *Result {
	now := ctx.Now()

	result := &Result{
		Status: "pass",
		Profile: ProfileInfo{
			ID:      profile.ID,
			Name:    profile.Name,
			Version: profile.Version,
			Digest:  profileDigest,
		},
		ValidatedAt:      now.Format(time.RFC3339),
		ValidatedAtLabel: "just now",
		PackDigest:       pack.PackDigest,
		Summary:          Summary{Total: len(profile.Requirements)},
		ByCategory:       make(map[string]CategorySummary),
	}

	for _, req := range profile.Requirements {
		reqResult := v.evaluateRequirement(ctx, &req, pack)
		result.Requirements = append(result.Requirements, reqResult)

		// Update summary
		if reqResult.Status == "pass" {
			result.Summary.Passed++
		} else {
			result.Status = "fail"
			if reqResult.FailureKind == "missing" {
				result.Summary.Missing++
			} else {
				result.Summary.Failed++
			}

			// Track key failures
			if reqResult.Severity == "critical" || reqResult.Severity == "high" {
				result.KeyFailures = append(result.KeyFailures, KeyFailure{
					ID:       reqResult.ID,
					Name:     reqResult.Name,
					Severity: reqResult.Severity,
				})
			}
		}

		// Update category summary
		if req.Category != "" {
			cat := result.ByCategory[req.Category]
			if reqResult.Status == "pass" {
				cat.Passed++
			} else if reqResult.FailureKind == "missing" {
				cat.Missing++
			} else {
				cat.Failed++
			}
			result.ByCategory[req.Category] = cat
		}
	}

	return result
}

func (v *Validator) evaluateRequirement(ctx *Context, req *compiled.CompiledRequirement, pack *PackIndex) RequirementResult {
	result := RequirementResult{
		ID:       req.ID,
		Name:     req.Name,
		Control:  req.Control,
		Category: req.Category,
	}

	// Evaluate all clauses
	outcomes := make([]ClauseOutcome, len(req.Clauses))
	for i, clause := range req.Clauses {
		artifacts := pack.BySchema[clause.Schema]
		outcomes[i] = v.evaluateClause(ctx, &clause, artifacts)
	}
	result.Checks = buildCheckResults(req, outcomes)

	switch req.Mode {
	case compiled.ClauseModeAny:
		// For graduated failures, we want to show the "pass" threshold (first clause)
		// rather than the matched fallback clause. Capture first clause's details.
		var firstClauseDetails *ClauseOutcome
		var firstClauseCondCount int
		if len(outcomes) > 0 && outcomes[0].ConditionPath != "" {
			firstClauseDetails = &outcomes[0]
			firstClauseCondCount = len(req.Clauses[0].Conditions)
		}

		// First matching clause wins - its severity determines outcome
		for i, o := range outcomes {
			if o.Matched {
				if o.Severity == "" {
					// No severity = requirement PASSES
					result.Status = "pass"
					populatePassDetailsFromOutcome(&result, o)
					return result
				}
				// Has severity = requirement FAILS with that severity
				// This is a graduated failure - show what's needed to fully pass
				result.Status = "fail"
				result.Severity = o.Severity
				result.Artifact = o.ArtifactPath

				// For graduated failures (not the first clause), show the first clause's
				// failure details so users see what they need to achieve for full compliance.
				// The first clause's failing condition shows the gap to full pass.
				matchedClauseCondCount := len(req.Clauses[i].Conditions)
				canUseFirstClause := i > 0 &&
					firstClauseDetails != nil &&
					firstClauseDetails.ConditionExpected != nil &&
					!firstClauseDetails.Matched // First clause must have failed (has meaningful failure details)

				// For single-condition clauses, both paths are reliable - require match
				// For multi-condition clauses, first clause's path is from the failing condition (reliable)
				// while matched clause's path is from the first condition (not necessarily the relevant one)
				if canUseFirstClause && firstClauseCondCount == 1 && matchedClauseCondCount == 1 {
					canUseFirstClause = firstClauseDetails.ConditionPath == o.ConditionPath
				}

				if canUseFirstClause {
					// Use first clause's failure details entirely (path, expected, actual, delta)
					result.Path = firstClauseDetails.ConditionPath
					result.Expected = firstClauseDetails.ConditionExpected
					result.Actual = firstClauseDetails.ConditionActual
					result.Delta = firstClauseDetails.ConditionDelta
				} else {
					// First clause matched with severity, no first clause details,
					// or single-condition clauses check different paths - use matched clause's details
					result.Path = o.ConditionPath
					result.Expected = o.ConditionExpected
					result.Actual = o.ConditionActual
					result.Delta = o.ConditionDelta
				}
				return result
			}
		}
		// No clause matched = FAIL with default severity
		// Use details from a single outcome to avoid mixing different clauses
		result.Status = "fail"
		result.Severity = "high"
		bestOutcome := selectBestFailureOutcome(outcomes)
		result.FailureKind = failureKindForOutcome(bestOutcome)
		result.Message = bestOutcome.FailureDetail
		result.Path = bestOutcome.ConditionPath
		result.Expected = bestOutcome.ConditionExpected
		result.Actual = bestOutcome.ConditionActual
		result.Delta = bestOutcome.ConditionDelta
		result.Artifact = bestOutcome.ArtifactPath
		return result

	case compiled.ClauseModeAll:
		// All clauses must match AND have no severity to pass
		var highestSeverity string
		for _, o := range outcomes {
			if !o.Matched {
				result.Status = "fail"
				result.Severity = "high"
				result.FailureKind = failureKindForOutcome(o)
				result.Message = o.FailureDetail
				if o.ArtifactPath != "" {
					result.Artifact = o.ArtifactPath
				}
				// Propagate condition details
				result.Path = o.ConditionPath
				result.Expected = o.ConditionExpected
				result.Actual = o.ConditionActual
				result.Delta = o.ConditionDelta
				return result
			}
			if o.Severity != "" {
				highestSeverity = compiled.MaxSeverity(highestSeverity, o.Severity)
			}
		}
		if highestSeverity != "" {
			result.Status = "fail"
			result.Severity = highestSeverity
			return result
		}
		result.Status = "pass"
		if len(outcomes) == 1 {
			populatePassDetailsFromOutcome(&result, outcomes[0])
		}
		return result
	}

	// Should not reach here
	result.Status = "fail"
	result.Severity = "high"
	result.Message = "invalid clause mode"
	return result
}

func populatePassDetailsFromOutcome(result *RequirementResult, outcome ClauseOutcome) {
	result.Artifact = outcome.ArtifactPath
	result.Path = outcome.ConditionPath
	result.Expected = outcome.ConditionExpected
	result.Actual = outcome.ConditionActual
	result.Delta = outcome.ConditionDelta
}

func buildCheckResults(req *compiled.CompiledRequirement, outcomes []ClauseOutcome) []CheckResult {
	if len(outcomes) == 0 {
		return nil
	}

	checks := make([]CheckResult, 0, len(outcomes))
	for i, outcome := range outcomes {
		check := CheckResult{
			ClauseIndex: i,
			Schema:      req.Clauses[i].Schema,
			Status:      checkStatusForOutcome(outcome),
			Severity:    outcome.Severity,
			Artifact:    outcome.ArtifactPath,
			Message:     outcome.FailureDetail,
			Conditions:  outcome.ConditionChecks,
		}

		checks = append(checks, check)
	}

	return checks
}

func checkStatusForOutcome(outcome ClauseOutcome) string {
	if outcome.Matched {
		if outcome.Severity == "" {
			return "pass"
		}
		return "fail"
	}

	switch outcome.FailureKind {
	case FailureKindNoMatch:
		return "missing"
	case FailureKindFreshness:
		return "stale"
	case FailureKindFreshnessMissing:
		return "freshness_missing"
	default:
		return "fail"
	}
}

func failureKindForOutcome(outcome ClauseOutcome) string {
	switch outcome.FailureKind {
	case FailureKindNoMatch:
		return "missing"
	case FailureKindFreshness:
		return "stale"
	case FailureKindFreshnessMissing:
		return "freshness_missing"
	case FailureKindCondition:
		return "condition"
	default:
		return ""
	}
}

func (v *Validator) evaluateClause(ctx *Context, clause *compiled.CompiledClause, artifacts []IndexedArtifact) ClauseOutcome {
	if len(artifacts) == 0 {
		return ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindNoMatch,
			FailureDetail: fmt.Sprintf("no artifact with schema %s", clause.Schema),
			Origin:        clause.Origin,
		}
	}

	// Track what we've seen for accurate failure reporting
	var freshConditionFailure *ClauseOutcome // Fresh artifact that failed conditions
	var staleArtifact *IndexedArtifact       // First stale artifact found
	var missingTimestamp bool                // Any artifact missing timestamp

	for _, artifact := range artifacts {
		artifact := artifact // capture for pointer

		// Check freshness if required
		if clause.MaxAgeDays != nil {
			if artifact.CollectedAt == nil {
				missingTimestamp = true
				continue // Skip artifacts without timestamp
			}
			age := ctx.Now().Sub(*artifact.CollectedAt)
			maxAge := time.Duration(*clause.MaxAgeDays) * 24 * time.Hour
			if age > maxAge {
				if staleArtifact == nil {
					staleArtifact = &artifact
				}
				continue // Too old, try next artifact
			}
		}

		// Artifact is fresh (or no freshness requirement) - evaluate conditions
		condResult := evaluateConditionsWithDetails(clause.Conditions, artifact.Body)
		if condResult.Passed {
			outcome := ClauseOutcome{
				Matched:         true,
				Severity:        clause.Severity,
				ArtifactPath:    artifact.Path,
				Origin:          clause.Origin,
				ConditionChecks: condResult.Checks,
			}
			if condResult.Detail != nil {
				outcome.ConditionPath = condResult.Detail.Path
				outcome.ConditionExpected = condResult.Detail.Expected
				outcome.ConditionActual = condResult.Detail.Actual
				outcome.ConditionDelta = condResult.Detail.Delta
			}
			return outcome
		}

		// Fresh artifact failed conditions - track for reporting
		if freshConditionFailure == nil {
			freshConditionFailure = &ClauseOutcome{
				Matched:         false,
				FailureKind:     FailureKindCondition,
				FailureDetail:   "conditions not satisfied",
				ArtifactPath:    artifact.Path,
				Origin:          clause.Origin,
				ConditionChecks: condResult.Checks,
			}
			if condResult.Detail != nil {
				freshConditionFailure.ConditionPath = condResult.Detail.Path
				freshConditionFailure.ConditionExpected = condResult.Detail.Expected
				freshConditionFailure.ConditionActual = condResult.Detail.Actual
				freshConditionFailure.ConditionDelta = condResult.Detail.Delta
			}
		}
	}

	// Report failure - prioritize condition failures over freshness
	// (if a fresh artifact existed but failed conditions, that's the real issue)
	if freshConditionFailure != nil {
		return *freshConditionFailure
	}

	// No fresh artifacts - report freshness issue
	if staleArtifact != nil {
		age := ctx.Now().Sub(*staleArtifact.CollectedAt)
		return ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindFreshness,
			FailureDetail: fmt.Sprintf("artifact too old: collected %s ago, max %d days", age.Round(time.Hour), *clause.MaxAgeDays),
			ArtifactPath:  staleArtifact.Path,
			Origin:        clause.Origin,
		}
	}

	if missingTimestamp {
		return ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindFreshnessMissing,
			FailureDetail: "artifact missing collected_at timestamp",
			Origin:        clause.Origin,
		}
	}

	// Shouldn't reach here, but fallback to condition failure
	return ClauseOutcome{
		Matched:       false,
		FailureKind:   FailureKindCondition,
		FailureDetail: "conditions not satisfied",
		Origin:        clause.Origin,
	}
}

func conditionCheckFromFailure(detail *ConditionFailure, passed bool) ConditionCheck {
	if detail == nil {
		return ConditionCheck{Passed: passed}
	}

	return ConditionCheck{
		Path:     detail.Path,
		Expected: detail.Expected,
		Actual:   detail.Actual,
		Delta:    detail.Delta,
		Passed:   passed,
	}
}

// ConditionFailure captures details about a failed condition.
type ConditionFailure struct {
	Path     string         // JSONPath that was evaluated
	Expected *ExpectedValue // Structured expected value
	Actual   any            // Actual value (typed)
	Delta    *float64       // Delta for numeric comparisons (actual - expected)
}

// ConditionResult captures details about condition evaluation.
type ConditionResult struct {
	Passed bool
	Detail *ConditionFailure // Always populated if there are conditions
	Checks []ConditionCheck
}

// evaluateConditionsWithDetails evaluates all conditions and returns both pass/fail status
// and the first condition's details for display (useful for graduated checks).
func evaluateConditionsWithDetails(conditions []compiled.CompiledCondition, body any) ConditionResult {
	if len(conditions) == 0 {
		return ConditionResult{Passed: true, Detail: nil}
	}

	// Always capture the first condition's details for display
	firstCond := conditions[0]
	firstPassed, firstDetail := evaluateSingleCondition(&firstCond, body)
	checks := []ConditionCheck{conditionCheckFromFailure(firstDetail, firstPassed)}

	// If first condition failed, return immediately
	if !firstPassed {
		return ConditionResult{Passed: false, Detail: firstDetail, Checks: checks}
	}

	// Evaluate remaining conditions
	for i := 1; i < len(conditions); i++ {
		cond := &conditions[i]
		passed, detail := evaluateSingleCondition(cond, body)
		checks = append(checks, conditionCheckFromFailure(detail, passed))
		if !passed {
			return ConditionResult{Passed: false, Detail: detail, Checks: checks}
		}
	}

	// All conditions passed - return first condition's details for graduated checks
	return ConditionResult{Passed: true, Detail: firstDetail, Checks: checks}
}

// evaluateSingleCondition evaluates one condition with cardinality support.
func evaluateSingleCondition(cond *compiled.CompiledCondition, body any) (bool, *ConditionFailure) {
	// Handle single-value (default) cardinality
	if cond.Cardinality == compiled.CardinalitySingle {
		return evaluateSingleValueCondition(cond, body)
	}

	// Handle multi-value cardinality
	return evaluateMultiValueCondition(cond, body)
}

// evaluateSingleValueCondition handles the default single-value case.
func evaluateSingleValueCondition(cond *compiled.CompiledCondition, body any) (bool, *ConditionFailure) {
	actual, err := condition.EvaluateJSONPath(cond.Expr, body)

	if err != nil {
		return false, &ConditionFailure{
			Path:     cond.Path,
			Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
			Actual:   nil,
		}
	}

	passed := cond.Op.Apply(actual, cond.Expected)
	detail := &ConditionFailure{
		Path:     cond.Path,
		Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
		Actual:   actual,
	}

	// Calculate delta for numeric comparisons
	if actualNum, aOK := condition.NormalizeNumeric(actual); aOK {
		if expectedNum, eOK := condition.NormalizeNumeric(cond.Expected); eOK {
			delta := actualNum - expectedNum
			detail.Delta = &delta
		}
	}

	return passed, detail
}

// evaluateMultiValueCondition handles cardinality: all/any/none.
func evaluateMultiValueCondition(cond *compiled.CompiledCondition, body any) (bool, *ConditionFailure) {
	values := condition.EvaluateJSONPathMulti(cond.Expr, body)

	// Special handling for exists/not_exists operators with cardinality.
	// These operators reason about field presence, but missing elements
	// don't appear in the JSONPath result set at all.
	if cond.Op == condition.OpExists || cond.Op == condition.OpNotExists {
		return evaluatePresenceCondition(cond, body, values)
	}

	if len(values) == 0 {
		// No values found - behavior depends on cardinality
		// For "all" and "any", empty means fail (nothing to check)
		// For "none", empty means pass (nothing violates)
		passed := cond.Cardinality == compiled.CardinalityNone
		return passed, &ConditionFailure{
			Path:     cond.Path,
			Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
			Actual:   nil,
		}
	}

	var passCount, failCount int
	var firstFailValue any
	var firstPassValue any

	for _, val := range values {
		if cond.Op.Apply(val, cond.Expected) {
			passCount++
			if firstPassValue == nil {
				firstPassValue = val
			}
		} else {
			failCount++
			if firstFailValue == nil {
				firstFailValue = val
			}
		}
	}

	var passed bool
	var actualValue any

	switch cond.Cardinality {
	case compiled.CardinalityAll:
		// All values must satisfy the condition
		passed = failCount == 0

		// Additional check: verify we got values from ALL array elements
		// This catches the case where some elements are missing the field entirely
		if passed && cond.BaseExpr != nil {
			expectedCount := condition.GetArrayLength(cond.BaseExpr, body)
			if expectedCount > 0 && len(values) < expectedCount {
				// Some elements are missing the field - fail
				passed = false
				actualValue = fmt.Sprintf("%d of %d elements have field", len(values), expectedCount)
			}
		}

		if !passed && actualValue == nil {
			if firstFailValue != nil {
				actualValue = firstFailValue
			}
		}
		if passed && passCount > 0 {
			actualValue = firstPassValue
		}

	case compiled.CardinalityAny:
		// At least one value must satisfy the condition
		passed = passCount > 0
		if passed && firstPassValue != nil {
			actualValue = firstPassValue
		} else if firstFailValue != nil {
			actualValue = firstFailValue
		}

	case compiled.CardinalityNone:
		// No value should satisfy the condition
		passed = passCount == 0
		if !passed && firstPassValue != nil {
			actualValue = firstPassValue
		} else if firstFailValue != nil {
			actualValue = firstFailValue
		}
	}

	detail := &ConditionFailure{
		Path:     cond.Path,
		Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
		Actual:   actualValue,
	}

	// Calculate delta for numeric comparisons
	if actualNum, aOK := condition.NormalizeNumeric(actualValue); aOK {
		if expectedNum, eOK := condition.NormalizeNumeric(cond.Expected); eOK {
			delta := actualNum - expectedNum
			detail.Delta = &delta
		}
	}

	return passed, detail
}

// evaluatePresenceCondition handles exists/not_exists with cardinality.
// These operators require special handling because missing elements don't
// appear in the JSONPath result set - we need to compare counts.
func evaluatePresenceCondition(cond *compiled.CompiledCondition, body any, values []any) (bool, *ConditionFailure) {
	actualCount := len(values)

	// Get expected element count from base array (if available)
	expectedCount := -1
	if cond.BaseExpr != nil {
		expectedCount = condition.GetArrayLength(cond.BaseExpr, body)
	}

	// Count non-nil values (for exists, nil values don't count as "existing")
	nonNilCount := 0
	for _, v := range values {
		if v != nil {
			nonNilCount++
		}
	}

	var passed bool
	var actualValue any

	switch cond.Op {
	case condition.OpExists:
		// "exists" means field should be present and non-nil
		switch cond.Cardinality {
		case compiled.CardinalityAll:
			// All elements must have the field (and be non-nil)
			if expectedCount > 0 {
				passed = nonNilCount == expectedCount
				if !passed {
					actualValue = fmt.Sprintf("%d of %d elements have field", nonNilCount, expectedCount)
				}
			} else {
				// No base path - can't verify element count, just check values
				passed = actualCount > 0 && nonNilCount == actualCount
				if !passed && actualCount > 0 {
					actualValue = "some values are null"
				}
			}
		case compiled.CardinalityAny:
			// At least one element must have the field
			passed = nonNilCount > 0
		case compiled.CardinalityNone:
			// No element should have the field
			passed = nonNilCount == 0
			if !passed && expectedCount > 0 {
				actualValue = fmt.Sprintf("%d of %d elements have field", nonNilCount, expectedCount)
			}
		}

	case condition.OpNotExists:
		// "not_exists" means field should NOT be present OR is null
		// An element satisfies not_exists if: missing from result set OR present but null
		// nonNilCount = elements that have non-null values (DON'T satisfy not_exists)
		// satisfyingCount = expectedCount - nonNilCount (missing + null elements)
		switch cond.Cardinality {
		case compiled.CardinalityAll:
			// All elements must satisfy not_exists (be missing or null)
			// → no element should have a non-null value
			passed = nonNilCount == 0
			if !passed {
				if expectedCount > 0 {
					actualValue = fmt.Sprintf("%d of %d elements have non-null value", nonNilCount, expectedCount)
				} else {
					// No base path - just report that some values are non-null
					actualValue = "some values are non-null"
				}
			}
		case compiled.CardinalityAny:
			// At least one element must satisfy not_exists (be missing or null)
			if expectedCount > 0 {
				passed = nonNilCount < expectedCount
				satisfyingCount := expectedCount - nonNilCount
				if passed {
					actualValue = fmt.Sprintf("%d of %d elements satisfy not_exists", satisfyingCount, expectedCount)
				} else {
					actualValue = fmt.Sprintf("all %d elements have non-null value", expectedCount)
				}
			} else {
				// No base path - check if any values in result are null
				nilCount := actualCount - nonNilCount
				passed = nilCount > 0
				if !passed {
					actualValue = "no null values found"
				}
			}
		case compiled.CardinalityNone:
			// No element should satisfy not_exists (all must have non-null values)
			if expectedCount > 0 {
				passed = nonNilCount == expectedCount
				if !passed {
					satisfyingCount := expectedCount - nonNilCount
					actualValue = fmt.Sprintf("%d of %d elements satisfy not_exists", satisfyingCount, expectedCount)
				}
			} else {
				// No base path - check if all values in result are non-null
				passed = actualCount > 0 && nonNilCount == actualCount
				if !passed {
					actualValue = "some values are null"
				}
			}
		}
	}

	return passed, &ConditionFailure{
		Path:     cond.Path,
		Expected: &ExpectedValue{Op: cond.Op.String()},
		Actual:   actualValue,
	}
}

// selectBestFailureOutcome picks the most informative failure outcome.
// Prioritizes condition failures (which have path/expected/actual details)
// over freshness or no-match failures.
func selectBestFailureOutcome(outcomes []ClauseOutcome) ClauseOutcome {
	// First priority: condition failures with details
	for _, o := range outcomes {
		if o.FailureKind == FailureKindCondition && o.ConditionPath != "" {
			return o
		}
	}

	// Second priority: any failure with a detail message
	for _, o := range outcomes {
		if o.FailureDetail != "" {
			return o
		}
	}

	// Fallback: first outcome or empty
	if len(outcomes) > 0 {
		return outcomes[0]
	}
	return ClauseOutcome{FailureDetail: "no matching clause found"}
}
