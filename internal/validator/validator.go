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

		// Update summary. Any failure makes the overall status "fail"; with
		// no failures, any unknown makes it "unknown" (the pack cannot be
		// asserted to pass on absent evidence).
		switch reqResult.Status {
		case "pass":
			result.Summary.Passed++
		case "unknown":
			result.Summary.Unknown++
			if result.Status == "pass" {
				result.Status = "unknown"
			}
		default:
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
			switch {
			case reqResult.Status == "pass":
				cat.Passed++
			case reqResult.Status == "unknown":
				cat.Unknown++
			case reqResult.FailureKind == "missing":
				cat.Missing++
			default:
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
		Mode:     req.Mode.String(), // "any_of" or "all_of"
	}

	// Evaluate all clauses
	outcomes := make([]ClauseOutcome, len(req.Clauses))
	for i, clause := range req.Clauses {
		artifacts := pack.BySchema[clause.Schema]
		outcomes[i] = v.evaluateClause(ctx, &clause, artifacts)
	}

	switch req.Mode {
	case compiled.ClauseModeAny:
		// Track which clause index is selected (determines outcome)
		var selectedClauseIndex int
		// For graduated failures, we want to show the "pass" threshold (first clause)
		// rather than the matched fallback clause. Capture first clause's details.
		var firstClauseDetails *ClauseOutcome
		var firstClauseCondCount int
		if len(outcomes) > 0 && outcomes[0].ConditionPath != "" {
			firstClauseDetails = &outcomes[0]
			firstClauseCondCount = len(req.Clauses[0].Conditions)
		}

		// A definite pass wins outright: any_of is satisfied regardless of
		// what the other clauses did.
		for i, o := range outcomes {
			if o.Matched && o.Severity == "" {
				selectedClauseIndex = i // This clause determined the outcome
				result.Status = "pass"
				populatePassDetailsFromOutcome(&result, o)
				result.Checks = buildCheckResults(req, outcomes, selectedClauseIndex)
				return result
			}
		}

		// With no definite pass, any unknown clause blocks a verdict: the
		// absent evidence might have satisfied the requirement, so neither a
		// graded failure nor the no-clause-matched default can be asserted.
		for i, o := range outcomes {
			if o.Unknown {
				result.Status = "unknown"
				result.FailureKind = failureKindForOutcome(o)
				result.Message = o.FailureDetail
				result.Path = o.ConditionPath
				result.Expected = o.ConditionExpected
				result.Actual = o.ConditionActual
				result.Delta = o.ConditionDelta
				result.Artifact = o.ArtifactPath
				result.Checks = buildCheckResults(req, outcomes, i)
				return result
			}
		}

		// First matching clause wins - its severity determines outcome
		for i, o := range outcomes {
			if o.Matched {
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
					// Also mark first clause as selected since it shows the pass threshold
					selectedClauseIndex = 0
					result.Path = firstClauseDetails.ConditionPath
					result.Expected = firstClauseDetails.ConditionExpected
					result.Actual = firstClauseDetails.ConditionActual
					result.Delta = firstClauseDetails.ConditionDelta
				} else {
					// First clause matched with severity, no first clause details,
					// or single-condition clauses check different paths - use matched clause's details
					selectedClauseIndex = i
					result.Path = o.ConditionPath
					result.Expected = o.ConditionExpected
					result.Actual = o.ConditionActual
					result.Delta = o.ConditionDelta
				}
				result.Checks = buildCheckResults(req, outcomes, selectedClauseIndex)
				return result
			}
		}
		// No clause matched = FAIL with default severity
		// Use details from a single outcome to avoid mixing different clauses
		result.Status = "fail"
		result.Severity = "high"
		bestOutcome := selectBestFailureOutcome(outcomes)
		selectedClauseIndex = selectBestFailureIndex(outcomes) // Track which outcome we're using
		result.FailureKind = failureKindForOutcome(bestOutcome)
		result.Message = bestOutcome.FailureDetail
		result.Path = bestOutcome.ConditionPath
		result.Expected = bestOutcome.ConditionExpected
		result.Actual = bestOutcome.ConditionActual
		result.Delta = bestOutcome.ConditionDelta
		result.Artifact = bestOutcome.ArtifactPath
		result.Checks = buildCheckResults(req, outcomes, selectedClauseIndex)
		return result

	case compiled.ClauseModeAll:
		// All clauses must match AND have no severity to pass
		// For all_of mode, don't mark any check as selected (all matter equally)
		// A definite non-match decides failure even when other clauses are
		// unknown: all_of needs every clause, and one definitively missed.
		var highestSeverity string
		for _, o := range outcomes {
			if !o.Matched && !o.Unknown {
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
				// For all_of, the first failing check is technically the "blocker"
				// but we don't mark it as selected since all checks matter
				result.Checks = buildCheckResults(req, outcomes, -1) // -1 = no selected
				return result
			}
			if o.Severity != "" {
				highestSeverity = compiled.MaxSeverity(highestSeverity, o.Severity)
			}
		}
		// No definite miss; an unknown clause means the requirement cannot be
		// scored (it might have matched or missed).
		for _, o := range outcomes {
			if o.Unknown {
				result.Status = "unknown"
				result.FailureKind = failureKindForOutcome(o)
				result.Message = o.FailureDetail
				if o.ArtifactPath != "" {
					result.Artifact = o.ArtifactPath
				}
				result.Path = o.ConditionPath
				result.Expected = o.ConditionExpected
				result.Actual = o.ConditionActual
				result.Delta = o.ConditionDelta
				result.Checks = buildCheckResults(req, outcomes, -1)
				return result
			}
		}
		if highestSeverity != "" {
			result.Status = "fail"
			result.Severity = highestSeverity
			result.Checks = buildCheckResults(req, outcomes, -1)
			return result
		}
		result.Status = "pass"
		if len(outcomes) == 1 {
			populatePassDetailsFromOutcome(&result, outcomes[0])
		}
		result.Checks = buildCheckResults(req, outcomes, -1)
		return result
	}

	// Should not reach here
	result.Status = "fail"
	result.Severity = "high"
	result.Message = "invalid clause mode"
	result.Checks = buildCheckResults(req, outcomes, -1)
	return result
}

func populatePassDetailsFromOutcome(result *RequirementResult, outcome ClauseOutcome) {
	result.Artifact = outcome.ArtifactPath
	result.Path = outcome.ConditionPath
	result.Expected = outcome.ConditionExpected
	result.Actual = outcome.ConditionActual
	result.Delta = outcome.ConditionDelta
}

func buildCheckResults(req *compiled.CompiledRequirement, outcomes []ClauseOutcome, selectedIndex int) []CheckResult {
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
			Selected:    i == selectedIndex, // Mark the decisive check
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
	if outcome.Unknown {
		return "unknown"
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
	case FailureKindInsufficientEvidence:
		return "insufficient_evidence"
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
	var insufficientEvidence *ClauseOutcome  // Fresh artifact whose evidence was absent
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
		condResult := evaluateConditionsWithDetailsAt(clause.Conditions, artifact.Body, ctx.Now())
		switch condResult.Verdict {
		case VerdictTrue:
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

		case VerdictUnknown:
			if insufficientEvidence == nil {
				insufficientEvidence = &ClauseOutcome{
					Unknown:         true,
					FailureKind:     FailureKindInsufficientEvidence,
					FailureDetail:   "insufficient evidence: referenced value absent from artifact",
					ArtifactPath:    artifact.Path,
					Origin:          clause.Origin,
					ConditionChecks: condResult.Checks,
				}
				if condResult.Detail != nil {
					insufficientEvidence.FailureDetail = fmt.Sprintf("insufficient evidence: %s absent from artifact", condResult.Detail.Path)
					insufficientEvidence.ConditionPath = condResult.Detail.Path
					insufficientEvidence.ConditionExpected = condResult.Detail.Expected
					insufficientEvidence.ConditionActual = condResult.Detail.Actual
					insufficientEvidence.ConditionDelta = condResult.Detail.Delta
				}
			}

		default:
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
	}

	// No artifact matched. An artifact with absent evidence outranks a
	// definite condition failure on another artifact: the absent one might
	// have satisfied the clause, so the clause cannot be scored either way.
	if insufficientEvidence != nil {
		return *insufficientEvidence
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

func conditionCheckFromFailure(detail *ConditionFailure, verdict Verdict) ConditionCheck {
	if detail == nil {
		return ConditionCheck{Passed: verdict == VerdictTrue, Unknown: verdict == VerdictUnknown}
	}

	return ConditionCheck{
		Path:     detail.Path,
		Expected: detail.Expected,
		Actual:   detail.Actual,
		Delta:    detail.Delta,
		Passed:   verdict == VerdictTrue,
		Unknown:  verdict == VerdictUnknown,
	}
}

// ConditionFailure captures details about a failed condition.
type ConditionFailure struct {
	Path     string         // JSONPath that was evaluated
	Expected *ExpectedValue // Structured expected value
	Actual   any            // Actual value (typed)
	Delta    *float64       // Delta for numeric comparisons (actual - expected)
}

// ConditionResult captures details about condition evaluation. The condition
// group is a three-valued AND: any definite false decides false, otherwise any
// unknown decides unknown, otherwise true.
type ConditionResult struct {
	Verdict Verdict
	Detail  *ConditionFailure // Always populated if there are conditions
	Checks  []ConditionCheck
}

// evaluateConditionsWithDetails evaluates all conditions and returns both the
// verdict and the first condition's details for display (useful for graduated checks).
func evaluateConditionsWithDetails(conditions []compiled.CompiledCondition, body any) ConditionResult {
	return evaluateConditionsWithDetailsAt(conditions, body, time.Now())
}

func evaluateConditionsWithDetailsAt(conditions []compiled.CompiledCondition, body any, now time.Time) ConditionResult {
	if len(conditions) == 0 {
		return ConditionResult{Verdict: VerdictTrue, Detail: nil}
	}

	// Always capture the first condition's details for display
	firstCond := conditions[0]
	firstVerdict, firstDetail := evaluateSingleConditionAt(&firstCond, body, now)
	checks := []ConditionCheck{conditionCheckFromFailure(firstDetail, firstVerdict)}

	// A definite false decides immediately; an unknown is recorded but later
	// conditions still run, since a definite false among them must win.
	if firstVerdict == VerdictFalse {
		return ConditionResult{Verdict: VerdictFalse, Detail: firstDetail, Checks: checks}
	}
	unknownDetail := firstDetail
	sawUnknown := firstVerdict == VerdictUnknown

	for i := 1; i < len(conditions); i++ {
		cond := &conditions[i]
		verdict, detail := evaluateSingleConditionAt(cond, body, now)
		checks = append(checks, conditionCheckFromFailure(detail, verdict))
		if verdict == VerdictFalse {
			return ConditionResult{Verdict: VerdictFalse, Detail: detail, Checks: checks}
		}
		if verdict == VerdictUnknown && !sawUnknown {
			sawUnknown = true
			unknownDetail = detail
		}
	}

	if sawUnknown {
		return ConditionResult{Verdict: VerdictUnknown, Detail: unknownDetail, Checks: checks}
	}

	// All conditions passed - return first condition's details for graduated checks
	return ConditionResult{Verdict: VerdictTrue, Detail: firstDetail, Checks: checks}
}

// evaluateSingleCondition evaluates one condition with cardinality support.
func evaluateSingleCondition(cond *compiled.CompiledCondition, body any) (Verdict, *ConditionFailure) {
	return evaluateSingleConditionAt(cond, body, time.Now())
}

func evaluateSingleConditionAt(cond *compiled.CompiledCondition, body any, now time.Time) (Verdict, *ConditionFailure) {
	// Handle single-value (default) cardinality
	if cond.Cardinality == compiled.CardinalitySingle {
		return evaluateSingleValueConditionAt(cond, body, now)
	}

	// Handle multi-value cardinality
	return evaluateMultiValueConditionAt(cond, body, now)
}

// presenceOp reports whether the operator reasons about presence itself.
// Presence operators stay two-valued: an absent value is exactly what they
// test for. Every other operator yields VerdictUnknown on an absent value,
// since a comparison against nothing is not evidence in either direction.
func presenceOp(op condition.Operator) bool {
	return op == condition.OpExists || op == condition.OpNotExists
}

// evaluateSingleValueConditionAt handles the default single-value case.
func evaluateSingleValueConditionAt(cond *compiled.CompiledCondition, body any, now time.Time) (Verdict, *ConditionFailure) {
	actual, err := condition.EvaluateJSONPath(cond.Expr, body)

	if err != nil {
		return VerdictFalse, &ConditionFailure{
			Path:     cond.Path,
			Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
			Actual:   nil,
		}
	}

	detail := &ConditionFailure{
		Path:     cond.Path,
		Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
		Actual:   actual,
	}

	// An absent (or null) value cannot pass or fail a comparison; only the
	// presence operators score it.
	if actual == nil && !presenceOp(cond.Op) {
		return VerdictUnknown, detail
	}

	passed := cond.Op.ApplyAt(actual, cond.Expected, now)

	// Calculate delta for numeric comparisons
	if actualNum, aOK := condition.NormalizeNumeric(actual); aOK {
		if expectedNum, eOK := condition.NormalizeNumeric(cond.Expected); eOK {
			delta := actualNum - expectedNum
			detail.Delta = &delta
		}
	}

	if passed {
		return VerdictTrue, detail
	}
	return VerdictFalse, detail
}

// evaluateMultiValueConditionAt handles cardinality: all/any/none.
func evaluateMultiValueConditionAt(cond *compiled.CompiledCondition, body any, now time.Time) (Verdict, *ConditionFailure) {
	values := condition.EvaluateJSONPathMulti(cond.Expr, body)

	// Special handling for exists/not_exists operators with cardinality.
	// These operators reason about field presence, but missing elements
	// don't appear in the JSONPath result set at all.
	if cond.Op == condition.OpExists || cond.Op == condition.OpNotExists {
		return evaluatePresenceCondition(cond, body, values)
	}

	expectedCount := -1
	if cond.BaseExpr != nil {
		expectedCount = condition.GetArrayLength(cond.BaseExpr, body)
	}

	if len(values) == 0 {
		// No values found. A present-but-empty base array is definite for
		// "none" (nothing violates, vacuously). Everything else is unknown:
		// the values may be absent because they were never collected, and
		// scoring absence would fabricate a verdict in one direction or the
		// other. Profiles that need "the array is non-empty" assert it with
		// an explicit count or exists condition.
		if cond.Cardinality == compiled.CardinalityNone && expectedCount == 0 {
			return VerdictTrue, &ConditionFailure{
				Path:     cond.Path,
				Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
				Actual:   nil,
			}
		}
		return VerdictUnknown, &ConditionFailure{
			Path:     cond.Path,
			Expected: &ExpectedValue{Op: cond.Op.String(), Value: cond.Expected},
			Actual:   nil,
		}
	}

	// Count definite passes and failures; null elements are unknowns (an
	// explicit null cannot pass or fail a comparison).
	var passCount, failCount, unknownCount int
	var firstFailValue any
	var firstPassValue any

	for _, val := range values {
		if val == nil {
			unknownCount++
			continue
		}
		if cond.Op.ApplyAt(val, cond.Expected, now) {
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

	// Elements missing the field entirely never appear in the result set;
	// compare against the base array length so per-element absence reads as
	// unknown rather than being silently skipped (which would let a partially
	// collected artifact pass a cardinality "all" check).
	if expectedCount > 0 && len(values) < expectedCount {
		unknownCount += expectedCount - len(values)
	}

	var verdict Verdict
	var actualValue any

	switch cond.Cardinality {
	case compiled.CardinalityAll:
		// A definite violation decides false; otherwise any unevaluated
		// element blocks a pass.
		switch {
		case failCount > 0:
			verdict = VerdictFalse
			actualValue = firstFailValue
		case unknownCount > 0:
			verdict = VerdictUnknown
			actualValue = fmt.Sprintf("%d of %d elements evaluated", passCount, passCount+unknownCount)
		default:
			verdict = VerdictTrue
			actualValue = firstPassValue
		}

	case compiled.CardinalityAny:
		// A definite pass decides true; otherwise an unevaluated element
		// might have passed.
		switch {
		case passCount > 0:
			verdict = VerdictTrue
			actualValue = firstPassValue
		case unknownCount > 0:
			verdict = VerdictUnknown
			actualValue = fmt.Sprintf("0 of %d evaluated elements satisfy; %d unevaluated", failCount, unknownCount)
		default:
			verdict = VerdictFalse
			actualValue = firstFailValue
		}

	case compiled.CardinalityNone:
		// A definite violation decides false; otherwise an unevaluated
		// element might have violated.
		switch {
		case passCount > 0:
			verdict = VerdictFalse
			actualValue = firstPassValue
		case unknownCount > 0:
			verdict = VerdictUnknown
			actualValue = fmt.Sprintf("%d of %d elements evaluated", failCount, failCount+unknownCount)
		default:
			verdict = VerdictTrue
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

	return verdict, detail
}

// evaluatePresenceCondition handles exists/not_exists with cardinality.
// These operators require special handling because missing elements don't
// appear in the JSONPath result set - we need to compare counts. Presence
// operators are deliberately two-valued: absence is exactly what they test.
func evaluatePresenceCondition(cond *compiled.CompiledCondition, body any, values []any) (Verdict, *ConditionFailure) {
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

	verdict := VerdictFalse
	if passed {
		verdict = VerdictTrue
	}
	return verdict, &ConditionFailure{
		Path:     cond.Path,
		Expected: &ExpectedValue{Op: cond.Op.String()},
		Actual:   actualValue,
	}
}

// selectBestFailureOutcome picks the most informative failure outcome.
// Prioritizes condition failures (which have path/expected/actual details)
// over freshness or no-match failures.
func selectBestFailureOutcome(outcomes []ClauseOutcome) ClauseOutcome {
	idx := selectBestFailureIndex(outcomes)
	if idx >= 0 && idx < len(outcomes) {
		return outcomes[idx]
	}
	return ClauseOutcome{FailureDetail: "no matching clause found"}
}

// selectBestFailureIndex returns the index of the most informative failure outcome.
// Used to mark the selected check in any_of failures.
func selectBestFailureIndex(outcomes []ClauseOutcome) int {
	// First priority: condition failures with details
	for i, o := range outcomes {
		if o.FailureKind == FailureKindCondition && o.ConditionPath != "" {
			return i
		}
	}

	// Second priority: any failure with a detail message
	for i, o := range outcomes {
		if o.FailureDetail != "" {
			return i
		}
	}

	// Fallback: first outcome
	if len(outcomes) > 0 {
		return 0
	}
	return -1
}
