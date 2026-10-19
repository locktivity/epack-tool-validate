// Package compiled provides profile compilation from raw to execution-ready form.
package compiled

import (
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/diagnostic"
	"github.com/locktivity/epack-tool-validate/internal/profile/raw"
	"github.com/ohler55/ojg/jp"
)

// Compile transforms a raw profile into an immutable CompiledProfile.
// This validates all invariants and pre-parses JSONPaths and operators.
// If Compile returns nil error, the profile is guaranteed to be valid.
// defaultSourceFile is used as fallback when requirements don't have SourceFile set.
func Compile(profile *raw.RawProfile, defaultSourceFile string) (*CompiledProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile is nil")
	}
	compiled, diags := compile(profile, defaultSourceFile, true)
	if len(diags) > 0 {
		return nil, diags[0]
	}
	return compiled, nil
}

// Diagnose runs the same checks as Compile but reports every failure in
// document order instead of stopping at the first.
func Diagnose(profile *raw.RawProfile, defaultSourceFile string) []diagnostic.Diagnostic {
	if profile == nil {
		return nil
	}
	_, diags := compile(profile, defaultSourceFile, false)
	return diags
}

func compile(profile *raw.RawProfile, defaultSourceFile string, stopAtFirst bool) (*CompiledProfile, []diagnostic.Diagnostic) {
	compiled := &CompiledProfile{
		ID:      profile.ID,
		Name:    profile.Name,
		Version: profile.Version,
	}

	var diags []diagnostic.Diagnostic
	seenIDs := make(map[string]bool)

	for _, req := range profile.Requirements {
		sourceFile := req.SourceFile
		if sourceFile == "" {
			sourceFile = defaultSourceFile
		}

		if seenIDs[req.ID] {
			diags = append(diags, diagnostic.Errorf(
				diagnostic.CodeDuplicateRequirement,
				diagnostic.Location{File: sourceFile, RequirementID: req.ID},
				"duplicate requirement ID: %s", req.ID,
			))
			if stopAtFirst {
				return nil, diags
			}
			continue
		}
		seenIDs[req.ID] = true

		compiledReq, reqDiags := compileRequirement(&req, sourceFile)
		if len(reqDiags) > 0 {
			diags = append(diags, reqDiags...)
			if stopAtFirst {
				return nil, diags
			}
			continue
		}
		compiled.Requirements = append(compiled.Requirements, *compiledReq)
	}

	if len(diags) > 0 {
		return nil, diags
	}
	return compiled, nil
}

func compileRequirement(req *raw.RawRequirement, sourceFile string) (*CompiledRequirement, []diagnostic.Diagnostic) {
	loc := diagnostic.Location{File: sourceFile, RequirementID: req.ID}

	// Validate exactly one of any_of, all_of, or manual
	hasAnyOf := len(req.SatisfiedBy.AnyOf) > 0
	hasAllOf := len(req.SatisfiedBy.AllOf) > 0

	if req.Manual {
		if hasAnyOf || hasAllOf {
			return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
				diagnostic.CodeInvalidClauseMode, loc,
				"requirement %s: cannot combine manual: true with satisfied_by clauses", req.ID,
			)}
		}
		// A manual requirement without an id or control can never receive
		// asserted support, so it would be unreachable by any mapping entry.
		if req.ID == "" && req.Control == "" {
			return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
				diagnostic.CodeMissingField, loc,
				"manual requirement must carry id or control",
			)}
		}
		return &CompiledRequirement{
			ID:          req.ID,
			Control:     req.Control,
			Name:        req.Name,
			Description: req.Description,
			Category:    req.Category,
			Manual:      true,
		}, nil
	}

	if !hasAnyOf && !hasAllOf {
		return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
			diagnostic.CodeInvalidClauseMode, loc,
			"requirement %s: must have any_of, all_of, or manual: true", req.ID,
		)}
	}
	if hasAnyOf && hasAllOf {
		return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
			diagnostic.CodeInvalidClauseMode, loc,
			"requirement %s: cannot have both any_of and all_of", req.ID,
		)}
	}

	compiled := &CompiledRequirement{
		ID:          req.ID,
		Control:     req.Control,
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
	}

	var rawClauses []raw.RawClause
	if hasAnyOf {
		compiled.Mode = ClauseModeAny
		rawClauses = req.SatisfiedBy.AnyOf
	} else {
		compiled.Mode = ClauseModeAll
		rawClauses = req.SatisfiedBy.AllOf
	}

	if len(rawClauses) == 0 {
		return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
			diagnostic.CodeEmptyClauses, loc,
			"requirement %s: has no clauses", req.ID,
		)}
	}

	var diags []diagnostic.Diagnostic
	for i, clause := range rawClauses {
		compiledClause, clauseDiags := compileClause(&clause, req.ID, i, sourceFile)
		if len(clauseDiags) > 0 {
			diags = append(diags, clauseDiags...)
			continue
		}
		compiled.Clauses = append(compiled.Clauses, *compiledClause)
	}
	if len(diags) > 0 {
		return nil, diags
	}

	return compiled, nil
}

func compileClause(clause *raw.RawClause, reqID string, idx int, sourceFile string) (*CompiledClause, []diagnostic.Diagnostic) {
	loc := diagnostic.Location{
		File:          sourceFile,
		RequirementID: reqID,
		ClauseIndex:   idx,
	}

	// Validate type (schema) is present
	if clause.Type == "" {
		return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
			diagnostic.CodeMissingType, loc,
			"requirement %s, clause %d: missing type (schema)", reqID, idx,
		)}
	}

	// Validate severity
	if !ValidSeverities[clause.Severity] {
		return nil, []diagnostic.Diagnostic{diagnostic.Errorf(
			diagnostic.CodeInvalidSeverity, loc,
			"requirement %s, clause %d: invalid severity %q (must be critical, high, medium, low, or empty)",
			reqID, idx, clause.Severity,
		)}
	}

	compiled := &CompiledClause{
		Schema:   clause.Type,
		Severity: clause.Severity,
		Origin: Origin{
			RequirementID: reqID,
			ClauseIndex:   idx,
			SourceFile:    sourceFile,
		},
	}

	// Extract freshness
	if clause.Freshness != nil && clause.Freshness.MaxAgeDays > 0 {
		maxAge := clause.Freshness.MaxAgeDays
		compiled.MaxAgeDays = &maxAge
	}

	// Compile conditions
	var diags []diagnostic.Diagnostic
	if clause.MetadataConditions != nil {
		for j, cond := range clause.MetadataConditions.All {
			compiledCond, condDiag := compileCondition(&cond, reqID, idx, j, sourceFile)
			if condDiag != nil {
				diags = append(diags, *condDiag)
				continue
			}
			compiled.Conditions = append(compiled.Conditions, *compiledCond)
		}
	}
	if len(diags) > 0 {
		return nil, diags
	}

	return compiled, nil
}

func compileCondition(cond *raw.RawCondition, reqID string, clauseIdx, condIdx int, sourceFile string) (*CompiledCondition, *diagnostic.Diagnostic) {
	loc := diagnostic.Location{
		File:           sourceFile,
		RequirementID:  reqID,
		ClauseIndex:    clauseIdx,
		ConditionIndex: condIdx,
	}

	// Parse operator
	op, err := condition.ParseOperator(cond.Op)
	if err != nil {
		d := diagnostic.Errorf(
			diagnostic.CodeInvalidOperator, loc,
			"requirement %s, clause %d, condition %d: %v", reqID, clauseIdx, condIdx, err,
		)
		return nil, &d
	}

	if op == condition.OpMaxAgeDays {
		if maxDays, numOK := condition.NormalizeNumeric(cond.Value); !numOK || maxDays < 0 {
			d := diagnostic.Errorf(
				diagnostic.CodeInvalidFieldType, loc,
				"requirement %s, clause %d, condition %d: max_age_days requires a non-negative numeric value, got %v",
				reqID, clauseIdx, condIdx, cond.Value,
			)
			return nil, &d
		}
	}

	// Parse cardinality
	cardinality, ok := ValidCardinalities[cond.Cardinality]
	if !ok {
		d := diagnostic.Errorf(
			diagnostic.CodeInvalidCardinality, loc,
			"requirement %s, clause %d, condition %d: invalid cardinality %q (must be all, any, none, or empty)",
			reqID, clauseIdx, condIdx, cond.Cardinality,
		)
		return nil, &d
	}

	// Parse JSONPath - allow multi-value if cardinality is specified
	var expr jp.Expr
	var baseExpr jp.Expr
	var isMulti bool

	if cardinality != CardinalitySingle {
		// Multi-value cardinality allows multi-value paths
		var parseErr error
		expr, isMulti, parseErr = condition.ParseJSONPathMulti(cond.Path)
		if parseErr != nil {
			d := diagnostic.Errorf(
				diagnostic.CodeInvalidJSONPath, loc,
				"requirement %s, clause %d, condition %d: %v", reqID, clauseIdx, condIdx, parseErr,
			)
			return nil, &d
		}

		// Extract base path for element count verification. Every cardinality
		// needs it: "all" and "any" compare leaf matches against the element
		// count so per-element absence reads as unknown rather than being
		// silently skipped, "none" uses it to distinguish a present-but-empty
		// array (vacuously satisfied) from an absent one (unknown), and the
		// presence operators need the count comparison directly.
		baseExpr = condition.ExtractBasePath(expr)
		// baseExpr may be nil for recursive descent - that's OK, we'll skip the count check
	} else {
		// Single cardinality requires single-value paths
		var parseErr error
		expr, parseErr = condition.ParseJSONPath(cond.Path)
		if parseErr != nil {
			d := diagnostic.Errorf(
				diagnostic.CodeInvalidJSONPath, loc,
				"requirement %s, clause %d, condition %d: %v", reqID, clauseIdx, condIdx, parseErr,
			)
			return nil, &d
		}
		isMulti = false
	}

	return &CompiledCondition{
		Path:        cond.Path,
		Expr:        expr,
		BaseExpr:    baseExpr,
		Op:          op,
		Expected:    cond.Value,
		Cardinality: cardinality,
		IsMulti:     isMulti,
	}, nil
}
