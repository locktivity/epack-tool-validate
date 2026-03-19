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

	compiled := &CompiledProfile{
		ID:      profile.ID,
		Name:    profile.Name,
		Version: profile.Version,
	}

	// Track requirement IDs for uniqueness check
	seenIDs := make(map[string]bool)

	for _, req := range profile.Requirements {
		// Use requirement's SourceFile if set, otherwise fall back to default
		sourceFile := req.SourceFile
		if sourceFile == "" {
			sourceFile = defaultSourceFile
		}

		// Check ID uniqueness
		if seenIDs[req.ID] {
			return nil, diagnostic.Errorf(
				diagnostic.CodeDuplicateRequirement,
				diagnostic.Location{File: sourceFile, RequirementID: req.ID},
				"duplicate requirement ID: %s", req.ID,
			)
		}
		seenIDs[req.ID] = true

		compiledReq, err := compileRequirement(&req, sourceFile)
		if err != nil {
			return nil, err
		}
		compiled.Requirements = append(compiled.Requirements, *compiledReq)
	}

	return compiled, nil
}

func compileRequirement(req *raw.RawRequirement, sourceFile string) (*CompiledRequirement, error) {
	loc := diagnostic.Location{File: sourceFile, RequirementID: req.ID}

	// Validate exactly one of any_of or all_of
	hasAnyOf := len(req.SatisfiedBy.AnyOf) > 0
	hasAllOf := len(req.SatisfiedBy.AllOf) > 0

	if !hasAnyOf && !hasAllOf {
		return nil, diagnostic.Errorf(
			diagnostic.CodeInvalidClauseMode, loc,
			"requirement %s: must have either any_of or all_of", req.ID,
		)
	}
	if hasAnyOf && hasAllOf {
		return nil, diagnostic.Errorf(
			diagnostic.CodeInvalidClauseMode, loc,
			"requirement %s: cannot have both any_of and all_of", req.ID,
		)
	}

	compiled := &CompiledRequirement{
		ID:       req.ID,
		Control:  req.Control,
		Name:     req.Name,
		Category: req.Category,
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
		return nil, diagnostic.Errorf(
			diagnostic.CodeEmptyClauses, loc,
			"requirement %s: has no clauses", req.ID,
		)
	}

	for i, clause := range rawClauses {
		compiledClause, err := compileClause(&clause, req.ID, i, sourceFile)
		if err != nil {
			return nil, err
		}
		compiled.Clauses = append(compiled.Clauses, *compiledClause)
	}

	return compiled, nil
}

func compileClause(clause *raw.RawClause, reqID string, idx int, sourceFile string) (*CompiledClause, error) {
	loc := diagnostic.Location{
		File:          sourceFile,
		RequirementID: reqID,
		ClauseIndex:   idx,
	}

	// Validate type (schema) is present
	if clause.Type == "" {
		return nil, diagnostic.Errorf(
			diagnostic.CodeMissingType, loc,
			"requirement %s, clause %d: missing type (schema)", reqID, idx,
		)
	}

	// Validate severity
	if !ValidSeverities[clause.Severity] {
		return nil, diagnostic.Errorf(
			diagnostic.CodeInvalidSeverity, loc,
			"requirement %s, clause %d: invalid severity %q (must be critical, high, medium, low, or empty)",
			reqID, idx, clause.Severity,
		)
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
	if clause.MetadataConditions != nil {
		for j, cond := range clause.MetadataConditions.All {
			compiledCond, err := compileCondition(&cond, reqID, idx, j, sourceFile)
			if err != nil {
				return nil, err
			}
			compiled.Conditions = append(compiled.Conditions, *compiledCond)
		}
	}

	return compiled, nil
}

func compileCondition(cond *raw.RawCondition, reqID string, clauseIdx, condIdx int, sourceFile string) (*CompiledCondition, error) {
	loc := diagnostic.Location{
		File:          sourceFile,
		RequirementID: reqID,
		ClauseIndex:   clauseIdx,
	}

	// Parse operator
	op, err := condition.ParseOperator(cond.Op)
	if err != nil {
		return nil, diagnostic.Errorf(
			diagnostic.CodeInvalidOperator, loc,
			"requirement %s, clause %d, condition %d: %v", reqID, clauseIdx, condIdx, err,
		)
	}

	// Parse cardinality
	cardinality, ok := ValidCardinalities[cond.Cardinality]
	if !ok {
		return nil, diagnostic.Errorf(
			diagnostic.CodeInvalidCardinality, loc,
			"requirement %s, clause %d, condition %d: invalid cardinality %q (must be all, any, none, or empty)",
			reqID, clauseIdx, condIdx, cond.Cardinality,
		)
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
			return nil, diagnostic.Errorf(
				diagnostic.CodeInvalidJSONPath, loc,
				"requirement %s, clause %d, condition %d: %v", reqID, clauseIdx, condIdx, parseErr,
			)
		}

		// Extract base path for element count verification when needed:
		// - cardinality:all requires count check for partial presence detection
		// - exists/not_exists with any cardinality need count comparison
		if cardinality == CardinalityAll ||
			op == condition.OpExists ||
			op == condition.OpNotExists {
			baseExpr = condition.ExtractBasePath(expr)
			// baseExpr may be nil for recursive descent - that's OK, we'll skip the count check
		}
	} else {
		// Single cardinality requires single-value paths
		var parseErr error
		expr, parseErr = condition.ParseJSONPath(cond.Path)
		if parseErr != nil {
			return nil, diagnostic.Errorf(
				diagnostic.CodeInvalidJSONPath, loc,
				"requirement %s, clause %d, condition %d: %v", reqID, clauseIdx, condIdx, parseErr,
			)
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
