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

	var diags []diagnostic.Diagnostic
	if clause.ApplicableWhen != nil {
		gate, gateDiags := compileGate(clause.ApplicableWhen, clause.Type, reqID, idx, sourceFile)
		compiled.Gate = gate
		diags = append(diags, gateDiags...)
	}

	// Compile conditions
	var rawConditions []raw.RawCondition
	if clause.MetadataConditions != nil {
		rawConditions = clause.MetadataConditions.All
	}
	for j, cond := range rawConditions {
		compiledCond, condDiag := compileCondition(&cond, reqID, idx, diagnostic.ListMetadataConditions, j, sourceFile)
		if condDiag == nil && compiled.Gate.HasEach() && compiledCond.IsMulti {
			condDiag = bindToGateList(compiledCond, compiled.Gate.List, reqID, idx, j, sourceFile)
		}
		if condDiag != nil {
			diags = append(diags, *condDiag)
			continue
		}
		compiled.Conditions = append(compiled.Conditions, *compiledCond)
	}

	// A clause with no conditions passes whenever it applies. With each, it
	// would pass as soon as one element qualified and say nothing of the rest.
	if compiled.Gate.HasEach() && len(rawConditions) == 0 {
		for j, cond := range clause.ApplicableWhen.All {
			if ValidCardinalities[cond.Cardinality] == CardinalityEach {
				diags = append(diags, diagnostic.Errorf(
					diagnostic.CodeInvalidGate, gateConditionLocation(sourceFile, reqID, idx, j),
					"requirement %s, clause %d, applicable_when condition %d: cardinality each needs metadata_conditions to grade the elements it admits",
					reqID, idx, j,
				))
				break
			}
		}
	}

	if len(diags) > 0 {
		return nil, diags
	}

	return compiled, nil
}

// compileGate compiles applicable_when. Its each conditions must read the
// clause's own type and range over one shared list.
func compileGate(gate *raw.RawGate, clauseType, reqID string, clauseIdx int, sourceFile string) (*CompiledGate, []diagnostic.Diagnostic) {
	compiled := &CompiledGate{Schema: gate.Type}
	if compiled.Schema == "" {
		compiled.Schema = clauseType
	}

	if len(gate.All) == 0 {
		loc := gateConditionLocation(sourceFile, reqID, clauseIdx, -1)
		return compiled, []diagnostic.Diagnostic{diagnostic.Errorf(
			diagnostic.CodeInvalidGate, loc,
			"requirement %s, clause %d: applicable_when has no conditions", reqID, clauseIdx,
		)}
	}

	var diags []diagnostic.Diagnostic
	for j, cond := range gate.All {
		compiledCond, condDiag := compileCondition(&cond, reqID, clauseIdx, diagnostic.ListApplicableWhen, j, sourceFile)
		if condDiag == nil && compiledCond.Cardinality == CardinalityEach {
			loc := gateConditionLocation(sourceFile, reqID, clauseIdx, j)
			switch {
			case compiled.Schema != clauseType:
				d := diagnostic.Errorf(
					diagnostic.CodeInvalidGate, loc,
					"requirement %s, clause %d, applicable_when condition %d: cardinality each needs applicable_when to read the clause's own type, %s, not %s",
					reqID, clauseIdx, j, clauseType, compiled.Schema,
				)
				condDiag = &d
			case compiled.List == nil:
				compiled.List = compiledCond.BaseExpr
			case compiledCond.BaseExpr.String() != compiled.List.String():
				d := diagnostic.Errorf(
					diagnostic.CodeInvalidGate, loc,
					"requirement %s, clause %d, applicable_when condition %d: every cardinality each condition must range over one list; %s ranges over %s, not %s",
					reqID, clauseIdx, j, cond.Path, compiledCond.BaseExpr, compiled.List,
				)
				condDiag = &d
			}
		}
		if condDiag != nil {
			diags = append(diags, *condDiag)
			continue
		}
		compiled.Conditions = append(compiled.Conditions, *compiledCond)
	}
	return compiled, diags
}

// bindToGateList points a clause condition at the gate's list so it counts
// only the elements the gate admits.
func bindToGateList(cond *CompiledCondition, list jp.Expr, reqID string, clauseIdx, condIdx int, sourceFile string) *diagnostic.Diagnostic {
	condList, element, ok := condition.SplitAtWildcard(cond.Expr)
	if !ok || condList.String() != list.String() {
		loc := diagnostic.Location{
			File:           sourceFile,
			RequirementID:  reqID,
			ClauseIndex:    clauseIdx,
			ConditionList:  diagnostic.ListMetadataConditions,
			ConditionIndex: condIdx,
		}
		d := diagnostic.Errorf(
			diagnostic.CodeInvalidGate, loc,
			"requirement %s, clause %d, condition %d: applicable_when checks each element of %s, so list conditions must read that list with one [*]; %s does not",
			reqID, clauseIdx, condIdx, list, cond.Path,
		)
		return &d
	}
	cond.Element = element
	return nil
}

func gateConditionLocation(sourceFile, reqID string, clauseIdx, condIdx int) diagnostic.Location {
	return diagnostic.Location{
		File:           sourceFile,
		RequirementID:  reqID,
		ClauseIndex:    clauseIdx,
		ConditionList:  diagnostic.ListApplicableWhen,
		ConditionIndex: condIdx,
	}
}

func compileCondition(cond *raw.RawCondition, reqID string, clauseIdx int, list string, condIdx int, sourceFile string) (*CompiledCondition, *diagnostic.Diagnostic) {
	loc := diagnostic.Location{
		File:           sourceFile,
		RequirementID:  reqID,
		ClauseIndex:    clauseIdx,
		ConditionList:  list,
		ConditionIndex: condIdx,
	}
	at := fmt.Sprintf("requirement %s, clause %d, condition %d", reqID, clauseIdx, condIdx)
	if list == diagnostic.ListApplicableWhen {
		at = fmt.Sprintf("requirement %s, clause %d, applicable_when condition %d", reqID, clauseIdx, condIdx)
	}

	// Parse operator
	op, err := condition.ParseOperator(cond.Op)
	if err != nil {
		d := diagnostic.Errorf(diagnostic.CodeInvalidOperator, loc, "%s: %v", at, err)
		return nil, &d
	}

	if op == condition.OpMaxAgeDays {
		if maxDays, numOK := condition.NormalizeNumeric(cond.Value); !numOK || maxDays < 0 {
			d := diagnostic.Errorf(
				diagnostic.CodeInvalidFieldType, loc,
				"%s: max_age_days requires a non-negative numeric value, got %v", at, cond.Value,
			)
			return nil, &d
		}
	}

	// Parse cardinality
	cardinality, ok := ValidCardinalities[cond.Cardinality]
	if !ok {
		allowed := "all, any, none, or empty"
		if list == diagnostic.ListApplicableWhen {
			allowed = "all, any, none, each, or empty"
		}
		d := diagnostic.Errorf(
			diagnostic.CodeInvalidCardinality, loc,
			"%s: invalid cardinality %q (must be %s)", at, cond.Cardinality, allowed,
		)
		return nil, &d
	}
	if cardinality == CardinalityEach && list != diagnostic.ListApplicableWhen {
		d := diagnostic.Errorf(
			diagnostic.CodeInvalidCardinality, loc,
			"%s: cardinality each is allowed only in applicable_when", at,
		)
		return nil, &d
	}

	// Parse JSONPath - allow multi-value if cardinality is specified
	var expr jp.Expr
	var baseExpr jp.Expr
	var element jp.Expr
	var isMulti bool

	if cardinality != CardinalitySingle {
		// Multi-value cardinality allows multi-value paths
		var parseErr error
		expr, isMulti, parseErr = condition.ParseJSONPathMulti(cond.Path)
		if parseErr != nil {
			d := diagnostic.Errorf(diagnostic.CodeInvalidJSONPath, loc, "%s: %v", at, parseErr)
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

		if cardinality == CardinalityEach {
			var split bool
			baseExpr, element, split = condition.SplitAtWildcard(expr)
			if !split {
				d := diagnostic.Errorf(
					diagnostic.CodeInvalidGate, loc,
					"%s: cardinality each needs a path with exactly one [*] and no other multi-value syntax, got %q", at, cond.Path,
				)
				return nil, &d
			}
		}
	} else {
		// Single cardinality requires single-value paths
		var parseErr error
		expr, parseErr = condition.ParseJSONPath(cond.Path)
		if parseErr != nil {
			d := diagnostic.Errorf(diagnostic.CodeInvalidJSONPath, loc, "%s: %v", at, parseErr)
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
		Element:     element,
	}, nil
}
