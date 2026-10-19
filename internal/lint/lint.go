// Package lint checks a profile for mistakes that compile cleanly but can
// never produce a meaningful result: fields the evidence does not have,
// comparisons the field's type can never satisfy, and tests that pass when
// there is nothing to test.
package lint

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/diagnostic"
	"github.com/locktivity/epack-tool-validate/internal/evidenceschema"
	"github.com/locktivity/epack-tool-validate/internal/fileref"
	"github.com/locktivity/epack-tool-validate/internal/limits"
	"github.com/locktivity/epack-tool-validate/internal/profile"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/locktivity/epack-tool-validate/internal/profile/raw"
	"github.com/ohler55/ojg/jp"
)

// Codes for findings lint adds beyond the compiler's own.
const (
	CodeProfileLoad      = "PROFILE_LOAD_FAILED"
	CodeOverlay          = "OVERLAY_FAILED"
	CodeSchemaLoad       = "SCHEMA_LOAD_FAILED"
	CodeUnknownPath      = "UNKNOWN_PATH"
	CodePathShape        = "PATH_SHAPE"
	CodePathUnchecked    = "PATH_UNCHECKED"
	CodeTypeUnchecked    = "TYPE_UNCHECKED"
	CodeOperatorMismatch = "OPERATOR_TYPE_MISMATCH"
	CodeMissingValue     = "MISSING_VALUE"
	CodeNeverMatches     = "NEVER_MATCHES"
	CodeAlwaysMatches    = "ALWAYS_MATCHES"
	CodeVacuousPass      = "VACUOUS_PASS"
	CodeFreshnessIgnored = "FRESHNESS_IGNORED"
)

// Options says what to lint.
type Options struct {
	ProjectRoot  string
	ProfilePath  string
	OverlayPaths []string
	// SchemaPaths maps artifact types to JSON Schema files, relative to
	// ProjectRoot. They add types the tool does not bundle and replace
	// bundled schemas for the types they name.
	SchemaPaths map[string]string
}

// Run lints a profile and its overlays. Problems with the profile are
// findings in the report; the error is reserved for the tool itself failing.
func Run(opts Options) (*Report, error) {
	registry, err := evidenceschema.Bundled()
	if err != nil {
		return nil, err
	}

	report := newReport(opts)
	for typ, path := range opts.SchemaPaths {
		ref, err := fileref.Load(opts.ProjectRoot, path, limits.ArtifactSchemaFile)
		if err == nil {
			err = registry.Add(typ, ref.Data, path)
		}
		if err != nil {
			report.add(Diagnostic{
				Severity: SeverityError,
				Code:     CodeSchemaLoad,
				Message:  fmt.Sprintf("schema for %s could not be loaded: %v", typ, err),
				File:     path,
				Type:     typ,
			})
		}
	}

	bundle, err := profile.LoadBundle(opts.ProjectRoot, opts.ProfilePath, opts.OverlayPaths)
	if err != nil {
		report.add(Diagnostic{Severity: SeverityError, Code: CodeProfileLoad, Message: err.Error(), File: opts.ProfilePath})
		return report.finish(), nil
	}
	report.Profile.Digest = bundle.Digest()

	merged, err := bundle.Merge()
	if err != nil {
		report.add(Diagnostic{Severity: SeverityError, Code: CodeOverlay, Message: err.Error(), File: opts.ProfilePath})
		return report.finish(), nil
	}
	report.Profile.ID = merged.ID
	report.Profile.Name = merged.Name
	report.Profile.Version = merged.Version

	l := &linter{report: report, registry: registry, defaultFile: bundle.ProfilePath(), positions: map[string]int{}}
	for i := len(merged.Requirements) - 1; i >= 0; i-- {
		l.positions[merged.Requirements[i].ID] = i
	}
	l.checkProfileFields(merged)
	broken := l.compileFindings(merged)
	for i := range merged.Requirements {
		l.checkRequirement(&merged.Requirements[i], broken)
	}
	return report.finish(), nil
}

type linter struct {
	report      *Report
	registry    *evidenceschema.Registry
	defaultFile string
	positions   map[string]int
}

func (l *linter) add(d Diagnostic) {
	d.order = -1
	if position, ok := l.positions[d.Requirement]; ok && d.Requirement != "" {
		d.order = position
	}
	l.report.add(d)
}

type conditionKey struct {
	requirement string
	clause      int
	condition   int
}

func (l *linter) checkProfileFields(p *raw.RawProfile) {
	if p.Version == "" {
		l.add(Diagnostic{
			Severity: SeverityError,
			Code:     diagnostic.CodeMissingField,
			Message:  "profile has no version",
			File:     l.defaultFile,
		})
	}
	for i, req := range p.Requirements {
		file := l.fileFor(&req)
		if req.ID == "" && !req.Manual {
			l.add(Diagnostic{
				Severity: SeverityError,
				Code:     diagnostic.CodeMissingField,
				Message:  fmt.Sprintf("requirement %d has no id; ids are how results, overlays and mappings refer to it", i+1),
				File:     file,
				Location: fmt.Sprintf("requirements[%d]", i),
			})
		}
		if req.Name == "" {
			l.add(Diagnostic{
				Severity:    SeverityError,
				Code:        diagnostic.CodeMissingField,
				Message:     "requirement has no name; the name is the statement a reviewer reads",
				File:        file,
				Requirement: req.ID,
				Location:    fmt.Sprintf("requirements[%d]", i),
			})
		}
	}
}

// compileFindings reports everything the compiler rejects and returns the
// conditions it rejected, which the schema checks then skip.
func (l *linter) compileFindings(p *raw.RawProfile) map[conditionKey]bool {
	broken := map[conditionKey]bool{}
	for _, d := range compiled.Diagnose(p, l.defaultFile) {
		finding := Diagnostic{
			Severity:    SeverityError,
			Code:        d.Code,
			Message:     compilerLocationPrefix.ReplaceAllString(d.Message, ""),
			File:        d.Location.File,
			Requirement: d.Location.RequirementID,
		}
		if isConditionCode(d.Code) {
			broken[conditionKey{d.Location.RequirementID, d.Location.ClauseIndex, d.Location.ConditionIndex}] = true
			finding.Location = l.conditionLocation(p, d.Location.RequirementID, d.Location.ClauseIndex, d.Location.ConditionIndex)
		} else if isClauseCode(d.Code) {
			broken[conditionKey{d.Location.RequirementID, d.Location.ClauseIndex, -1}] = true
			finding.Location = l.clauseLocation(p, d.Location.RequirementID, d.Location.ClauseIndex)
		} else {
			broken[conditionKey{d.Location.RequirementID, -1, -1}] = true
		}
		l.add(finding)
	}
	return broken
}

// compilerLocationPrefix matches the "requirement X, clause N, condition M: "
// lead-in compiler messages carry; lint reports the location separately.
var compilerLocationPrefix = regexp.MustCompile(`^requirement [^:]*: `)

func isConditionCode(code string) bool {
	switch code {
	case diagnostic.CodeInvalidOperator, diagnostic.CodeInvalidCardinality, diagnostic.CodeInvalidJSONPath, diagnostic.CodeInvalidFieldType:
		return true
	}
	return false
}

func isClauseCode(code string) bool {
	return code == diagnostic.CodeMissingType || code == diagnostic.CodeInvalidSeverity
}

func (l *linter) checkRequirement(req *raw.RawRequirement, broken map[conditionKey]bool) {
	if req.Manual || broken[conditionKey{req.ID, -1, -1}] {
		return
	}
	mode, clauses := clausesOf(req)
	for ci, clause := range clauses {
		if broken[conditionKey{req.ID, ci, -1}] {
			continue
		}
		if clause.Freshness != nil && clause.Freshness.MaxAgeDays <= 0 {
			l.add(Diagnostic{
				Severity:    SeverityWarning,
				Code:        CodeFreshnessIgnored,
				Message:     "freshness.max_age_days must be at least 1; a smaller value is ignored, so the artifact's age is not checked",
				File:        l.fileFor(req),
				Requirement: req.ID,
				Location:    fmt.Sprintf("%s[%d].freshness", mode, ci),
				Type:        clause.Type,
			})
		}
		if clause.MetadataConditions == nil || len(clause.MetadataConditions.All) == 0 {
			continue
		}
		schema := l.registry.Lookup(clause.Type)
		if schema == nil {
			l.add(Diagnostic{
				Severity:    SeverityWarning,
				Code:        CodeTypeUnchecked,
				Message:     fmt.Sprintf("no schema is known for %s, so its paths were not checked; pass one under the schemas option", clause.Type),
				File:        l.fileFor(req),
				Requirement: req.ID,
				Location:    fmt.Sprintf("%s[%d]", mode, ci),
				Type:        clause.Type,
			})
		}
		for di := range clause.MetadataConditions.All {
			if broken[conditionKey{req.ID, ci, di}] {
				continue
			}
			l.checkCondition(req, schema, clause.Type, &clause.MetadataConditions.All[di], fmt.Sprintf("%s[%d].metadata_conditions.all[%d]", mode, ci, di))
		}
	}
}

func (l *linter) checkCondition(req *raw.RawRequirement, schema *evidenceschema.Schema, typ string, cond *raw.RawCondition, location string) {
	at := func(severity, code, message string, suggestions ...string) {
		l.add(Diagnostic{
			Severity:    severity,
			Code:        code,
			Message:     message,
			File:        l.fileFor(req),
			Requirement: req.ID,
			Location:    location,
			Path:        cond.Path,
			Type:        typ,
			Suggestions: suggestions,
		})
	}

	op, _ := condition.ParseOperator(cond.Op)
	cardinality := compiled.ValidCardinalities[cond.Cardinality]

	if cond.Value == nil && op != condition.OpExists && op != condition.OpNotExists {
		at(SeverityError, CodeMissingValue, fmt.Sprintf("%s needs a value to compare against", op))
	}
	if message := vacuousPass(op, cardinality); message != "" {
		at(SeverityWarning, CodeVacuousPass, message)
	}

	if schema == nil {
		return
	}
	expr, _ := jp.ParseString(cond.Path)
	node, err := schema.Resolve(expr)
	if err != nil {
		var unknown *evidenceschema.UnknownFieldError
		var shape *evidenceschema.ShapeError
		var unchecked *evidenceschema.UncheckedError
		switch {
		case errors.As(err, &unknown):
			parent := unknown.Parent
			if parent == "$" {
				parent = "the top level"
			}
			at(SeverityError, CodeUnknownPath,
				fmt.Sprintf("%s has no field %q in %s; declared fields there: %s", parent, unknown.Field, typ, strings.Join(unknown.Known, ", ")),
				unknown.Suggestions...)
		case errors.As(err, &shape):
			at(SeverityError, CodePathShape, shape.Error())
		case errors.As(err, &unchecked):
			at(SeverityWarning, CodePathUnchecked, unchecked.Reason)
		default:
			at(SeverityWarning, CodePathUnchecked, err.Error())
		}
		return
	}
	if node.Open || cond.Value == nil {
		return
	}

	switch op {
	case condition.OpGt, condition.OpGte, condition.OpLt, condition.OpLte:
		if !node.Allows("number") {
			at(SeverityError, CodeOperatorMismatch, fmt.Sprintf("%s compares numbers, but %s is %s", op, cond.Path, article(describeTypes(node))))
		} else if _, ok := condition.NormalizeNumeric(cond.Value); !ok {
			at(SeverityError, CodeNeverMatches, fmt.Sprintf("%s needs a numeric value, got %s", op, formatValue(cond.Value)))
		}
	case condition.OpMaxAgeDays:
		if !node.Allows("string") {
			at(SeverityError, CodeOperatorMismatch, fmt.Sprintf("max_age_days reads a date or timestamp string, but %s is %s", cond.Path, article(describeTypes(node))))
		}
	case condition.OpEq, condition.OpNeq:
		if reason := impossibleValue(node, cond.Value); reason != "" {
			if op == condition.OpEq {
				at(SeverityError, CodeNeverMatches, fmt.Sprintf("eq can never pass: %s", reason))
			} else {
				at(SeverityWarning, CodeAlwaysMatches, fmt.Sprintf("neq always passes: %s", reason))
			}
		}
	}
}

// vacuousPass names the condition shapes that pass when there is nothing to
// test: an empty list, or a field that was never collected.
func vacuousPass(op condition.Operator, cardinality compiled.Cardinality) string {
	switch {
	case op == condition.OpNotExists && cardinality == compiled.CardinalitySingle:
		return "not_exists also passes when the field was never collected; pair it with an exists condition on a field that is always present"
	case op == condition.OpNotExists && cardinality == compiled.CardinalityAll:
		return "not_exists with cardinality all passes when the list is empty or absent; add a condition that the list has entries"
	case op == condition.OpExists && cardinality == compiled.CardinalityNone:
		return "exists with cardinality none passes when the list is empty; add a condition that the list has entries"
	case op != condition.OpExists && op != condition.OpNotExists && cardinality == compiled.CardinalityNone:
		return "cardinality none passes when the list is empty; add a condition that the list has entries"
	}
	return ""
}

func impossibleValue(node *evidenceschema.Node, value any) string {
	valueType := evidenceschema.JSONType(value)
	if node.OnlyContainers() && valueType != "object" && valueType != "array" {
		return fmt.Sprintf("the path is %s, not a single value; compare a field inside it", article(describeTypes(node)))
	}
	if node.Enum != nil {
		if slices.ContainsFunc(node.Enum, func(allowed any) bool { return condition.OpEq.Apply(allowed, value) }) {
			return ""
		}
		return fmt.Sprintf("%s is not one of the allowed values: %s", formatValue(value), formatValues(node.Enum))
	}
	if !node.Allows(valueType) {
		return fmt.Sprintf("the value %s is %s, but the field is %s", formatValue(value), article(valueType), article(describeTypes(node)))
	}
	return ""
}

func formatValue(v any) string {
	if s, ok := v.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%v", v)
}

func formatValues(values []any) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = formatValue(v)
	}
	return strings.Join(parts, ", ")
}

func article(typeName string) string {
	if typeName == "" {
		return typeName
	}
	switch typeName[0] {
	case 'a', 'e', 'i', 'o', 'u':
		return "an " + typeName
	}
	return "a " + typeName
}

func describeTypes(node *evidenceschema.Node) string {
	if len(node.Types) == 0 {
		return "untyped"
	}
	types := slices.DeleteFunc(slices.Clone(node.Types), func(t string) bool { return t == "null" })
	if len(types) < len(node.Types) {
		types = append(types, "null")
	}
	return strings.Join(types, " or ")
}

func clausesOf(req *raw.RawRequirement) (string, []raw.RawClause) {
	if len(req.SatisfiedBy.AnyOf) > 0 {
		return "any_of", req.SatisfiedBy.AnyOf
	}
	return "all_of", req.SatisfiedBy.AllOf
}

func (l *linter) fileFor(req *raw.RawRequirement) string {
	if req.SourceFile != "" {
		return req.SourceFile
	}
	return l.defaultFile
}

func (l *linter) findRequirement(p *raw.RawProfile, id string) *raw.RawRequirement {
	for i := range p.Requirements {
		if p.Requirements[i].ID == id {
			return &p.Requirements[i]
		}
	}
	return nil
}

func (l *linter) clauseLocation(p *raw.RawProfile, reqID string, clause int) string {
	req := l.findRequirement(p, reqID)
	if req == nil {
		return ""
	}
	mode, _ := clausesOf(req)
	return fmt.Sprintf("%s[%d]", mode, clause)
}

func (l *linter) conditionLocation(p *raw.RawProfile, reqID string, clause, cond int) string {
	base := l.clauseLocation(p, reqID, clause)
	if base == "" {
		return ""
	}
	return fmt.Sprintf("%s.metadata_conditions.all[%d]", base, cond)
}
