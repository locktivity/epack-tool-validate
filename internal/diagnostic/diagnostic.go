// Package diagnostic provides structured errors and findings for all stages.
package diagnostic

import "fmt"

// Severity indicates how serious the issue is.
type Severity int

const (
	SeverityError   Severity = iota // Stops processing
	SeverityWarning                 // Continues but noted
	SeverityInfo                    // Informational
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// Diagnostic is a structured issue from any stage.
type Diagnostic struct {
	Code     string   // Stable machine-readable code (e.g., "E001", "OVERLAY_TARGET_MISSING")
	Severity Severity // How serious the issue is
	Message  string   // Human-readable description
	Location Location // Where the issue occurred
}

// Location identifies where in the input the issue occurred.
type Location struct {
	File          string // Source file path
	RequirementID string // If applicable
	ClauseIndex   int    // If applicable (-1 if not)
	Line          int    // YAML line number if known (-1 if not)
}

// NewLocation creates a location with default values for optional fields.
func NewLocation(file string) Location {
	return Location{
		File:        file,
		ClauseIndex: -1,
		Line:        -1,
	}
}

// Error implements the error interface.
func (d Diagnostic) Error() string {
	if d.Location.File != "" {
		return fmt.Sprintf("%s: %s: %s", d.Location.File, d.Code, d.Message)
	}
	return fmt.Sprintf("%s: %s", d.Code, d.Message)
}

// Diagnostic codes for profile parsing and compilation.
const (
	// Parsing errors
	CodeInvalidYAML      = "INVALID_YAML"
	CodeMissingField     = "MISSING_FIELD"
	CodeInvalidFieldType = "INVALID_FIELD_TYPE"
	CodeUnknownField     = "UNKNOWN_FIELD"

	// Overlay errors
	CodeOverlayTargetMissing = "OVERLAY_TARGET_MISSING"
	CodeOverlayDuplicateID   = "OVERLAY_DUPLICATE_ID"
	CodeOverlayConflict      = "OVERLAY_CONFLICT"

	// Compilation errors
	CodeInvalidClauseMode    = "INVALID_CLAUSE_MODE"
	CodeEmptyClauses         = "EMPTY_CLAUSES"
	CodeMissingType          = "MISSING_TYPE"
	CodeInvalidSeverity      = "INVALID_SEVERITY"
	CodeInvalidOperator      = "INVALID_OPERATOR"
	CodeInvalidJSONPath      = "INVALID_JSONPATH"
	CodeInvalidCardinality   = "INVALID_CARDINALITY"
	CodeDuplicateRequirement = "DUPLICATE_REQUIREMENT"
)

// Errorf creates an error diagnostic with the given code, location, and formatted message.
func Errorf(code string, loc Location, format string, args ...any) Diagnostic {
	return Diagnostic{
		Code:     code,
		Severity: SeverityError,
		Message:  fmt.Sprintf(format, args...),
		Location: loc,
	}
}

// Warnf creates a warning diagnostic.
func Warnf(code string, loc Location, format string, args ...any) Diagnostic {
	return Diagnostic{
		Code:     code,
		Severity: SeverityWarning,
		Message:  fmt.Sprintf(format, args...),
		Location: loc,
	}
}
