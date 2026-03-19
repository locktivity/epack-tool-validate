package diagnostic

import (
	"strings"
	"testing"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityError, "error"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "info"},
		{Severity(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("Severity.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewLocation(t *testing.T) {
	loc := NewLocation("test.yaml")

	if loc.File != "test.yaml" {
		t.Errorf("File = %q, want %q", loc.File, "test.yaml")
	}
	if loc.RequirementID != "" {
		t.Errorf("RequirementID = %q, want empty", loc.RequirementID)
	}
	if loc.ClauseIndex != -1 {
		t.Errorf("ClauseIndex = %d, want -1", loc.ClauseIndex)
	}
	if loc.Line != -1 {
		t.Errorf("Line = %d, want -1", loc.Line)
	}
}

func TestDiagnostic_Error(t *testing.T) {
	t.Run("with file location", func(t *testing.T) {
		d := Diagnostic{
			Code:     "E001",
			Severity: SeverityError,
			Message:  "something went wrong",
			Location: Location{File: "test.yaml"},
		}

		got := d.Error()
		if !strings.Contains(got, "test.yaml") {
			t.Errorf("Error() should contain file name, got: %q", got)
		}
		if !strings.Contains(got, "E001") {
			t.Errorf("Error() should contain code, got: %q", got)
		}
		if !strings.Contains(got, "something went wrong") {
			t.Errorf("Error() should contain message, got: %q", got)
		}
	})

	t.Run("without file location", func(t *testing.T) {
		d := Diagnostic{
			Code:     "E002",
			Severity: SeverityError,
			Message:  "error message",
			Location: Location{},
		}

		got := d.Error()
		want := "E002: error message"
		if got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

func TestErrorf(t *testing.T) {
	loc := Location{File: "profile.yaml", RequirementID: "REQ-001"}
	d := Errorf(CodeMissingField, loc, "field %q is required", "name")

	if d.Code != CodeMissingField {
		t.Errorf("Code = %q, want %q", d.Code, CodeMissingField)
	}
	if d.Severity != SeverityError {
		t.Errorf("Severity = %v, want SeverityError", d.Severity)
	}
	if !strings.Contains(d.Message, "name") {
		t.Errorf("Message should contain formatted arg, got: %q", d.Message)
	}
	if d.Location.File != "profile.yaml" {
		t.Errorf("Location.File = %q, want %q", d.Location.File, "profile.yaml")
	}
	if d.Location.RequirementID != "REQ-001" {
		t.Errorf("Location.RequirementID = %q, want %q", d.Location.RequirementID, "REQ-001")
	}
}

func TestWarnf(t *testing.T) {
	loc := NewLocation("overlay.yaml")
	d := Warnf(CodeOverlayConflict, loc, "conflicting modifications")

	if d.Code != CodeOverlayConflict {
		t.Errorf("Code = %q, want %q", d.Code, CodeOverlayConflict)
	}
	if d.Severity != SeverityWarning {
		t.Errorf("Severity = %v, want SeverityWarning", d.Severity)
	}
	if d.Message != "conflicting modifications" {
		t.Errorf("Message = %q, want %q", d.Message, "conflicting modifications")
	}
}

func TestDiagnosticCodes(t *testing.T) {
	// Verify all codes are non-empty and unique
	codes := []string{
		CodeInvalidYAML,
		CodeMissingField,
		CodeInvalidFieldType,
		CodeUnknownField,
		CodeOverlayTargetMissing,
		CodeOverlayDuplicateID,
		CodeOverlayConflict,
		CodeInvalidClauseMode,
		CodeEmptyClauses,
		CodeMissingType,
		CodeInvalidSeverity,
		CodeInvalidOperator,
		CodeInvalidJSONPath,
		CodeDuplicateRequirement,
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if code == "" {
			t.Error("diagnostic code should not be empty")
		}
		if seen[code] {
			t.Errorf("duplicate diagnostic code: %q", code)
		}
		seen[code] = true
	}
}

func TestDiagnostic_AsError(t *testing.T) {
	// Verify Diagnostic can be used as an error
	var err error = Diagnostic{
		Code:     "TEST",
		Severity: SeverityError,
		Message:  "test error",
	}

	if err.Error() != "TEST: test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "TEST: test error")
	}
}

func TestLocation_WithAllFields(t *testing.T) {
	loc := Location{
		File:          "profile.yaml",
		RequirementID: "REQ-123",
		ClauseIndex:   2,
		Line:          42,
	}

	d := Errorf("CODE", loc, "message")

	if d.Location.File != "profile.yaml" {
		t.Errorf("File = %q", d.Location.File)
	}
	if d.Location.RequirementID != "REQ-123" {
		t.Errorf("RequirementID = %q", d.Location.RequirementID)
	}
	if d.Location.ClauseIndex != 2 {
		t.Errorf("ClauseIndex = %d", d.Location.ClauseIndex)
	}
	if d.Location.Line != 42 {
		t.Errorf("Line = %d", d.Location.Line)
	}
}
