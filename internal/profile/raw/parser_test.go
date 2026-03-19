package raw

import (
	"strings"
	"testing"
)

func TestParseProfileFromBytes(t *testing.T) {
	t.Run("valid profile", func(t *testing.T) {
		data := []byte(`
id: test-profile
name: Test Profile
version: "1.0.0"
description: A test profile
requirements:
  - id: REQ-001
    name: Test Requirement
    control: TEST-1.1
    category: Testing
    satisfied_by:
      any_of:
        - type: evidencepack/test@v1
          metadata_conditions:
            all:
              - path: $.enabled
                op: eq
                value: true
`)
		profile, err := ParseProfileFromBytes(data)
		if err != nil {
			t.Errorf("ParseProfileFromBytes() unexpected error: %v", err)
		}
		if profile.ID != "test-profile" {
			t.Errorf("ID = %q, want %q", profile.ID, "test-profile")
		}
		if profile.Name != "Test Profile" {
			t.Errorf("Name = %q, want %q", profile.Name, "Test Profile")
		}
		if profile.Version != "1.0.0" {
			t.Errorf("Version = %q, want %q", profile.Version, "1.0.0")
		}
		if len(profile.Requirements) != 1 {
			t.Errorf("Requirements count = %d, want 1", len(profile.Requirements))
		}
	})

	t.Run("missing id", func(t *testing.T) {
		data := []byte(`
name: Test Profile
version: "1.0.0"
requirements:
  - id: REQ-001
    name: Test
    satisfied_by:
      any_of:
        - type: test@v1
`)
		_, err := ParseProfileFromBytes(data)
		if err == nil {
			t.Error("ParseProfileFromBytes() should reject profile without id")
		}
		if !strings.Contains(err.Error(), "id") {
			t.Errorf("error should mention 'id', got: %v", err)
		}
	})

	t.Run("missing name", func(t *testing.T) {
		data := []byte(`
id: test-profile
version: "1.0.0"
requirements:
  - id: REQ-001
    name: Test
    satisfied_by:
      any_of:
        - type: test@v1
`)
		_, err := ParseProfileFromBytes(data)
		if err == nil {
			t.Error("ParseProfileFromBytes() should reject profile without name")
		}
		if !strings.Contains(err.Error(), "name") {
			t.Errorf("error should mention 'name', got: %v", err)
		}
	})

	t.Run("no requirements", func(t *testing.T) {
		data := []byte(`
id: test-profile
name: Test Profile
version: "1.0.0"
requirements: []
`)
		_, err := ParseProfileFromBytes(data)
		if err == nil {
			t.Error("ParseProfileFromBytes() should reject profile without requirements")
		}
		if !strings.Contains(err.Error(), "requirements") {
			t.Errorf("error should mention 'requirements', got: %v", err)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		data := []byte(`
id: test
name: [unclosed
`)
		_, err := ParseProfileFromBytes(data)
		if err == nil {
			t.Error("ParseProfileFromBytes() should reject invalid YAML")
		}
	})

	t.Run("unknown field rejected (strict)", func(t *testing.T) {
		data := []byte(`
id: test-profile
name: Test Profile
version: "1.0.0"
unknown_field: should fail
requirements:
  - id: REQ-001
    name: Test
    satisfied_by:
      any_of:
        - type: test@v1
`)
		_, err := ParseProfileFromBytes(data)
		if err == nil {
			t.Error("ParseProfileFromBytes() should reject unknown fields in strict mode")
		}
	})

	t.Run("requirement with all_of", func(t *testing.T) {
		data := []byte(`
id: test-profile
name: Test Profile
version: "1.0.0"
requirements:
  - id: REQ-001
    name: Test Requirement
    satisfied_by:
      all_of:
        - type: evidencepack/type1@v1
        - type: evidencepack/type2@v1
`)
		profile, err := ParseProfileFromBytes(data)
		if err != nil {
			t.Errorf("ParseProfileFromBytes() unexpected error: %v", err)
		}
		if len(profile.Requirements[0].SatisfiedBy.AllOf) != 2 {
			t.Errorf("AllOf count = %d, want 2", len(profile.Requirements[0].SatisfiedBy.AllOf))
		}
	})

	t.Run("clause with severity", func(t *testing.T) {
		data := []byte(`
id: test-profile
name: Test Profile
version: "1.0.0"
requirements:
  - id: REQ-001
    name: Test Requirement
    satisfied_by:
      any_of:
        - type: evidencepack/test@v1
          severity: high
`)
		profile, err := ParseProfileFromBytes(data)
		if err != nil {
			t.Errorf("ParseProfileFromBytes() unexpected error: %v", err)
		}
		if profile.Requirements[0].SatisfiedBy.AnyOf[0].Severity != "high" {
			t.Errorf("Severity = %q, want %q", profile.Requirements[0].SatisfiedBy.AnyOf[0].Severity, "high")
		}
	})

	t.Run("clause with freshness", func(t *testing.T) {
		data := []byte(`
id: test-profile
name: Test Profile
version: "1.0.0"
requirements:
  - id: REQ-001
    name: Test Requirement
    satisfied_by:
      any_of:
        - type: evidencepack/test@v1
          freshness:
            max_age_days: 30
`)
		profile, err := ParseProfileFromBytes(data)
		if err != nil {
			t.Errorf("ParseProfileFromBytes() unexpected error: %v", err)
		}
		freshness := profile.Requirements[0].SatisfiedBy.AnyOf[0].Freshness
		if freshness == nil {
			t.Fatal("Freshness should not be nil")
		}
		if freshness.MaxAgeDays != 30 {
			t.Errorf("MaxAgeDays = %d, want 30", freshness.MaxAgeDays)
		}
	})
}

func TestParseOverlayFromBytes(t *testing.T) {
	t.Run("valid overlay with modify", func(t *testing.T) {
		data := []byte(`
id: test-overlay
name: Test Overlay
modify:
  - id: REQ-001
    name: Modified Requirement
`)
		overlay, err := ParseOverlayFromBytes(data)
		if err != nil {
			t.Errorf("ParseOverlayFromBytes() unexpected error: %v", err)
		}
		if overlay.ID != "test-overlay" {
			t.Errorf("ID = %q, want %q", overlay.ID, "test-overlay")
		}
		if len(overlay.Modify) != 1 {
			t.Errorf("Modify count = %d, want 1", len(overlay.Modify))
		}
	})

	t.Run("valid overlay with skip", func(t *testing.T) {
		data := []byte(`
skip:
  - REQ-001
  - REQ-002
`)
		overlay, err := ParseOverlayFromBytes(data)
		if err != nil {
			t.Errorf("ParseOverlayFromBytes() unexpected error: %v", err)
		}
		if len(overlay.Skip) != 2 {
			t.Errorf("Skip count = %d, want 2", len(overlay.Skip))
		}
	})

	t.Run("valid overlay with add", func(t *testing.T) {
		data := []byte(`
add:
  - id: REQ-NEW
    name: New Requirement
    satisfied_by:
      any_of:
        - type: evidencepack/new@v1
`)
		overlay, err := ParseOverlayFromBytes(data)
		if err != nil {
			t.Errorf("ParseOverlayFromBytes() unexpected error: %v", err)
		}
		if len(overlay.Add) != 1 {
			t.Errorf("Add count = %d, want 1", len(overlay.Add))
		}
		if overlay.Add[0].ID != "REQ-NEW" {
			t.Errorf("Add[0].ID = %q, want %q", overlay.Add[0].ID, "REQ-NEW")
		}
	})

	t.Run("minimal overlay", func(t *testing.T) {
		// An overlay with just an empty object
		data := []byte(`{}`)
		overlay, err := ParseOverlayFromBytes(data)
		if err != nil {
			t.Errorf("ParseOverlayFromBytes() unexpected error: %v", err)
			return
		}
		if overlay == nil {
			t.Fatal("overlay should not be nil")
		}
		if len(overlay.Modify) != 0 || len(overlay.Skip) != 0 || len(overlay.Add) != 0 {
			t.Error("minimal overlay should have no directives")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		data := []byte(`
modify:
  - [invalid
`)
		_, err := ParseOverlayFromBytes(data)
		if err == nil {
			t.Error("ParseOverlayFromBytes() should reject invalid YAML")
		}
	})
}
