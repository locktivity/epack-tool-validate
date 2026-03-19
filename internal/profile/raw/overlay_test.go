package raw

import (
	"strings"
	"testing"
)

func makeTestProfile() *RawProfile {
	return &RawProfile{
		ID:          "test-profile",
		Name:        "Test Profile",
		Version:     "1.0.0",
		Description: "A test profile",
		Requirements: []RawRequirement{
			{
				ID:       "REQ-001",
				Name:     "First Requirement",
				Control:  "CTRL-1",
				Category: "Category A",
				SatisfiedBy: RawSatisfiedBy{
					AnyOf: []RawClause{
						{Type: "evidencepack/test@v1"},
					},
				},
			},
			{
				ID:       "REQ-002",
				Name:     "Second Requirement",
				Control:  "CTRL-2",
				Category: "Category B",
				SatisfiedBy: RawSatisfiedBy{
					AnyOf: []RawClause{
						{Type: "evidencepack/other@v1"},
					},
				},
			},
		},
	}
}

func TestApplyOverlays(t *testing.T) {
	t.Run("no overlays", func(t *testing.T) {
		base := makeTestProfile()
		result, err := ApplyOverlays(base, nil)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if result.ID != base.ID {
			t.Errorf("ID = %q, want %q", result.ID, base.ID)
		}
		if len(result.Requirements) != 2 {
			t.Errorf("Requirements count = %d, want 2", len(result.Requirements))
		}
	})

	t.Run("nil base profile", func(t *testing.T) {
		_, err := ApplyOverlays(nil, nil)
		if err == nil {
			t.Error("ApplyOverlays() should reject nil base profile")
		}
	})

	t.Run("skip requirement", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Skip: []string{"REQ-001"},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if len(result.Requirements) != 1 {
			t.Errorf("Requirements count = %d, want 1", len(result.Requirements))
		}
		if result.Requirements[0].ID != "REQ-002" {
			t.Errorf("Remaining requirement ID = %q, want %q", result.Requirements[0].ID, "REQ-002")
		}
	})

	t.Run("skip nonexistent requirement fails", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Skip: []string{"REQ-NONEXISTENT"},
			},
		}
		_, err := ApplyOverlays(base, overlays)
		if err == nil {
			t.Error("ApplyOverlays() should fail when skip target doesn't exist")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention 'not found', got: %v", err)
		}
	})

	t.Run("modify replaces entire requirement", func(t *testing.T) {
		base := makeTestProfile()
		// Modify replaces the entire requirement - must specify all desired fields
		overlays := []*RawOverlay{
			{
				Modify: []RawModify{
					{
						ID:      "REQ-001",
						Name:    "Modified Requirement Name",
						Control: "CTRL-NEW", // Must specify - not preserved from original
						SatisfiedBy: &RawSatisfiedBy{
							AnyOf: []RawClause{
								{Type: "evidencepack/new@v1"},
							},
						},
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if result.Requirements[0].Name != "Modified Requirement Name" {
			t.Errorf("Name = %q, want %q", result.Requirements[0].Name, "Modified Requirement Name")
		}
		if result.Requirements[0].Control != "CTRL-NEW" {
			t.Errorf("Control = %q, want %q", result.Requirements[0].Control, "CTRL-NEW")
		}
		// Category was not specified, should be empty (replaced, not preserved)
		if result.Requirements[0].Category != "" {
			t.Errorf("Category = %q, want empty (not preserved from original)", result.Requirements[0].Category)
		}
	})

	t.Run("modify with partial spec clears unspecified fields", func(t *testing.T) {
		base := makeTestProfile()
		// Only specify name - other fields will be cleared
		overlays := []*RawOverlay{
			{
				Modify: []RawModify{
					{
						ID:   "REQ-001",
						Name: "Partial Modification",
						// No Control, Category, or SatisfiedBy - will be cleared
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if result.Requirements[0].Name != "Partial Modification" {
			t.Errorf("Name = %q, want %q", result.Requirements[0].Name, "Partial Modification")
		}
		// Control was not specified, should be empty (replace semantics, not patch)
		if result.Requirements[0].Control != "" {
			t.Errorf("Control = %q, want empty (replace semantics)", result.Requirements[0].Control)
		}
		// SatisfiedBy was not specified, should be empty
		if len(result.Requirements[0].SatisfiedBy.AnyOf) != 0 || len(result.Requirements[0].SatisfiedBy.AllOf) != 0 {
			t.Error("SatisfiedBy should be empty when not specified in modify")
		}
	})

	t.Run("modify nonexistent requirement fails", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Modify: []RawModify{
					{
						ID:   "REQ-NONEXISTENT",
						Name: "Modified",
					},
				},
			},
		}
		_, err := ApplyOverlays(base, overlays)
		if err == nil {
			t.Error("ApplyOverlays() should fail when modify target doesn't exist")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention 'not found', got: %v", err)
		}
	})

	t.Run("modify satisfied_by", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Modify: []RawModify{
					{
						ID: "REQ-001",
						SatisfiedBy: &RawSatisfiedBy{
							AllOf: []RawClause{
								{Type: "evidencepack/new@v1"},
								{Type: "evidencepack/another@v1"},
							},
						},
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if len(result.Requirements[0].SatisfiedBy.AllOf) != 2 {
			t.Errorf("AllOf count = %d, want 2", len(result.Requirements[0].SatisfiedBy.AllOf))
		}
		if len(result.Requirements[0].SatisfiedBy.AnyOf) != 0 {
			t.Errorf("AnyOf count = %d, want 0 (should be replaced)", len(result.Requirements[0].SatisfiedBy.AnyOf))
		}
	})

	t.Run("add new requirement", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Add: []RawRequirement{
					{
						ID:   "REQ-NEW",
						Name: "New Requirement",
						SatisfiedBy: RawSatisfiedBy{
							AnyOf: []RawClause{
								{Type: "evidencepack/new@v1"},
							},
						},
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if len(result.Requirements) != 3 {
			t.Errorf("Requirements count = %d, want 3", len(result.Requirements))
		}
		if result.Requirements[2].ID != "REQ-NEW" {
			t.Errorf("New requirement ID = %q, want %q", result.Requirements[2].ID, "REQ-NEW")
		}
	})

	t.Run("add duplicate ID fails", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Add: []RawRequirement{
					{
						ID:   "REQ-001", // Already exists
						Name: "Duplicate Requirement",
						SatisfiedBy: RawSatisfiedBy{
							AnyOf: []RawClause{
								{Type: "evidencepack/test@v1"},
							},
						},
					},
				},
			},
		}
		_, err := ApplyOverlays(base, overlays)
		if err == nil {
			t.Error("ApplyOverlays() should fail when adding duplicate ID")
		}
		if !strings.Contains(err.Error(), "overwrite") {
			t.Errorf("error should mention 'overwrite', got: %v", err)
		}
	})

	t.Run("multiple overlays apply in order (last-write-wins)", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			{
				Modify: []RawModify{
					{
						ID:   "REQ-001",
						Name: "First Modification",
					},
				},
			},
			{
				Modify: []RawModify{
					{
						ID:   "REQ-001",
						Name: "Second Modification",
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		// Second modification should win
		if result.Requirements[0].Name != "Second Modification" {
			t.Errorf("Name = %q, want %q (last-write-wins)", result.Requirements[0].Name, "Second Modification")
		}
	})

	t.Run("skip in one overlay, add in next overlay", func(t *testing.T) {
		base := makeTestProfile()
		// To replace a requirement, skip it in one overlay, then add it in the next
		overlays := []*RawOverlay{
			{
				Skip: []string{"REQ-001"},
			},
			{
				Add: []RawRequirement{
					{
						ID:   "REQ-001",
						Name: "Replacement Requirement",
						SatisfiedBy: RawSatisfiedBy{
							AnyOf: []RawClause{
								{Type: "evidencepack/replacement@v1"},
							},
						},
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		// Should have original REQ-002 plus new REQ-001
		if len(result.Requirements) != 2 {
			t.Errorf("Requirements count = %d, want 2", len(result.Requirements))
		}
	})

	t.Run("nil overlay in list skipped", func(t *testing.T) {
		base := makeTestProfile()
		overlays := []*RawOverlay{
			nil,
			{
				Modify: []RawModify{
					{
						ID:   "REQ-001",
						Name: "Modified",
					},
				},
			},
		}
		result, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}
		if result.Requirements[0].Name != "Modified" {
			t.Errorf("Name = %q, want %q", result.Requirements[0].Name, "Modified")
		}
	})

	t.Run("does not mutate original", func(t *testing.T) {
		base := makeTestProfile()
		originalName := base.Requirements[0].Name

		overlays := []*RawOverlay{
			{
				Modify: []RawModify{
					{
						ID:   "REQ-001",
						Name: "Modified",
					},
				},
			},
		}
		_, err := ApplyOverlays(base, overlays)
		if err != nil {
			t.Errorf("ApplyOverlays() unexpected error: %v", err)
		}

		// Original should be unchanged
		if base.Requirements[0].Name != originalName {
			t.Errorf("Original was mutated: Name = %q, want %q", base.Requirements[0].Name, originalName)
		}
	})
}
