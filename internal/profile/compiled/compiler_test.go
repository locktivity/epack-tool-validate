package compiled

import (
	"strings"
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/profile/raw"
)

func makeValidRawProfile() *raw.RawProfile {
	return &raw.RawProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []raw.RawRequirement{
			{
				ID:       "REQ-001",
				Name:     "Test Requirement",
				Control:  "CTRL-1",
				Category: "Testing",
				SatisfiedBy: raw.RawSatisfiedBy{
					AnyOf: []raw.RawClause{
						{
							Type: "evidencepack/test@v1",
							MetadataConditions: &raw.RawConditions{
								All: []raw.RawCondition{
									{
										Path:  "$.enabled",
										Op:    "eq",
										Value: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestCompile(t *testing.T) {
	t.Run("valid profile", func(t *testing.T) {
		profile := makeValidRawProfile()
		compiled, err := Compile(profile, "test.yaml")
		if err != nil {
			t.Errorf("Compile() unexpected error: %v", err)
		}
		if compiled.ID != "test-profile" {
			t.Errorf("ID = %q, want %q", compiled.ID, "test-profile")
		}
		if compiled.Name != "Test Profile" {
			t.Errorf("Name = %q, want %q", compiled.Name, "Test Profile")
		}
		if len(compiled.Requirements) != 1 {
			t.Errorf("Requirements count = %d, want 1", len(compiled.Requirements))
		}
	})

	t.Run("nil profile", func(t *testing.T) {
		_, err := Compile(nil, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject nil profile")
		}
	})

	t.Run("duplicate requirement ID", func(t *testing.T) {
		profile := makeValidRawProfile()
		profile.Requirements = append(profile.Requirements, raw.RawRequirement{
			ID:   "REQ-001", // Duplicate
			Name: "Another Requirement",
			SatisfiedBy: raw.RawSatisfiedBy{
				AnyOf: []raw.RawClause{{Type: "test@v1"}},
			},
		})

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject duplicate requirement ID")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("error should mention 'duplicate', got: %v", err)
		}
	})

	t.Run("requirement with all_of mode", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AllOf: []raw.RawClause{
							{Type: "type1@v1"},
							{Type: "type2@v1"},
						},
					},
				},
			},
		}

		compiled, err := Compile(profile, "test.yaml")
		if err != nil {
			t.Errorf("Compile() unexpected error: %v", err)
		}
		if compiled.Requirements[0].Mode != ClauseModeAll {
			t.Errorf("Mode = %v, want ClauseModeAll", compiled.Requirements[0].Mode)
		}
		if len(compiled.Requirements[0].Clauses) != 2 {
			t.Errorf("Clauses count = %d, want 2", len(compiled.Requirements[0].Clauses))
		}
	})
}

func TestCompile_RequirementErrors(t *testing.T) {
	t.Run("neither any_of nor all_of", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:          "REQ-001",
					Name:        "Test",
					SatisfiedBy: raw.RawSatisfiedBy{}, // Neither any_of nor all_of
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject requirement without any_of or all_of")
		}
		if !strings.Contains(err.Error(), "must have any_of, all_of, or manual") {
			t.Errorf("error should mention the clause modes, got: %v", err)
		}
	})

	t.Run("both any_of and all_of", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{{Type: "test@v1"}},
						AllOf: []raw.RawClause{{Type: "test@v1"}},
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject requirement with both any_of and all_of")
		}
		if !strings.Contains(err.Error(), "cannot have both") {
			t.Errorf("error should mention 'cannot have both', got: %v", err)
		}
	})

	t.Run("empty clauses treated as missing mode", func(t *testing.T) {
		// An empty AnyOf slice is treated the same as not having any_of at all
		// since len([]) == 0 makes hasAnyOf false
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{}, // Empty
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject requirement with empty clauses")
		}
		// Empty slice is treated as "must have either any_of or all_of"
		if !strings.Contains(err.Error(), "must have any_of, all_of, or manual") {
			t.Errorf("error should mention clause mode, got: %v", err)
		}
	})
}

func TestCompile_ClauseErrors(t *testing.T) {
	t.Run("missing type", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{{Type: ""}}, // Empty type
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject clause without type")
		}
		if !strings.Contains(err.Error(), "missing type") {
			t.Errorf("error should mention 'missing type', got: %v", err)
		}
	})

	t.Run("invalid severity", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{
							{Type: "test@v1", Severity: "invalid"},
						},
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject clause with invalid severity")
		}
		if !strings.Contains(err.Error(), "invalid severity") {
			t.Errorf("error should mention 'invalid severity', got: %v", err)
		}
	})

	t.Run("valid severities", func(t *testing.T) {
		for _, severity := range []string{"", "critical", "high", "medium", "low"} {
			profile := &raw.RawProfile{
				ID:   "test",
				Name: "Test",
				Requirements: []raw.RawRequirement{
					{
						ID:   "REQ-001",
						Name: "Test",
						SatisfiedBy: raw.RawSatisfiedBy{
							AnyOf: []raw.RawClause{
								{Type: "test@v1", Severity: severity},
							},
						},
					},
				},
			}

			compiled, err := Compile(profile, "test.yaml")
			if err != nil {
				t.Errorf("Compile() with severity %q returned error: %v", severity, err)
			}
			if compiled.Requirements[0].Clauses[0].Severity != severity {
				t.Errorf("Severity = %q, want %q", compiled.Requirements[0].Clauses[0].Severity, severity)
			}
		}
	})

	t.Run("freshness compiled", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{
							{
								Type: "test@v1",
								Freshness: &raw.RawFreshness{
									MaxAgeDays: 30,
								},
							},
						},
					},
				},
			},
		}

		compiled, err := Compile(profile, "test.yaml")
		if err != nil {
			t.Errorf("Compile() unexpected error: %v", err)
		}
		if compiled.Requirements[0].Clauses[0].MaxAgeDays == nil {
			t.Error("MaxAgeDays should not be nil")
		}
		if *compiled.Requirements[0].Clauses[0].MaxAgeDays != 30 {
			t.Errorf("MaxAgeDays = %d, want 30", *compiled.Requirements[0].Clauses[0].MaxAgeDays)
		}
	})
}

func TestCompile_ConditionErrors(t *testing.T) {
	t.Run("invalid operator", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{
							{
								Type: "test@v1",
								MetadataConditions: &raw.RawConditions{
									All: []raw.RawCondition{
										{Path: "$.field", Op: "invalid_op", Value: true},
									},
								},
							},
						},
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject invalid operator")
		}
	})

	t.Run("max_age_days value validation", func(t *testing.T) {
		makeProfile := func(value any) *raw.RawProfile {
			return &raw.RawProfile{
				ID:   "test",
				Name: "Test",
				Requirements: []raw.RawRequirement{
					{
						ID:   "REQ-001",
						Name: "Test",
						SatisfiedBy: raw.RawSatisfiedBy{
							AnyOf: []raw.RawClause{
								{
									Type: "test@v1",
									MetadataConditions: &raw.RawConditions{
										All: []raw.RawCondition{
											{Path: "$.metadata.test_date", Op: "max_age_days", Value: value},
										},
									},
								},
							},
						},
					},
				},
			}
		}

		if _, err := Compile(makeProfile(365), "test.yaml"); err != nil {
			t.Errorf("Compile() with numeric value: unexpected error %v", err)
		}

		rejected := map[string]any{
			"missing":  nil,
			"string":   "365",
			"negative": -1,
		}
		for name, value := range rejected {
			if _, err := Compile(makeProfile(value), "test.yaml"); err == nil {
				t.Errorf("Compile() should reject max_age_days with %s value", name)
			}
		}
	})

	t.Run("invalid JSONPath", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{
							{
								Type: "test@v1",
								MetadataConditions: &raw.RawConditions{
									All: []raw.RawCondition{
										{Path: "$[", Op: "eq", Value: true}, // Invalid
									},
								},
							},
						},
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject invalid JSONPath")
		}
	})

	t.Run("multi-value JSONPath rejected", func(t *testing.T) {
		profile := &raw.RawProfile{
			ID:   "test",
			Name: "Test",
			Requirements: []raw.RawRequirement{
				{
					ID:   "REQ-001",
					Name: "Test",
					SatisfiedBy: raw.RawSatisfiedBy{
						AnyOf: []raw.RawClause{
							{
								Type: "test@v1",
								MetadataConditions: &raw.RawConditions{
									All: []raw.RawCondition{
										{Path: "$.items[*]", Op: "eq", Value: true}, // Multi-value
									},
								},
							},
						},
					},
				},
			},
		}

		_, err := Compile(profile, "test.yaml")
		if err == nil {
			t.Error("Compile() should reject multi-value JSONPath")
		}
	})

	t.Run("valid conditions compiled", func(t *testing.T) {
		profile := makeValidRawProfile()
		compiled, err := Compile(profile, "test.yaml")
		if err != nil {
			t.Errorf("Compile() unexpected error: %v", err)
		}

		cond := compiled.Requirements[0].Clauses[0].Conditions[0]
		if cond.Path != "$.enabled" {
			t.Errorf("Path = %q, want %q", cond.Path, "$.enabled")
		}
		if cond.Op != condition.OpEq {
			t.Errorf("Op = %v, want OpEq", cond.Op)
		}
		if cond.Expected != true {
			t.Errorf("Expected = %v, want true", cond.Expected)
		}
		if cond.Expr == nil {
			t.Error("Expr should not be nil")
		}
	})
}

func TestCompile_Origin(t *testing.T) {
	profile := makeValidRawProfile()
	compiled, err := Compile(profile, "profiles/test-profile.yaml")
	if err != nil {
		t.Errorf("Compile() unexpected error: %v", err)
	}

	origin := compiled.Requirements[0].Clauses[0].Origin
	if origin.RequirementID != "REQ-001" {
		t.Errorf("RequirementID = %q, want %q", origin.RequirementID, "REQ-001")
	}
	if origin.ClauseIndex != 0 {
		t.Errorf("ClauseIndex = %d, want 0", origin.ClauseIndex)
	}
	if origin.SourceFile != "profiles/test-profile.yaml" {
		t.Errorf("SourceFile = %q, want %q", origin.SourceFile, "profiles/test-profile.yaml")
	}
}

func TestCompile_ManualRequirements(t *testing.T) {
	t.Run("manual requirement compiles without clauses", func(t *testing.T) {
		profile := makeValidRawProfile()
		profile.Requirements = append(profile.Requirements, raw.RawRequirement{
			ID:      "REQ-MANUAL",
			Control: "PL-01",
			Name:    "Information Security Policy",
			Manual:  true,
		})

		compiled, err := Compile(profile, "test.yaml")
		if err != nil {
			t.Fatalf("Compile() unexpected error: %v", err)
		}
		req := compiled.Requirements[1]
		if !req.Manual {
			t.Error("Manual should be true")
		}
		if len(req.Clauses) != 0 {
			t.Errorf("Clauses = %d, want 0", len(req.Clauses))
		}
	})

	t.Run("manual with clauses is rejected", func(t *testing.T) {
		profile := makeValidRawProfile()
		profile.Requirements[0].Manual = true

		_, err := Compile(profile, "test.yaml")
		if err == nil || !strings.Contains(err.Error(), "cannot combine manual") {
			t.Errorf("Compile() = %v, want manual/clauses conflict error", err)
		}
	})

	t.Run("manual without id or control is rejected", func(t *testing.T) {
		profile := makeValidRawProfile()
		profile.Requirements = append(profile.Requirements, raw.RawRequirement{
			Name:   "Unreachable",
			Manual: true,
		})

		_, err := Compile(profile, "test.yaml")
		if err == nil || !strings.Contains(err.Error(), "id or control") {
			t.Errorf("Compile() = %v, want id-or-control error", err)
		}
	})

	t.Run("manual with only a control is accepted", func(t *testing.T) {
		profile := makeValidRawProfile()
		profile.Requirements = append(profile.Requirements, raw.RawRequirement{
			ID:      "REQ-CTRL-ONLY",
			Control: "AC-02",
			Manual:  true,
		})

		if _, err := Compile(profile, "test.yaml"); err != nil {
			t.Errorf("Compile() unexpected error: %v", err)
		}
	})
}

func TestCompile_DescriptionPassthrough(t *testing.T) {
	profile := makeValidRawProfile()
	profile.Requirements[0].Description = "What the auditor expects to see."
	profile.Requirements = append(profile.Requirements, raw.RawRequirement{
		ID:          "REQ-MANUAL-DESC",
		Control:     "PL-01",
		Description: "Must name an approving officer.",
		Manual:      true,
	})

	compiled, err := Compile(profile, "test.yaml")
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if compiled.Requirements[0].Description != "What the auditor expects to see." {
		t.Errorf("machine requirement Description = %q", compiled.Requirements[0].Description)
	}
	if compiled.Requirements[1].Description != "Must name an approving officer." {
		t.Errorf("manual requirement Description = %q", compiled.Requirements[1].Description)
	}
}

func TestDiagnose_ReportsEveryFailureInDocumentOrder(t *testing.T) {
	profile := makeValidRawProfile()
	conds := profile.Requirements[0].SatisfiedBy.AnyOf[0].MetadataConditions
	conds.All = append(conds.All,
		raw.RawCondition{Path: "$.a", Op: "like", Value: 1},
		raw.RawCondition{Path: "$.b", Op: "eq", Value: 1, Cardinality: "most"},
	)
	second := profile.Requirements[0]
	second.ID = "REQ-002"
	second.SatisfiedBy = raw.RawSatisfiedBy{}
	profile.Requirements = append(profile.Requirements, second)

	diags := Diagnose(profile, "profile.yaml")
	var got []string
	for _, d := range diags {
		got = append(got, d.Code)
	}
	want := []string{"INVALID_OPERATOR", "INVALID_CARDINALITY", "INVALID_CLAUSE_MODE"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Diagnose codes = %v, want %v", got, want)
	}
	if diags[0].Location.ConditionIndex != 1 || diags[1].Location.ConditionIndex != 2 {
		t.Errorf("condition indexes = %d, %d", diags[0].Location.ConditionIndex, diags[1].Location.ConditionIndex)
	}

	_, err := Compile(profile, "profile.yaml")
	if err == nil || !strings.Contains(err.Error(), "INVALID_OPERATOR") {
		t.Errorf("Compile should still stop at the first failure, got %v", err)
	}
}

func TestDiagnose_ValidProfileHasNoFindings(t *testing.T) {
	if diags := Diagnose(makeValidRawProfile(), "profile.yaml"); len(diags) != 0 {
		t.Errorf("Diagnose = %v", diags)
	}
}
