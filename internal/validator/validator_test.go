package validator

import (
	"testing"
	"time"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/locktivity/epack-tool-validate/internal/profile/raw"
)

func makeTestContext() *Context {
	return TestContext(time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC))
}

func makeTestPackIndex() *PackIndex {
	now := time.Date(2024, 6, 14, 12, 0, 0, 0, time.UTC) // 1 day ago
	return &PackIndex{
		BySchema: map[string][]IndexedArtifact{
			"evidencepack/idp-posture@v1": {
				{
					Path:        "artifacts/idp-posture.json",
					Schema:      "evidencepack/idp-posture@v1",
					CollectedAt: &now,
					Body: map[string]any{
						"mfa_coverage":      100.0,
						"has_access_policy": true,
						"enabled":           true,
						"password_strength": 80.0,
					},
				},
			},
			"evidencepack/vuln-scan@v1": {
				{
					Path:        "artifacts/vuln-scan.json",
					Schema:      "evidencepack/vuln-scan@v1",
					CollectedAt: &now,
					Body: map[string]any{
						"critical_count": 0.0,
						"high_count":     2.0,
					},
				},
			},
		},
		PackDigest: "sha256:abc123",
	}
}

func makeCompiledCondition(path, op string, expected any) compiled.CompiledCondition {
	expr, _ := condition.ParseJSONPath(path)
	parsedOp, _ := condition.ParseOperator(op)
	return compiled.CompiledCondition{
		Path:     path,
		Expr:     expr,
		Op:       parsedOp,
		Expected: expected,
	}
}

func TestNew(t *testing.T) {
	v := New()
	if v == nil {
		t.Fatal("New() returned nil")
	}
}

func TestValidate_AllPass(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:       "REQ-001",
				Name:     "MFA Enabled",
				Category: "Security",
				Mode:     compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "sha256:profile123")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
	if result.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", result.Summary.Total)
	}
	if result.Summary.Passed != 1 {
		t.Errorf("Summary.Passed = %d, want 1", result.Summary.Passed)
	}
	if result.Summary.Failed != 0 {
		t.Errorf("Summary.Failed = %d, want 0", result.Summary.Failed)
	}
	if result.Summary.Missing != 0 {
		t.Errorf("Summary.Missing = %d, want 0", result.Summary.Missing)
	}
	if result.Profile.ID != "test-profile" {
		t.Errorf("Profile.ID = %q, want %q", result.Profile.ID, "test-profile")
	}
	if result.Profile.Digest != "sha256:profile123" {
		t.Errorf("Profile.Digest = %q, want %q", result.Profile.Digest, "sha256:profile123")
	}
	if len(result.Requirements) == 0 {
		t.Fatal("Requirements should not be empty")
	}
	if result.Requirements[0].Artifact != "artifacts/idp-posture.json" {
		t.Errorf("Requirements[0].Artifact = %q, want %q", result.Requirements[0].Artifact, "artifacts/idp-posture.json")
	}
	if result.Requirements[0].Path != "$.enabled" {
		t.Errorf("Requirements[0].Path = %q, want %q", result.Requirements[0].Path, "$.enabled")
	}
	if len(result.Requirements[0].Checks) != 1 {
		t.Fatalf("Requirements[0].Checks length = %d, want 1", len(result.Requirements[0].Checks))
	}
	if result.Requirements[0].Checks[0].Status != "pass" {
		t.Errorf("Requirements[0].Checks[0].Status = %q, want %q", result.Requirements[0].Checks[0].Status, "pass")
	}
}

func TestValidate_FailedRequirement(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:       "REQ-001",
				Name:     "MFA Full Coverage",
				Category: "Security",
				Mode:     compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 150.0)}, // Will fail
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	if result.Summary.Failed != 1 {
		t.Errorf("Summary.Failed = %d, want 1", result.Summary.Failed)
	}
	if result.Summary.Missing != 0 {
		t.Errorf("Summary.Missing = %d, want 0", result.Summary.Missing)
	}
}

func TestValidate_MixedResults(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Passing Req",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
			{
				ID:   "REQ-002",
				Name: "Failing Req",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/nonexistent@v1", // No such artifact
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.field", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-002", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	if result.Summary.Passed != 1 {
		t.Errorf("Summary.Passed = %d, want 1", result.Summary.Passed)
	}
	if result.Summary.Failed != 0 {
		t.Errorf("Summary.Failed = %d, want 0", result.Summary.Failed)
	}
	if result.Summary.Missing != 1 {
		t.Errorf("Summary.Missing = %d, want 1", result.Summary.Missing)
	}
}

func TestValidate_KeyFailures(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Critical Failing Req",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Severity:   "critical",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 100.0)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Clause with severity matched, so requirement fails with that severity
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	if len(result.KeyFailures) != 1 {
		t.Errorf("KeyFailures count = %d, want 1", len(result.KeyFailures))
	}
	if len(result.KeyFailures) > 0 && result.KeyFailures[0].Severity != "critical" {
		t.Errorf("KeyFailures[0].Severity = %q, want %q", result.KeyFailures[0].Severity, "critical")
	}
}

func TestValidate_CategorySummary(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:       "REQ-001",
				Name:     "Req 1",
				Category: "Security",
				Mode:     compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
			{
				ID:       "REQ-002",
				Name:     "Req 2",
				Category: "Security",
				Mode:     compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema: "evidencepack/nonexistent@v1",
						Origin: compiled.Origin{RequirementID: "REQ-002", ClauseIndex: 0},
					},
				},
			},
			{
				ID:       "REQ-003",
				Name:     "Req 3",
				Category: "Compliance",
				Mode:     compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-003", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	securityCat := result.ByCategory["Security"]
	if securityCat.Passed != 1 {
		t.Errorf("Security.Passed = %d, want 1", securityCat.Passed)
	}
	if securityCat.Failed != 0 {
		t.Errorf("Security.Failed = %d, want 0", securityCat.Failed)
	}
	if securityCat.Missing != 1 {
		t.Errorf("Security.Missing = %d, want 1", securityCat.Missing)
	}

	complianceCat := result.ByCategory["Compliance"]
	if complianceCat.Passed != 1 {
		t.Errorf("Compliance.Passed = %d, want 1", complianceCat.Passed)
	}
	if complianceCat.Failed != 0 {
		t.Errorf("Compliance.Failed = %d, want 0", complianceCat.Failed)
	}
	if complianceCat.Missing != 0 {
		t.Errorf("Compliance.Missing = %d, want 0", complianceCat.Missing)
	}
}

func TestValidate_ClauseModeAny_FirstMatchWins(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Test",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						// No severity = PASS
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Severity:   "high",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "exists", nil)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// First clause matches without severity, so requirement passes
	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
	if len(result.Requirements) > 0 && result.Requirements[0].Status != "pass" {
		t.Errorf("Requirements[0].Status = %q, want %q", result.Requirements[0].Status, "pass")
	}
	if len(result.Requirements) == 0 || len(result.Requirements[0].Checks) != 2 {
		t.Fatalf("Requirements[0].Checks length = %d, want 2", len(result.Requirements[0].Checks))
	}
	if result.Requirements[0].Checks[0].Status != "pass" {
		t.Errorf("Requirements[0].Checks[0].Status = %q, want %q", result.Requirements[0].Checks[0].Status, "pass")
	}
	if result.Requirements[0].Checks[1].Status != "fail" {
		t.Errorf("Requirements[0].Checks[1].Status = %q, want %q", result.Requirements[0].Checks[1].Status, "fail")
	}

	// Verify Mode field is set correctly
	if result.Requirements[0].Mode != "any_of" {
		t.Errorf("Requirements[0].Mode = %q, want %q", result.Requirements[0].Mode, "any_of")
	}

	// Verify Selected field marks the winning check (first clause that passed)
	if !result.Requirements[0].Checks[0].Selected {
		t.Error("Requirements[0].Checks[0].Selected = false, want true (this check determined the outcome)")
	}
	if result.Requirements[0].Checks[1].Selected {
		t.Error("Requirements[0].Checks[1].Selected = true, want false (this check did not determine the outcome)")
	}
}

func TestValidate_ClauseModeAny_GraduatedSeverity(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// Simulate graduated severity: first clause requires mfa_coverage >= 150 (won't match),
	// second clause matches with severity
	// Artifact has mfa_coverage = 100, so:
	// - First clause (>= 150): 100 >= 150 is FALSE
	// - Second clause (>= 90): 100 >= 90 is TRUE with severity "low"
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "MFA Coverage",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 150.0)},
						// No severity = full pass
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Severity:   "low",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 90.0)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Second clause matches (100 >= 90), but has severity = FAIL with low severity
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}

	req := result.Requirements[0]
	if req.Severity != "low" {
		t.Errorf("Severity = %q, want %q", req.Severity, "low")
	}

	// Graduated failures should show the FIRST clause's expected (the "pass" threshold),
	// not the matched clause's expected. This tells users what they need to achieve.
	if req.Expected == nil {
		t.Fatal("Expected should not be nil")
	}
	if req.Expected.Value != 150.0 {
		t.Errorf("Expected.Value = %v, want 150 (first clause threshold, not 90)", req.Expected.Value)
	}

	// Actual should be the evaluated value
	if req.Actual != 100.0 {
		t.Errorf("Actual = %v, want 100", req.Actual)
	}

	// Delta should be against the first clause's expected (100 - 150 = -50)
	if req.Delta == nil {
		t.Fatal("Delta should not be nil")
	}
	if *req.Delta != -50.0 {
		t.Errorf("Delta = %v, want -50 (100 - 150, gap to full compliance)", *req.Delta)
	}
}

func TestValidate_ClauseModeAny_GraduatedSeverity_DifferentPaths(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// When clauses check DIFFERENT paths, we should NOT mix details from different clauses.
	// This test ensures we use the matched clause's details when paths differ.
	// First clause checks $.mfa_coverage, second checks $.password_strength
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Security Check",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 150.0)},
						// No severity = full pass (won't match, 100 < 150)
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:   "evidencepack/idp-posture@v1",
						Severity: "low",
						// Different path than first clause!
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.password_strength", "gte", 50.0)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Second clause matches (password_strength 80 >= 50), but has severity = FAIL with low severity
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}

	req := result.Requirements[0]
	if req.Severity != "low" {
		t.Errorf("Severity = %q, want %q", req.Severity, "low")
	}

	// Since the paths are DIFFERENT, we should use the matched clause's details,
	// NOT mix first clause's expected with second clause's actual
	if req.Expected == nil {
		t.Fatal("Expected should not be nil")
	}

	// Should show the matched clause's expected (gte 50), not the first clause's (gte 150)
	if req.Expected.Value != 50.0 {
		t.Errorf("Expected.Value = %v, want 50 (matched clause threshold when paths differ)", req.Expected.Value)
	}

	// Path should be from matched clause
	if req.Path != "$.password_strength" {
		t.Errorf("Path = %q, want %q (matched clause path)", req.Path, "$.password_strength")
	}

	// Actual should be from matched clause's artifact
	if req.Actual != 80.0 {
		t.Errorf("Actual = %v, want 80 (password_strength value)", req.Actual)
	}

	// Delta should be against the matched clause's expected (80 - 50 = 30)
	if req.Delta == nil {
		t.Fatal("Delta should not be nil")
	}
	if *req.Delta != 30.0 {
		t.Errorf("Delta = %v, want 30 (80 - 50, coherent with matched clause)", *req.Delta)
	}
}

func TestValidate_ClauseModeAny_GraduatedSeverity_MultiCondition(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// When clauses have MULTIPLE conditions, we should NOT try to do graduated-failure
	// path reuse because we only capture the first condition's path.
	// This test ensures we fall back to matched clause's details.
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Multi-Condition Graduated",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema: "evidencepack/idp-posture@v1",
						// Two conditions: same first condition (enabled), different threshold
						Conditions: []compiled.CompiledCondition{
							makeCompiledCondition("$.enabled", "eq", true),
							makeCompiledCondition("$.mfa_coverage", "gte", 150.0), // Won't match (100 < 150)
						},
						// No severity = full pass
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:   "evidencepack/idp-posture@v1",
						Severity: "low",
						// Same first condition, lower threshold
						Conditions: []compiled.CompiledCondition{
							makeCompiledCondition("$.enabled", "eq", true),
							makeCompiledCondition("$.mfa_coverage", "gte", 90.0), // Will match (100 >= 90)
						},
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Second clause matches (all conditions pass), but has severity = FAIL with low severity
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}

	req := result.Requirements[0]
	if req.Severity != "low" {
		t.Errorf("Severity = %q, want %q", req.Severity, "low")
	}

	// For multi-condition clauses, we should use the first clause's FAILING condition details.
	// The first clause failed on $.mfa_coverage >= 150 (the second condition), so we show
	// what's needed for full pass: the mfa_coverage threshold, not the enabled check.
	if req.Expected == nil {
		t.Fatal("Expected should not be nil")
	}

	// Should show the first clause's failing condition ($.mfa_coverage >= 150)
	if req.Expected.Op != "gte" {
		t.Errorf("Expected.Op = %q, want %q (first clause's failing condition)", req.Expected.Op, "gte")
	}
	if req.Expected.Value != 150.0 {
		t.Errorf("Expected.Value = %v, want 150 (first clause's failing condition)", req.Expected.Value)
	}

	// Path should be the failing condition's path
	if req.Path != "$.mfa_coverage" {
		t.Errorf("Path = %q, want %q (first clause's failing condition)", req.Path, "$.mfa_coverage")
	}

	// Actual should be the mfa_coverage value
	if req.Actual != 100.0 {
		t.Errorf("Actual = %v, want 100 (actual mfa_coverage)", req.Actual)
	}

	// Delta should show the gap to full compliance (100 - 150 = -50)
	if req.Delta == nil {
		t.Fatal("Delta should not be nil")
	}
	if *req.Delta != -50.0 {
		t.Errorf("Delta = %v, want -50 (100 - 150)", *req.Delta)
	}
}

func TestValidate_ClauseModeAll(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "All Clauses Must Match",
				Mode: compiled.ClauseModeAll,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.has_access_policy", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
	if len(result.Requirements) == 0 {
		t.Fatal("Requirements should not be empty")
	}
	if len(result.Requirements[0].Checks) != 2 {
		t.Fatalf("Requirements[0].Checks length = %d, want 2", len(result.Requirements[0].Checks))
	}
	if result.Requirements[0].Checks[0].Status != "pass" || result.Requirements[0].Checks[1].Status != "pass" {
		t.Errorf("Requirements[0].Checks statuses = [%q %q], want [pass pass]",
			result.Requirements[0].Checks[0].Status, result.Requirements[0].Checks[1].Status)
	}

	// Verify Mode field is set correctly
	if result.Requirements[0].Mode != "all_of" {
		t.Errorf("Requirements[0].Mode = %q, want %q", result.Requirements[0].Mode, "all_of")
	}

	// For all_of mode, no check is marked as selected because all checks matter equally
	for i, check := range result.Requirements[0].Checks {
		if check.Selected {
			t.Errorf("Checks[%d].Selected = true, want false (all_of mode: all checks matter equally)", i)
		}
	}
}

func TestValidate_ClauseModeAll_OneFails(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "All Clauses Must Match",
				Mode: compiled.ClauseModeAll,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", false)}, // Definitively fails: enabled is present and true
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
}

func TestValidate_ClauseModeAll_MissingMetricIsUnknown(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "All Clauses Must Match",
				Mode: compiled.ClauseModeAll,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.nonexistent", "eq", true)}, // Absent: cannot be scored
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "unknown" {
		t.Errorf("Status = %q, want %q", result.Status, "unknown")
	}
	req := result.Requirements[0]
	if req.Status != "unknown" {
		t.Errorf("Requirements[0].Status = %q, want %q", req.Status, "unknown")
	}
	if req.FailureKind != "insufficient_evidence" {
		t.Errorf("FailureKind = %q, want %q", req.FailureKind, "insufficient_evidence")
	}
	if req.Severity != "" {
		t.Errorf("Severity = %q, want empty (unknown is not a graded failure)", req.Severity)
	}
	if result.Summary.Unknown != 1 {
		t.Errorf("Summary.Unknown = %d, want 1", result.Summary.Unknown)
	}
	if len(result.KeyFailures) != 0 {
		t.Errorf("KeyFailures = %v, want empty (unknown is not a failure)", result.KeyFailures)
	}
}

func TestValidate_ClauseModeAll_WithSeverity(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Test",
				Mode: compiled.ClauseModeAll,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Severity:   "medium",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Severity:   "high",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.has_access_policy", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// All clauses match but have severities - highest severity wins
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	if len(result.Requirements) > 0 && result.Requirements[0].Severity != "high" {
		t.Errorf("Requirements[0].Severity = %q, want %q", result.Requirements[0].Severity, "high")
	}
}

func TestValidate_Freshness_Pass(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	maxAge := 7
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Fresh Artifact",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						MaxAgeDays: &maxAge,
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Artifact is 1 day old, max age is 7 days
	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
}

func TestValidate_Freshness_TooOld(t *testing.T) {
	ctx := makeTestContext()

	// Create pack with old artifact
	oldTime := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC) // Over a month old
	pack := &PackIndex{
		BySchema: map[string][]IndexedArtifact{
			"evidencepack/idp-posture@v1": {
				{
					Path:        "artifacts/idp-posture.json",
					Schema:      "evidencepack/idp-posture@v1",
					CollectedAt: &oldTime,
					Body:        map[string]any{"enabled": true},
				},
			},
		},
		PackDigest: "sha256:abc123",
	}

	v := New()
	maxAge := 7 // 7 days
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Fresh Artifact",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						MaxAgeDays: &maxAge,
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
}

func TestValidate_Freshness_MissingTimestamp(t *testing.T) {
	ctx := makeTestContext()

	// Create pack with artifact missing CollectedAt
	pack := &PackIndex{
		BySchema: map[string][]IndexedArtifact{
			"evidencepack/idp-posture@v1": {
				{
					Path:        "artifacts/idp-posture.json",
					Schema:      "evidencepack/idp-posture@v1",
					CollectedAt: nil, // Missing timestamp
					Body:        map[string]any{"enabled": true},
				},
			},
		},
		PackDigest: "sha256:abc123",
	}

	v := New()
	maxAge := 7
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Fresh Artifact",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						MaxAgeDays: &maxAge,
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Should fail because freshness is required but timestamp is missing
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
}

func TestValidate_MetadataDateWithinLastDays_Pass(t *testing.T) {
	ctx := makeTestContext()
	pack := &PackIndex{
		BySchema: map[string][]IndexedArtifact{
			"evidencepack/pentest-report@v1": {
				{
					Path:   "artifacts/documents/doc-1/metadata.json",
					Schema: "evidencepack/pentest-report@v1",
					Body: map[string]any{
						"metadata": map[string]any{
							"test_date": "2024-01-15",
						},
					},
				},
			},
		},
		PackDigest: "sha256:abc123",
	}

	v := New()
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "DOC-001",
				Name: "Recent penetration test",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/pentest-report@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.metadata.test_date", "max_age_days", 365)},
						Origin:     compiled.Origin{RequirementID: "DOC-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
	req := result.Requirements[0]
	if req.Path != "$.metadata.test_date" {
		t.Errorf("Path = %q, want %q", req.Path, "$.metadata.test_date")
	}
	if req.Actual != "2024-01-15" {
		t.Errorf("Actual = %v, want %q", req.Actual, "2024-01-15")
	}
}

func TestValidate_MetadataDateWithinLastDays_TooOld(t *testing.T) {
	ctx := makeTestContext()
	pack := &PackIndex{
		BySchema: map[string][]IndexedArtifact{
			"evidencepack/pentest-report@v1": {
				{
					Path:   "artifacts/documents/doc-1/metadata.json",
					Schema: "evidencepack/pentest-report@v1",
					Body: map[string]any{
						"metadata": map[string]any{
							"test_date": "2023-01-15",
						},
					},
				},
			},
		},
		PackDigest: "sha256:abc123",
	}

	v := New()
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "DOC-001",
				Name: "Recent penetration test",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/pentest-report@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.metadata.test_date", "max_age_days", 365)},
						Origin:     compiled.Origin{RequirementID: "DOC-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	req := result.Requirements[0]
	if req.Path != "$.metadata.test_date" {
		t.Errorf("Path = %q, want %q", req.Path, "$.metadata.test_date")
	}
	if req.Expected == nil || req.Expected.Op != "max_age_days" || req.Expected.Value != 365 {
		t.Errorf("Expected = %+v, want max_age_days 365", req.Expected)
	}
	if req.Actual != "2023-01-15" {
		t.Errorf("Actual = %v, want %q", req.Actual, "2023-01-15")
	}
}

func TestValidate_MetadataDateWithinLastDays_FutureDateFails(t *testing.T) {
	ctx := makeTestContext()
	cond := makeCompiledCondition("$.metadata.test_date", "max_age_days", 365)
	body := map[string]any{
		"metadata": map[string]any{
			"test_date": "2024-06-17",
		},
	}

	result := evaluateConditionsWithDetailsAt([]compiled.CompiledCondition{cond}, body, ctx.Now())

	if result.Verdict == VerdictTrue {
		t.Error("future dates should fail max_age_days")
	}
	if result.Detail == nil || result.Detail.Actual != "2024-06-17" {
		t.Errorf("Detail = %+v, want actual future date", result.Detail)
	}
}

func TestValidate_MetadataDateWithinLastDays_TomorrowPassesTolerance(t *testing.T) {
	ctx := makeTestContext()
	cond := makeCompiledCondition("$.metadata.test_date", "max_age_days", 365)
	body := map[string]any{
		"metadata": map[string]any{
			"test_date": "2024-06-16",
		},
	}

	result := evaluateConditionsWithDetailsAt([]compiled.CompiledCondition{cond}, body, ctx.Now())

	if result.Verdict != VerdictTrue {
		t.Error("date-only values one day ahead should pass (timezone tolerance)")
	}
}

func TestValidate_MetadataDateWithinLastDays_RFC3339Timestamp(t *testing.T) {
	ctx := makeTestContext()
	cond := makeCompiledCondition("$.metadata.completed_at", "max_age_days", 30)

	fresh := map[string]any{
		"metadata": map[string]any{"completed_at": "2024-06-01T09:30:00Z"},
	}
	result := evaluateConditionsWithDetailsAt([]compiled.CompiledCondition{cond}, fresh, ctx.Now())
	if result.Verdict != VerdictTrue {
		t.Error("RFC3339 timestamp 14 days old should pass max_age_days 30")
	}

	stale := map[string]any{
		"metadata": map[string]any{"completed_at": "2024-05-01T09:30:00Z"},
	}
	result = evaluateConditionsWithDetailsAt([]compiled.CompiledCondition{cond}, stale, ctx.Now())
	if result.Verdict == VerdictTrue {
		t.Error("RFC3339 timestamp 45 days old should fail max_age_days 30")
	}
}

func TestValidate_MetadataDateWithinLastDays_CardinalityAll(t *testing.T) {
	ctx := makeTestContext()
	cond := makeCompiledConditionWithCardinality("$.scans[*].date", "max_age_days", 90, compiled.CardinalityAll)

	allFresh := map[string]any{
		"scans": []any{
			map[string]any{"date": "2024-06-01"},
			map[string]any{"date": "2024-05-15"},
		},
	}
	verdict, _ := evaluateSingleConditionAt(&cond, allFresh, ctx.Now())
	if verdict != VerdictTrue {
		t.Error("all scan dates within 90 days should pass cardinality:all")
	}

	oneStale := map[string]any{
		"scans": []any{
			map[string]any{"date": "2024-06-01"},
			map[string]any{"date": "2023-12-01"},
		},
	}
	verdict, detail := evaluateSingleConditionAt(&cond, oneStale, ctx.Now())
	if verdict == VerdictTrue {
		t.Error("one stale scan date should fail cardinality:all")
	}
	if detail == nil || detail.Actual != "2023-12-01" {
		t.Errorf("Detail = %+v, want failing value 2023-12-01", detail)
	}
}

func TestValidate_MetadataDateWithinLastDays_MalformedDateFails(t *testing.T) {
	ctx := makeTestContext()
	cond := makeCompiledCondition("$.metadata.test_date", "max_age_days", 365)
	body := map[string]any{
		"metadata": map[string]any{
			"test_date": "June 15, 2024",
		},
	}

	result := evaluateConditionsWithDetailsAt([]compiled.CompiledCondition{cond}, body, ctx.Now())

	if result.Verdict == VerdictTrue {
		t.Error("malformed dates should fail max_age_days")
	}
	if result.Detail == nil || result.Detail.Expected.Op != "max_age_days" {
		t.Errorf("Detail = %+v, want max_age_days failure", result.Detail)
	}
}

func TestValidate_NoArtifactMatch(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Missing Schema",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/nonexistent@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.field", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	if len(result.Requirements) == 0 {
		t.Fatal("Requirements should not be empty")
	}
	if result.Requirements[0].FailureKind != "missing" {
		t.Errorf("Requirements[0].FailureKind = %q, want %q", result.Requirements[0].FailureKind, "missing")
	}
	if len(result.Requirements[0].Checks) != 1 {
		t.Fatalf("Requirements[0].Checks length = %d, want 1", len(result.Requirements[0].Checks))
	}
	if result.Requirements[0].Checks[0].Status != "missing" {
		t.Errorf("Requirements[0].Checks[0].Status = %q, want %q", result.Requirements[0].Checks[0].Status, "missing")
	}
	if result.Summary.Missing != 1 {
		t.Errorf("Summary.Missing = %d, want 1", result.Summary.Missing)
	}
	// Default severity for no match is "high"
	if len(result.Requirements) > 0 && result.Requirements[0].Severity != "high" {
		t.Errorf("Requirements[0].Severity = %q, want %q", result.Requirements[0].Severity, "high")
	}
}

func TestValidate_ConditionFails(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Condition Fails",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", false)}, // enabled is true
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
}

func TestValidate_MultipleConditions(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Multiple Conditions",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema: "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{
							makeCompiledCondition("$.enabled", "eq", true),
							makeCompiledCondition("$.mfa_coverage", "gte", 100.0),
							makeCompiledCondition("$.has_access_policy", "eq", true),
						},
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
	if len(result.Requirements) == 0 {
		t.Fatal("Requirements should not be empty")
	}
	if len(result.Requirements[0].Checks) != 1 {
		t.Fatalf("Requirements[0].Checks length = %d, want 1", len(result.Requirements[0].Checks))
	}
	if len(result.Requirements[0].Checks[0].Conditions) != 3 {
		t.Fatalf("Requirements[0].Checks[0].Conditions length = %d, want 3", len(result.Requirements[0].Checks[0].Conditions))
	}
	for i, check := range result.Requirements[0].Checks[0].Conditions {
		if !check.Passed {
			t.Errorf("Requirements[0].Checks[0].Conditions[%d].Passed = false, want true", i)
		}
	}
}

func TestValidate_MultipleConditions_OneFails(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Multiple Conditions",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema: "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{
							makeCompiledCondition("$.enabled", "eq", true),
							makeCompiledCondition("$.mfa_coverage", "gte", 200.0), // Will fail
							makeCompiledCondition("$.has_access_policy", "eq", true),
						},
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}
	if len(result.Requirements) == 0 {
		t.Fatal("Requirements should not be empty")
	}
	if len(result.Requirements[0].Checks) != 1 {
		t.Fatalf("Requirements[0].Checks length = %d, want 1", len(result.Requirements[0].Checks))
	}
	if len(result.Requirements[0].Checks[0].Conditions) != 2 {
		t.Fatalf("Requirements[0].Checks[0].Conditions length = %d, want 2", len(result.Requirements[0].Checks[0].Conditions))
	}
	if !result.Requirements[0].Checks[0].Conditions[0].Passed {
		t.Error("Requirements[0].Checks[0].Conditions[0].Passed = false, want true")
	}
	if result.Requirements[0].Checks[0].Conditions[1].Passed {
		t.Error("Requirements[0].Checks[0].Conditions[1].Passed = true, want false")
	}
}

func TestValidate_NoConditions(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// Clause with no conditions - just checks schema existence
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Just Schema Check",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: nil, // No conditions
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Should pass because artifact with matching schema exists
	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}
}

func TestValidate_ModeAndSelected_AnyOf_Failure(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// Test graduated failure: first clause (pass threshold) should be selected,
	// not the matched low-threshold clause. This prevents contradictory UX where
	// the requirement fails but the selected check shows its condition as PASS.
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Graduated Failure",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 150.0)}, // Will fail
						// No severity = full pass threshold
						Origin: compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Severity:   "low",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 90.0)}, // Will match but with severity
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Should fail because best match has severity
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}

	req := result.Requirements[0]

	// Verify Mode field
	if req.Mode != "any_of" {
		t.Errorf("Mode = %q, want %q", req.Mode, "any_of")
	}

	if len(req.Checks) != 2 {
		t.Fatalf("Checks length = %d, want 2", len(req.Checks))
	}

	// For graduated failures, the FIRST clause (pass threshold) should be selected
	// because it shows what the user needs to achieve - this prevents the contradictory
	// UX where requirement fails but the selected check shows PASS
	if !req.Checks[0].Selected {
		t.Error("Checks[0].Selected = false, want true (pass threshold shows what's needed for compliance)")
	}
	if req.Checks[1].Selected {
		t.Error("Checks[1].Selected = true, want false (matched with severity, but not the pass threshold)")
	}

	// The first check should show FAIL (100 < 150) which aligns with the requirement status
	if req.Checks[0].Status != "fail" {
		t.Errorf("Checks[0].Status = %q, want %q (first clause failed to match)", req.Checks[0].Status, "fail")
	}

	// CRITICAL: The selected check's inner conditions must show passed=false
	// This guards against the contradictory UX where requirement fails but condition shows PASS
	if len(req.Checks[0].Conditions) == 0 {
		t.Fatal("Checks[0].Conditions should not be empty")
	}
	if req.Checks[0].Conditions[0].Passed {
		t.Error("Checks[0].Conditions[0].Passed = true, want false (selected check's condition must align with FAIL status)")
	}

	// The second check (matched with severity) should show FAIL status
	// but its inner condition shows passed=true (met the low threshold)
	// This is OK because it's not the selected check (shown in alternative thresholds)
	if req.Checks[1].Status != "fail" {
		t.Errorf("Checks[1].Status = %q, want %q (matched with severity)", req.Checks[1].Status, "fail")
	}
	if len(req.Checks[1].Conditions) == 0 {
		t.Fatal("Checks[1].Conditions should not be empty")
	}
	if !req.Checks[1].Conditions[0].Passed {
		t.Error("Checks[1].Conditions[0].Passed = false, want true (met the low threshold)")
	}
}

func TestValidate_ModeAndSelected_AllOf_Failure(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// Test all_of mode where one clause fails
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "All Must Match",
				Mode: compiled.ClauseModeAll,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)}, // Will pass
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.mfa_coverage", "gte", 200.0)}, // Will fail
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 1},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	// Should fail because one clause fails
	if result.Status != "fail" {
		t.Errorf("Status = %q, want %q", result.Status, "fail")
	}

	req := result.Requirements[0]

	// Verify Mode field
	if req.Mode != "all_of" {
		t.Errorf("Mode = %q, want %q", req.Mode, "all_of")
	}

	if len(req.Checks) != 2 {
		t.Fatalf("Checks length = %d, want 2", len(req.Checks))
	}

	// For all_of mode, no check is marked as selected - all checks matter equally
	for i, check := range req.Checks {
		if check.Selected {
			t.Errorf("Checks[%d].Selected = true, want false (all_of mode: all checks matter equally)", i)
		}
	}
}

func TestValidate_ModeAndSelected_SingleClause(t *testing.T) {
	ctx := makeTestContext()
	pack := makeTestPackIndex()
	v := New()

	// Test with single clause - it should always be selected
	profile := &compiled.CompiledProfile{
		ID:      "test-profile",
		Name:    "Test Profile",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:   "REQ-001",
				Name: "Single Clause",
				Mode: compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema:     "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)},
						Origin:     compiled.Origin{RequirementID: "REQ-001", ClauseIndex: 0},
					},
				},
			},
		},
	}

	result := v.Validate(ctx, profile, pack, "")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want %q", result.Status, "pass")
	}

	req := result.Requirements[0]

	if req.Mode != "any_of" {
		t.Errorf("Mode = %q, want %q", req.Mode, "any_of")
	}

	if len(req.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(req.Checks))
	}

	if !req.Checks[0].Selected {
		t.Error("Checks[0].Selected = false, want true (single clause should be selected)")
	}
}

func TestEvaluateConditionsWithDetails(t *testing.T) {
	body := map[string]any{
		"enabled": true,
		"count":   100.0,
		"name":    "test",
	}

	t.Run("empty conditions always pass", func(t *testing.T) {
		result := evaluateConditionsWithDetails(nil, body)
		if result.Verdict != VerdictTrue {
			t.Error("nil conditions should pass")
		}
		result = evaluateConditionsWithDetails([]compiled.CompiledCondition{}, body)
		if result.Verdict != VerdictTrue {
			t.Error("empty conditions should pass")
		}
	})

	t.Run("single passing condition", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict != VerdictTrue {
			t.Error("matching condition should pass")
		}
	})

	t.Run("single failing condition", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", false)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict == VerdictTrue {
			t.Error("non-matching condition should fail")
		}
	})

	t.Run("all conditions must pass", func(t *testing.T) {
		conds := []compiled.CompiledCondition{
			makeCompiledCondition("$.enabled", "eq", true),
			makeCompiledCondition("$.count", "gte", 100.0),
		}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict != VerdictTrue {
			t.Error("all matching conditions should pass")
		}
	})

	t.Run("one failing condition fails all", func(t *testing.T) {
		conds := []compiled.CompiledCondition{
			makeCompiledCondition("$.enabled", "eq", true),
			makeCompiledCondition("$.count", "gte", 200.0), // Fails
		}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict == VerdictTrue {
			t.Error("one failing condition should fail all")
		}
	})

	t.Run("missing path is unknown", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.nonexistent", "eq", true)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict != VerdictUnknown {
			t.Errorf("missing path should be unknown, got %v", result.Verdict)
		}
	})

	t.Run("returns failure details", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.count", "gte", 200.0)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict == VerdictTrue {
			t.Fatal("expected failure")
		}
		if result.Detail == nil {
			t.Fatal("expected detail")
		}
		if result.Detail.Path != "$.count" {
			t.Errorf("Path = %q, want %q", result.Detail.Path, "$.count")
		}
		if result.Detail.Expected == nil {
			t.Fatal("Expected should not be nil")
		}
		if result.Detail.Expected.Op != "gte" {
			t.Errorf("Expected.Op = %q, want %q", result.Detail.Expected.Op, "gte")
		}
		if result.Detail.Expected.Value != 200.0 {
			t.Errorf("Expected.Value = %v, want %v", result.Detail.Expected.Value, 200.0)
		}
		if result.Detail.Actual != 100.0 {
			t.Errorf("Actual = %v, want %v", result.Detail.Actual, 100.0)
		}
		if result.Detail.Delta == nil {
			t.Fatal("Delta should not be nil for numeric comparison")
		}
		if *result.Detail.Delta != -100.0 {
			t.Errorf("Delta = %v, want %v", *result.Detail.Delta, -100.0)
		}
	})

	t.Run("passing conditions still return details for graduated checks", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.count", "gte", 90.0)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Verdict != VerdictTrue {
			t.Error("condition should pass")
		}
		if result.Detail == nil {
			t.Fatal("expected detail even for passing conditions")
		}
		if result.Detail.Path != "$.count" {
			t.Errorf("Path = %q, want %q", result.Detail.Path, "$.count")
		}
		if result.Detail.Actual != 100.0 {
			t.Errorf("Actual = %v, want %v", result.Detail.Actual, 100.0)
		}
	})
}

func TestSelectBestFailureIndex(t *testing.T) {
	t.Run("prioritizes condition failures with path", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureKind: FailureKindNoMatch, FailureDetail: "no artifact"},
			{FailureKind: FailureKindCondition, FailureDetail: "condition failed", ConditionPath: "$.mfa"},
		}
		idx := selectBestFailureIndex(outcomes)
		if idx != 1 {
			t.Errorf("selectBestFailureIndex = %d, want 1 (condition failure)", idx)
		}
	})

	t.Run("falls back to first with detail when no condition failures", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureKind: FailureKindNoMatch, FailureDetail: "no artifact"},
			{FailureKind: FailureKindFreshness, FailureDetail: "too old"},
		}
		idx := selectBestFailureIndex(outcomes)
		// Returns first with detail (index 0), not by failure kind
		if idx != 0 {
			t.Errorf("selectBestFailureIndex = %d, want 0 (first with detail)", idx)
		}
	})

	t.Run("returns first condition failure when multiple exist", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureKind: FailureKindCondition, FailureDetail: "first condition", ConditionPath: "$.a"},
			{FailureKind: FailureKindCondition, FailureDetail: "second condition", ConditionPath: "$.b"},
		}
		idx := selectBestFailureIndex(outcomes)
		if idx != 0 {
			t.Errorf("selectBestFailureIndex = %d, want 0 (first condition failure)", idx)
		}
	})

	t.Run("returns -1 for empty outcomes", func(t *testing.T) {
		idx := selectBestFailureIndex(nil)
		if idx != -1 {
			t.Errorf("selectBestFailureIndex = %d, want -1 (empty outcomes)", idx)
		}
	})

	t.Run("returns 0 when all are no match without details", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureKind: FailureKindNoMatch},
			{FailureKind: FailureKindNoMatch},
		}
		idx := selectBestFailureIndex(outcomes)
		if idx != 0 {
			t.Errorf("selectBestFailureIndex = %d, want 0 (first by default)", idx)
		}
	})
}

func TestSelectBestFailureOutcome(t *testing.T) {
	t.Run("prioritizes condition failures with details", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureKind: FailureKindFreshness, FailureDetail: "artifact too old"},
			{FailureKind: FailureKindCondition, FailureDetail: "conditions not satisfied", ConditionPath: "$.mfa"},
		}
		best := selectBestFailureOutcome(outcomes)
		if best.FailureKind != FailureKindCondition {
			t.Error("should prioritize condition failure")
		}
		if best.ConditionPath != "$.mfa" {
			t.Errorf("ConditionPath = %q, want %q", best.ConditionPath, "$.mfa")
		}
	})

	t.Run("falls back to first non-empty detail", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureDetail: ""},
			{FailureKind: FailureKindFreshness, FailureDetail: "artifact too old"},
			{FailureDetail: "second error"},
		}
		best := selectBestFailureOutcome(outcomes)
		if best.FailureDetail != "artifact too old" {
			t.Errorf("FailureDetail = %q, want %q", best.FailureDetail, "artifact too old")
		}
	})

	t.Run("returns default when all empty", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureDetail: ""},
			{FailureDetail: ""},
		}
		best := selectBestFailureOutcome(outcomes)
		// Should return first outcome when no details
		if best.FailureDetail != "" {
			t.Errorf("FailureDetail = %q, want empty", best.FailureDetail)
		}
	})

	t.Run("empty outcomes", func(t *testing.T) {
		best := selectBestFailureOutcome(nil)
		if best.FailureDetail != "no matching clause found" {
			t.Errorf("FailureDetail = %q, want %q", best.FailureDetail, "no matching clause found")
		}
	})

	t.Run("keeps message and path from same clause", func(t *testing.T) {
		outcomes := []ClauseOutcome{
			{FailureKind: FailureKindFreshness, FailureDetail: "artifact too old", ArtifactPath: "fresh.json"},
			{FailureKind: FailureKindCondition, FailureDetail: "mfa check failed", ConditionPath: "$.mfa", ArtifactPath: "idp.json"},
		}
		best := selectBestFailureOutcome(outcomes)
		// Should pick condition failure
		if best.FailureDetail != "mfa check failed" {
			t.Errorf("FailureDetail = %q, want %q", best.FailureDetail, "mfa check failed")
		}
		if best.ConditionPath != "$.mfa" {
			t.Errorf("ConditionPath = %q, want %q", best.ConditionPath, "$.mfa")
		}
		if best.ArtifactPath != "idp.json" {
			t.Errorf("ArtifactPath = %q, want %q", best.ArtifactPath, "idp.json")
		}
	})
}

func makeCompiledConditionWithCardinality(path, op string, expected any, cardinality compiled.Cardinality) compiled.CompiledCondition {
	expr, isMulti, _ := condition.ParseJSONPathMulti(path)
	parsedOp, _ := condition.ParseOperator(op)

	// Compute BaseExpr for element count checking, mirroring the compiler:
	// every cardinality uses it for absence detection.
	baseExpr := condition.ExtractBasePath(expr)

	return compiled.CompiledCondition{
		Path:        path,
		Expr:        expr,
		BaseExpr:    baseExpr,
		Op:          parsedOp,
		Expected:    expected,
		Cardinality: cardinality,
		IsMulti:     isMulti,
	}
}

func TestEvaluateMultiValueCondition(t *testing.T) {
	// Test data with array of accounts
	body := map[string]any{
		"accounts": []any{
			map[string]any{"id": "acc1", "mfa_enabled": true, "role": "admin"},
			map[string]any{"id": "acc2", "mfa_enabled": true, "role": "user"},
			map[string]any{"id": "acc3", "mfa_enabled": false, "role": "user"},
		},
		"scores": []any{95.0, 88.0, 72.0, 100.0},
	}

	t.Run("cardinality all - all values pass", func(t *testing.T) {
		// All accounts have mfa_enabled field existing
		cond := makeCompiledConditionWithCardinality("$.accounts[*].id", "exists", nil, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, body)
		if verdict != VerdictTrue {
			t.Error("all accounts have id, should pass")
		}
	})

	t.Run("cardinality all - one value fails", func(t *testing.T) {
		// Not all accounts have mfa_enabled = true
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", true, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, body)
		if verdict == VerdictTrue {
			t.Error("one account has mfa_enabled=false, should fail")
		}
		if detail.Actual != false {
			t.Errorf("Actual = %v, want false (the failing value)", detail.Actual)
		}
	})

	t.Run("cardinality any - at least one passes", func(t *testing.T) {
		// At least one account has mfa_enabled = false
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", false, compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, body)
		if verdict != VerdictTrue {
			t.Error("one account has mfa_enabled=false, should pass")
		}
	})

	t.Run("cardinality any - none pass", func(t *testing.T) {
		// No account has role = "superuser"
		cond := makeCompiledConditionWithCardinality("$.accounts[*].role", "eq", "superuser", compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, body)
		if verdict == VerdictTrue {
			t.Error("no account has role=superuser, should fail")
		}
	})

	t.Run("cardinality none - no value passes", func(t *testing.T) {
		// No account has role = "superuser"
		cond := makeCompiledConditionWithCardinality("$.accounts[*].role", "eq", "superuser", compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, body)
		if verdict != VerdictTrue {
			t.Error("no account has role=superuser, cardinality:none should pass")
		}
	})

	t.Run("cardinality none - one value passes (fail)", func(t *testing.T) {
		// At least one account has role = "admin" (violation for none)
		cond := makeCompiledConditionWithCardinality("$.accounts[*].role", "eq", "admin", compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, body)
		if verdict == VerdictTrue {
			t.Error("one account has role=admin, cardinality:none should fail")
		}
	})

	t.Run("cardinality all with numeric comparison", func(t *testing.T) {
		// All scores >= 70
		cond := makeCompiledConditionWithCardinality("$.scores[*]", "gte", 70.0, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, body)
		if verdict != VerdictTrue {
			t.Error("all scores >= 70, should pass")
		}
	})

	t.Run("cardinality all with numeric comparison - fail", func(t *testing.T) {
		// All scores >= 90 (88 is the first value that fails)
		// scores = [95.0, 88.0, 72.0, 100.0] - 88 is checked before 72
		cond := makeCompiledConditionWithCardinality("$.scores[*]", "gte", 90.0, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, body)
		if verdict == VerdictTrue {
			t.Error("88 < 90, should fail")
		}
		// Should show the first failing value (88) and delta
		if detail.Actual != 88.0 {
			t.Errorf("Actual = %v, want 88 (first failing value)", detail.Actual)
		}
		if detail.Delta == nil || *detail.Delta != -2.0 {
			t.Errorf("Delta = %v, want -2 (88-90)", detail.Delta)
		}
	})

	t.Run("empty array - cardinality all is unknown", func(t *testing.T) {
		emptyBody := map[string]any{"items": []any{}}
		cond := makeCompiledConditionWithCardinality("$.items[*].value", "eq", true, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, emptyBody)
		if verdict != VerdictUnknown {
			t.Errorf("empty array with cardinality:all should be unknown, got %v", verdict)
		}
	})

	t.Run("empty array - cardinality none passes", func(t *testing.T) {
		emptyBody := map[string]any{"items": []any{}}
		cond := makeCompiledConditionWithCardinality("$.items[*].value", "eq", true, compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, emptyBody)
		if verdict != VerdictTrue {
			t.Error("empty array with cardinality:none should pass")
		}
	})

	t.Run("cardinality all - partial presence is unknown", func(t *testing.T) {
		// Some accounts are missing the field entirely. The present values all
		// pass, but the absent ones might not have: the condition cannot be
		// scored either way.
		partialBody := map[string]any{
			"accounts": []any{
				map[string]any{"id": "acc1", "mfa_enabled": true},
				map[string]any{"id": "acc2", "mfa_enabled": true},
				map[string]any{"id": "acc3"}, // Missing mfa_enabled field!
			},
		}
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", true, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, partialBody)
		if verdict != VerdictUnknown {
			t.Errorf("one account missing mfa_enabled field, should be unknown with cardinality:all, got %v", verdict)
		}
		// Should report that 2 of 3 elements were evaluated
		if detail.Actual == nil {
			t.Fatal("Actual should indicate unevaluated elements")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string for partial presence, got %T", detail.Actual)
		}
		if actualStr != "2 of 3 elements evaluated" {
			t.Errorf("Actual = %q, want %q", actualStr, "2 of 3 elements evaluated")
		}
	})

	t.Run("cardinality all - all present passes", func(t *testing.T) {
		// All accounts have the field, and all values satisfy condition
		allPresentBody := map[string]any{
			"accounts": []any{
				map[string]any{"id": "acc1", "mfa_enabled": true},
				map[string]any{"id": "acc2", "mfa_enabled": true},
				map[string]any{"id": "acc3", "mfa_enabled": true},
			},
		}
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", true, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, allPresentBody)
		if verdict != VerdictTrue {
			t.Error("all accounts have mfa_enabled=true, should pass")
		}
	})
}

func TestEvaluatePresenceCondition(t *testing.T) {
	// Test data: 3 accounts, only 2 have deprecated_field
	partialBody := map[string]any{
		"accounts": []any{
			map[string]any{"id": "acc1", "deprecated_field": "old_value"},
			map[string]any{"id": "acc2"},
			map[string]any{"id": "acc3", "deprecated_field": "another"},
		},
	}

	// All accounts have the field
	allPresentBody := map[string]any{
		"accounts": []any{
			map[string]any{"id": "acc1", "field": "val1"},
			map[string]any{"id": "acc2", "field": "val2"},
			map[string]any{"id": "acc3", "field": "val3"},
		},
	}

	// No accounts have the field
	nonePresentBody := map[string]any{
		"accounts": []any{
			map[string]any{"id": "acc1"},
			map[string]any{"id": "acc2"},
			map[string]any{"id": "acc3"},
		},
	}

	// === EXISTS tests ===

	t.Run("exists + cardinality:all - all have field passes", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, allPresentBody)
		if verdict != VerdictTrue {
			t.Error("all accounts have field, should pass")
		}
	})

	t.Run("exists + cardinality:all - partial presence fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, partialBody)
		if verdict == VerdictTrue {
			t.Error("only 2 of 3 accounts have deprecated_field, should fail")
		}
		// Should report partial presence
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "2 of 3 elements have field" {
			t.Errorf("Actual = %q, want %q", actualStr, "2 of 3 elements have field")
		}
	})

	t.Run("exists + cardinality:any - partial presence passes", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, partialBody)
		if verdict != VerdictTrue {
			t.Error("at least one account has deprecated_field, should pass")
		}
	})

	t.Run("exists + cardinality:any - none present fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, nonePresentBody)
		if verdict == VerdictTrue {
			t.Error("no accounts have field, should fail")
		}
	})

	t.Run("exists + cardinality:none - none present passes", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, nonePresentBody)
		if verdict != VerdictTrue {
			t.Error("no accounts have deprecated_field, should pass")
		}
	})

	t.Run("exists + cardinality:none - some present fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, partialBody)
		if verdict == VerdictTrue {
			t.Error("some accounts have deprecated_field, should fail")
		}
	})

	// === NOT_EXISTS tests ===

	t.Run("not_exists + cardinality:all - none have field passes", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, nonePresentBody)
		if verdict != VerdictTrue {
			t.Error("no accounts have deprecated_field, should pass")
		}
	})

	t.Run("not_exists + cardinality:all - some have field fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, partialBody)
		if verdict == VerdictTrue {
			t.Error("2 of 3 accounts have deprecated_field, should fail")
		}
		// Should report how many have non-null values (null values satisfy not_exists)
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "2 of 3 elements have non-null value" {
			t.Errorf("Actual = %q, want %q", actualStr, "2 of 3 elements have non-null value")
		}
	})

	t.Run("not_exists + cardinality:any - partial presence passes", func(t *testing.T) {
		// At least one element is missing the field (satisfies not_exists)
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityAny)
		verdict, detail := evaluateSingleCondition(&cond, partialBody)
		if verdict != VerdictTrue {
			t.Error("1 of 3 accounts missing deprecated_field, should pass")
		}
		// Should report how many satisfy not_exists
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "1 of 3 elements satisfy not_exists" {
			t.Errorf("Actual = %q, want %q", actualStr, "1 of 3 elements satisfy not_exists")
		}
	})

	t.Run("not_exists + cardinality:any - all have field fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityAny)
		verdict, detail := evaluateSingleCondition(&cond, allPresentBody)
		if verdict == VerdictTrue {
			t.Error("all accounts have field, should fail")
		}
		// Should report all elements have the field
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "all 3 elements have non-null value" {
			t.Errorf("Actual = %q, want %q", actualStr, "all 3 elements have non-null value")
		}
	})

	t.Run("not_exists + cardinality:none - all have field passes", func(t *testing.T) {
		// No element should be missing the field (all must have it)
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, allPresentBody)
		if verdict != VerdictTrue {
			t.Error("all accounts have field, cardinality:none for not_exists should pass")
		}
	})

	t.Run("not_exists + cardinality:none - some missing fails", func(t *testing.T) {
		// Some elements are missing - this violates "none should satisfy not_exists"
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityNone)
		verdict, detail := evaluateSingleCondition(&cond, partialBody)
		if verdict == VerdictTrue {
			t.Error("1 account missing deprecated_field, cardinality:none for not_exists should fail")
		}
		// Should report how many satisfy not_exists
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "1 of 3 elements satisfy not_exists" {
			t.Errorf("Actual = %q, want %q", actualStr, "1 of 3 elements satisfy not_exists")
		}
	})

	// === NULL VALUE TESTS ===
	// Test that null values are correctly handled per operator semantics

	// Body with null values
	nullBody := map[string]any{
		"accounts": []any{
			map[string]any{"id": "acc1", "field": nil},     // null value
			map[string]any{"id": "acc2", "field": "value"}, // non-null value
			map[string]any{"id": "acc3"},                   // missing field
		},
	}

	// Body with all null values
	allNullBody := map[string]any{
		"accounts": []any{
			map[string]any{"id": "acc1", "field": nil},
			map[string]any{"id": "acc2", "field": nil},
			map[string]any{"id": "acc3", "field": nil},
		},
	}

	t.Run("exists + cardinality:all - null values fail", func(t *testing.T) {
		// exists requires non-null, so null values should fail
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, nullBody)
		if verdict == VerdictTrue {
			t.Error("one account has null field, should fail")
		}
		// Only 1 of 3 elements has non-null field (acc2)
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "1 of 3 elements have field" {
			t.Errorf("Actual = %q, want %q", actualStr, "1 of 3 elements have field")
		}
	})

	t.Run("exists + cardinality:any - one non-null passes", func(t *testing.T) {
		// At least one non-null value exists
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, nullBody)
		if verdict != VerdictTrue {
			t.Error("acc2 has non-null field, should pass")
		}
	})

	t.Run("exists + cardinality:any - all null fails", func(t *testing.T) {
		// No non-null values
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, allNullBody)
		if verdict == VerdictTrue {
			t.Error("all fields are null, should fail")
		}
	})

	t.Run("not_exists + cardinality:all - all null passes", func(t *testing.T) {
		// All values are null, so all satisfy not_exists
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, allNullBody)
		if verdict != VerdictTrue {
			t.Error("all fields are null, should pass not_exists:all")
		}
	})

	t.Run("not_exists + cardinality:all - one non-null fails", func(t *testing.T) {
		// acc2 has non-null value, so not all satisfy not_exists
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, nullBody)
		if verdict == VerdictTrue {
			t.Error("acc2 has non-null field, should fail not_exists:all")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "1 of 3 elements have non-null value" {
			t.Errorf("Actual = %q, want %q", actualStr, "1 of 3 elements have non-null value")
		}
	})

	t.Run("not_exists + cardinality:any - null satisfies", func(t *testing.T) {
		// acc1 has null (satisfies), acc3 is missing (satisfies)
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityAny)
		verdict, detail := evaluateSingleCondition(&cond, nullBody)
		if verdict != VerdictTrue {
			t.Error("acc1 has null and acc3 is missing, should pass not_exists:any")
		}
		// 2 of 3 satisfy not_exists (null + missing)
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "2 of 3 elements satisfy not_exists" {
			t.Errorf("Actual = %q, want %q", actualStr, "2 of 3 elements satisfy not_exists")
		}
	})

	t.Run("not_exists + cardinality:none - null violates", func(t *testing.T) {
		// null values satisfy not_exists, so cardinality:none should fail
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityNone)
		verdict, detail := evaluateSingleCondition(&cond, nullBody)
		if verdict == VerdictTrue {
			t.Error("acc1 has null and acc3 is missing, should fail not_exists:none")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "2 of 3 elements satisfy not_exists" {
			t.Errorf("Actual = %q, want %q", actualStr, "2 of 3 elements satisfy not_exists")
		}
	})
}

// TestEvaluatePresenceCondition_RecursiveDescent tests presence operators with
// recursive descent paths ($..field) where BaseExpr cannot be extracted.
// These paths have no single base array, so element count comparison is impossible.
func TestEvaluatePresenceCondition_RecursiveDescent(t *testing.T) {
	// Helper to create conditions with recursive descent (BaseExpr will be nil)
	makeRecursiveDescentCondition := func(path, opStr string, cardinality compiled.Cardinality) compiled.CompiledCondition {
		expr, _, _ := condition.ParseJSONPathMulti(path)
		op, _ := condition.ParseOperator(opStr)
		// BaseExpr is nil for recursive descent - ExtractBasePath returns nil for $..
		return compiled.CompiledCondition{
			Path:        path,
			Expr:        expr,
			BaseExpr:    nil, // Explicitly nil - recursive descent has no base array
			Op:          op,
			Expected:    nil,
			Cardinality: cardinality,
			IsMulti:     true,
		}
	}

	// Nested structure for recursive descent tests
	nestedBody := map[string]any{
		"level1": map[string]any{
			"field": "value1",
			"level2": map[string]any{
				"field": "value2",
				"level3": map[string]any{
					"field": "value3",
				},
			},
		},
	}

	// Nested structure with null values
	nullNestedBody := map[string]any{
		"level1": map[string]any{
			"field": nil, // null
			"level2": map[string]any{
				"field": "value2",
				"level3": map[string]any{
					"field": nil, // null
				},
			},
		},
	}

	// Nested structure with no matching fields
	noFieldBody := map[string]any{
		"level1": map[string]any{
			"other": "value1",
			"level2": map[string]any{
				"other": "value2",
			},
		},
	}

	// exists + cardinality:all with recursive descent
	// Without BaseExpr, we can only verify all found values are non-null
	t.Run("exists + recursive descent + cardinality:all - all found non-null passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, nestedBody)
		if verdict != VerdictTrue {
			t.Error("all $..field values are non-null, should pass")
		}
	})

	t.Run("exists + recursive descent + cardinality:all - some null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, nullNestedBody)
		if verdict == VerdictTrue {
			t.Error("some $..field values are null, should fail exists:all")
		}
		// Should indicate null values found
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "some values are null" {
			t.Errorf("Actual = %q, want %q", actualStr, "some values are null")
		}
	})

	t.Run("exists + recursive descent + cardinality:all - no matches fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, noFieldBody)
		if verdict == VerdictTrue {
			t.Error("no $..field values found, should fail exists:all")
		}
	})

	// exists + cardinality:any with recursive descent
	t.Run("exists + recursive descent + cardinality:any - one non-null passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, nullNestedBody)
		if verdict != VerdictTrue {
			t.Error("at least one $..field is non-null, should pass")
		}
	})

	t.Run("exists + recursive descent + cardinality:any - no matches fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, noFieldBody)
		if verdict == VerdictTrue {
			t.Error("no $..field values found, should fail exists:any")
		}
	})

	// exists + cardinality:none with recursive descent
	t.Run("exists + recursive descent + cardinality:none - no matches passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, noFieldBody)
		if verdict != VerdictTrue {
			t.Error("no $..field values found, cardinality:none should pass")
		}
	})

	t.Run("exists + recursive descent + cardinality:none - some matches fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, nestedBody)
		if verdict == VerdictTrue {
			t.Error("$..field values found, cardinality:none should fail")
		}
	})

	// not_exists + cardinality:all with recursive descent
	// Without BaseExpr, we can only check if all found values are null
	t.Run("not_exists + recursive descent + cardinality:all - all found null passes", func(t *testing.T) {
		// Create body where all found fields are null
		allNullNestedBody := map[string]any{
			"level1": map[string]any{
				"field": nil,
				"level2": map[string]any{
					"field": nil,
				},
			},
		}
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, allNullNestedBody)
		if verdict != VerdictTrue {
			t.Error("all $..field values are null, should pass not_exists:all")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:all - some non-null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAll)
		verdict, detail := evaluateSingleCondition(&cond, nullNestedBody)
		if verdict == VerdictTrue {
			t.Error("some $..field values are non-null, should fail not_exists:all")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "some values are non-null" {
			t.Errorf("Actual = %q, want %q", actualStr, "some values are non-null")
		}
	})

	// not_exists + cardinality:any with recursive descent
	t.Run("not_exists + recursive descent + cardinality:any - some null passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, nullNestedBody)
		if verdict != VerdictTrue {
			t.Error("some $..field values are null, should pass not_exists:any")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:any - all non-null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAny)
		verdict, detail := evaluateSingleCondition(&cond, nestedBody)
		if verdict == VerdictTrue {
			t.Error("all $..field values are non-null, should fail not_exists:any")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "no null values found" {
			t.Errorf("Actual = %q, want %q", actualStr, "no null values found")
		}
	})

	// not_exists + cardinality:none with recursive descent
	t.Run("not_exists + recursive descent + cardinality:none - all non-null passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityNone)
		verdict, _ := evaluateSingleCondition(&cond, nestedBody)
		if verdict != VerdictTrue {
			t.Error("all $..field values are non-null, cardinality:none should pass (no element satisfies not_exists)")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:none - some null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityNone)
		verdict, detail := evaluateSingleCondition(&cond, nullNestedBody)
		if verdict == VerdictTrue {
			t.Error("some $..field values are null, cardinality:none should fail")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string, got %T", detail.Actual)
		}
		if actualStr != "some values are null" {
			t.Errorf("Actual = %q, want %q", actualStr, "some values are null")
		}
	})

	// Edge case: no matches found (recursive descent finds nothing)
	t.Run("not_exists + recursive descent + cardinality:all - no matches passes", func(t *testing.T) {
		// When no values are found, not_exists:all should pass (vacuously true)
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAll)
		verdict, _ := evaluateSingleCondition(&cond, noFieldBody)
		if verdict != VerdictTrue {
			t.Error("no $..field values found, not_exists:all should pass (vacuously)")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:any - no matches fails", func(t *testing.T) {
		// When no values are found, not_exists:any needs at least one null to pass
		// But there are no values at all, so we can't find a null one
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAny)
		verdict, _ := evaluateSingleCondition(&cond, noFieldBody)
		// This is a semantic question: should "no values found" count as "found a null"?
		// Current implementation: no values found means no null values found → fails
		if verdict == VerdictTrue {
			t.Error("no $..field values found, not_exists:any should fail (no null value to find)")
		}
	})
}

// makeCloudPosturePack builds a PackIndex holding one cloud-posture artifact
// with the given accounts, mirroring the shape cloud collectors emit.
func makeCloudPosturePack(accounts []any) *PackIndex {
	now := time.Date(2024, 6, 14, 12, 0, 0, 0, time.UTC)
	return &PackIndex{
		BySchema: map[string][]IndexedArtifact{
			"evidencepack/cloud-posture@v1": {
				{
					Path:        "artifacts/aws.cloud-posture.json",
					Schema:      "evidencepack/cloud-posture@v1",
					CollectedAt: &now,
					Body: map[string]any{
						"provider": "aws",
						"accounts": accounts,
					},
				},
			},
		},
	}
}

// makeRootProtectionRequirement models the graduated any_of shape cloud
// profiles use for the highest-severity access rules: a pass clause requiring
// the metric true for every account, and a critical clause matching when any
// account reports it false.
func makeRootProtectionRequirement() compiled.CompiledRequirement {
	passCond := makeCompiledConditionWithCardinality("$.accounts[*].iam.root_access_protected", "eq", true, compiled.CardinalityAll)
	failCond := makeCompiledConditionWithCardinality("$.accounts[*].iam.root_access_protected", "eq", false, compiled.CardinalityAny)
	return compiled.CompiledRequirement{
		ID:   "REQ-ROOT",
		Name: "Highest-Privilege Access Protection",
		Mode: compiled.ClauseModeAny,
		Clauses: []compiled.CompiledClause{
			{
				Schema:     "evidencepack/cloud-posture@v1",
				Conditions: []compiled.CompiledCondition{passCond},
				Origin:     compiled.Origin{RequirementID: "REQ-ROOT", ClauseIndex: 0},
			},
			{
				Schema:     "evidencepack/cloud-posture@v1",
				Severity:   "critical",
				Conditions: []compiled.CompiledCondition{failCond},
				Origin:     compiled.Origin{RequirementID: "REQ-ROOT", ClauseIndex: 1},
			},
		},
	}
}

func makeRootProtectionProfile() *compiled.CompiledProfile {
	return &compiled.CompiledProfile{
		ID:           "cloud-test",
		Name:         "Cloud Test",
		Version:      "1.0.0",
		Requirements: []compiled.CompiledRequirement{makeRootProtectionRequirement()},
	}
}

func TestValidate_CloudPosture_AbsentMetricIsUnknownNotCritical(t *testing.T) {
	// The originating incident: a transient collection failure means the
	// account entry carries no root_access_protected at all. That must score
	// as unknown, not as the critical clause matching, and not as the
	// no-clause-matched default failure.
	ctx := makeTestContext()
	pack := makeCloudPosturePack([]any{
		map[string]any{"account_id": "111111111111", "iam": map[string]any{}},
	})

	result := New().Validate(ctx, makeRootProtectionProfile(), pack, "")

	req := result.Requirements[0]
	if req.Status != "unknown" {
		t.Fatalf("Status = %q, want unknown", req.Status)
	}
	if req.Severity != "" {
		t.Errorf("Severity = %q, want empty", req.Severity)
	}
	if req.FailureKind != "insufficient_evidence" {
		t.Errorf("FailureKind = %q, want insufficient_evidence", req.FailureKind)
	}
	if result.Status != "unknown" {
		t.Errorf("overall Status = %q, want unknown", result.Status)
	}
	if result.Summary.Unknown != 1 || result.Summary.Failed != 0 {
		t.Errorf("Summary = %+v, want Unknown=1 Failed=0", result.Summary)
	}
	if len(result.KeyFailures) != 0 {
		t.Errorf("KeyFailures = %v, want empty", result.KeyFailures)
	}
}

func TestValidate_CloudPosture_PartialAccountBlocksSilentPass(t *testing.T) {
	// One healthy account plus one whose metric is absent (e.g. a failed
	// account's stub entry). Previously the pass clause evaluated only the
	// present value and the requirement silently passed; it must be unknown.
	ctx := makeTestContext()
	pack := makeCloudPosturePack([]any{
		map[string]any{"account_id": "111111111111", "iam": map[string]any{"root_access_protected": true}},
		map[string]any{"account_id": "222222222222", "collection_error_code": "AccessDenied", "iam": map[string]any{}},
	})

	result := New().Validate(ctx, makeRootProtectionProfile(), pack, "")

	req := result.Requirements[0]
	if req.Status != "unknown" {
		t.Fatalf("Status = %q, want unknown (was a silent pass before three-valued evaluation)", req.Status)
	}
	if result.Summary.Unknown != 1 {
		t.Errorf("Summary.Unknown = %d, want 1", result.Summary.Unknown)
	}
}

func TestValidate_CloudPosture_DefiniteCriticalStillFails(t *testing.T) {
	// A present, adverse value keeps its graded severity: three-valued
	// evaluation must not soften real findings.
	ctx := makeTestContext()
	pack := makeCloudPosturePack([]any{
		map[string]any{"account_id": "111111111111", "iam": map[string]any{"root_access_protected": false}},
	})

	result := New().Validate(ctx, makeRootProtectionProfile(), pack, "")

	req := result.Requirements[0]
	if req.Status != "fail" {
		t.Fatalf("Status = %q, want fail", req.Status)
	}
	if req.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", req.Severity)
	}
	if len(result.KeyFailures) != 1 {
		t.Errorf("KeyFailures = %v, want the critical finding", result.KeyFailures)
	}
}

func TestValidate_CloudPosture_AllHealthyPasses(t *testing.T) {
	ctx := makeTestContext()
	pack := makeCloudPosturePack([]any{
		map[string]any{"account_id": "111111111111", "iam": map[string]any{"root_access_protected": true}},
		map[string]any{"account_id": "222222222222", "iam": map[string]any{"root_access_protected": true}},
	})

	result := New().Validate(ctx, makeRootProtectionProfile(), pack, "")

	if result.Requirements[0].Status != "pass" {
		t.Fatalf("Status = %q, want pass", result.Requirements[0].Status)
	}
	if result.Status != "pass" {
		t.Errorf("overall Status = %q, want pass", result.Status)
	}
}

func TestValidate_UnknownDoesNotOutrankFail(t *testing.T) {
	// A profile with one definite failure and one unknown requirement reports
	// overall "fail": absent evidence never hides a real finding.
	ctx := makeTestContext()
	pack := makeCloudPosturePack([]any{
		map[string]any{"account_id": "111111111111", "iam": map[string]any{"root_access_protected": false}},
	})

	unknownReq := makeRootProtectionRequirement()
	unknownReq.ID = "REQ-UNKNOWN"
	unknownReq.Clauses[0].Conditions = []compiled.CompiledCondition{
		makeCompiledConditionWithCardinality("$.accounts[*].iam.mfa_coverage_pct", "gte", 100.0, compiled.CardinalityAll),
	}
	unknownReq.Clauses[1].Conditions = []compiled.CompiledCondition{
		makeCompiledConditionWithCardinality("$.accounts[*].iam.mfa_coverage_pct", "lt", 100.0, compiled.CardinalityAny),
	}

	profile := &compiled.CompiledProfile{
		ID:      "cloud-test",
		Name:    "Cloud Test",
		Version: "1.0.0",
		Requirements: []compiled.CompiledRequirement{
			makeRootProtectionRequirement(),
			unknownReq,
		},
	}

	result := New().Validate(ctx, profile, pack, "")

	if result.Status != "fail" {
		t.Fatalf("overall Status = %q, want fail (fail outranks unknown)", result.Status)
	}
	if result.Summary.Failed != 1 || result.Summary.Unknown != 1 {
		t.Errorf("Summary = %+v, want Failed=1 Unknown=1", result.Summary)
	}
}

func TestValidate_ManualRequirement(t *testing.T) {
	v := New()
	profile := &compiled.CompiledProfile{
		ID:   "test-profile",
		Name: "Test",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:       "REQ-001",
				Name:     "MFA Coverage",
				Category: "Access Control",
				Mode:     compiled.ClauseModeAny,
				Clauses: []compiled.CompiledClause{
					{
						Schema: "evidencepack/idp-posture@v1",
						Conditions: []compiled.CompiledCondition{
							makeCompiledCondition("$.mfa_coverage", "gte", 100.0),
						},
					},
				},
			},
			{
				ID:          "REQ-MANUAL",
				Control:     "PL-01",
				Name:        "Information Security Policy",
				Description: "Current version, stating review cadence.",
				Category:    "Access Control",
				Manual:      true,
			},
		},
	}

	result := v.Validate(makeTestContext(), profile, makeTestPackIndex(), "sha256:test")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want pass: a manual requirement never affects the outcome", result.Status)
	}
	if result.Summary.Total != 2 || result.Summary.Passed != 1 || result.Summary.Manual != 1 {
		t.Errorf("Summary = %+v, want Total=2 Passed=1 Manual=1", result.Summary)
	}

	manual := result.Requirements[1]
	if manual.Status != "manual" {
		t.Errorf("Status = %q, want manual", manual.Status)
	}
	if manual.Mode != "" || len(manual.Checks) != 0 {
		t.Errorf("manual requirement must carry no checks; Mode=%q Checks=%d", manual.Mode, len(manual.Checks))
	}
	if manual.Control != "PL-01" || manual.Name != "Information Security Policy" {
		t.Errorf("identity fields should be echoed; got %+v", manual)
	}
	if manual.Description != "Current version, stating review cadence." {
		t.Errorf("Description = %q, want the requirement's description echoed", manual.Description)
	}

	cat := result.ByCategory["Access Control"]
	if cat.Passed != 1 || cat.Manual != 1 {
		t.Errorf("ByCategory = %+v, want Passed=1 Manual=1", cat)
	}
}

func TestValidate_AllManualProfilePassesVacuously(t *testing.T) {
	v := New()
	profile := &compiled.CompiledProfile{
		ID:   "test-profile",
		Name: "Test",
		Requirements: []compiled.CompiledRequirement{
			{ID: "REQ-M1", Name: "Policy Review", Manual: true},
		},
	}

	result := v.Validate(makeTestContext(), profile, makeTestPackIndex(), "sha256:test")

	if result.Status != "pass" {
		t.Errorf("Status = %q, want pass: no machine-checked requirement failed or was unknown", result.Status)
	}
	if result.Summary.Manual != 1 || result.Summary.Passed != 0 {
		t.Errorf("Summary = %+v", result.Summary)
	}
}

// compileProfile compiles a profile written in YAML, the way the tool loads one.
func compileProfile(t *testing.T, yaml string) *compiled.CompiledProfile {
	t.Helper()
	parsed, err := raw.ParseProfileFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	profile, err := compiled.Compile(parsed, "profile.yaml")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return profile
}

// packOf indexes artifacts by schema in the order given.
func packOf(artifacts ...IndexedArtifact) *PackIndex {
	pack := &PackIndex{BySchema: map[string][]IndexedArtifact{}}
	for _, a := range artifacts {
		pack.BySchema[a.Schema] = append(pack.BySchema[a.Schema], a)
	}
	return pack
}

func artifactOf(path, schema string, body map[string]any) IndexedArtifact {
	collected := time.Date(2024, 6, 14, 12, 0, 0, 0, time.UTC)
	return IndexedArtifact{Path: path, Schema: schema, CollectedAt: &collected, Body: body}
}

func cloudPosture(path string, body map[string]any) IndexedArtifact {
	return artifactOf(path, "evidencepack/cloud-posture@v1", body)
}

func iamAccount(id string, iam map[string]any) map[string]any {
	return map[string]any{"account_id": id, "iam": iam}
}

const gateProfileHeader = `id: gates
name: Gates
version: "1.0.0"
requirements:
  - id: R
    name: R
    category: Access
    satisfied_by:
`

// perAccountMFA grades MFA only in accounts that have IAM users.
const perAccountMFA = gateProfileHeader + `      any_of:
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.accounts[*].iam.user_count
                op: gte
                value: 1
                cardinality: each
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.mfa_coverage_pct
                op: gte
                value: 100
                cardinality: all
`

func TestValidate_ApplicableWhen_SameType(t *testing.T) {
	profile := compileProfile(t, gateProfileHeader+`      any_of:
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.provider
                op: eq
                value: aws
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.root_mfa_enabled
                op: eq
                value: true
                cardinality: all
`)
	accounts := []any{iamAccount("1", map[string]any{"root_mfa_enabled": true})}
	tests := []struct {
		name, provider, status, check string
	}{
		{"condition holds", "aws", "pass", "pass"},
		{"condition is false", "azure", "not_applicable", "not_applicable"},
		{"value is absent", "", "unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]any{"accounts": accounts}
			if tt.provider != "" {
				body["provider"] = tt.provider
			}
			result := New().Validate(makeTestContext(), profile, packOf(cloudPosture("artifacts/cloud.json", body)), "")
			req := result.Requirements[0]
			if req.Status != tt.status || req.Checks[0].Status != tt.check {
				t.Fatalf("requirement %s, check %s; want %s, %s", req.Status, req.Checks[0].Status, tt.status, tt.check)
			}
			gate := req.Checks[0].ApplicableWhen
			if gate == nil || gate.Type != "evidencepack/cloud-posture@v1" || len(gate.Conditions) != 1 {
				t.Fatalf("applicable_when = %+v", gate)
			}
			if gate.Skipped != nil || gate.Evaluated != nil {
				t.Errorf("skipped and evaluated appear only with each: %+v", gate)
			}
			if tt.status == "unknown" {
				if req.FailureKind != "insufficient_evidence" || req.Path != "$.provider" || !gate.Conditions[0].Unknown {
					t.Errorf("unknown gate: failure_kind %q, path %q, condition %+v", req.FailureKind, req.Path, gate.Conditions[0])
				}
			}
			if tt.status == "not_applicable" && (req.Severity != "" || req.FailureKind != "") {
				t.Errorf("not applicable is not a failure: severity %q, failure_kind %q", req.Severity, req.FailureKind)
			}
		})
	}
}

func TestValidate_ApplicableWhen_Each(t *testing.T) {
	profile := compileProfile(t, perAccountMFA)
	tests := []struct {
		name               string
		accounts           any
		omitAccounts       bool
		status             string
		skipped, evaluated int
	}{
		{
			name: "accounts without IAM users are skipped",
			accounts: []any{
				iamAccount("1", map[string]any{"user_count": 0.0, "mfa_coverage_pct": nil}),
				iamAccount("2", map[string]any{"user_count": 3.0, "mfa_coverage_pct": 100.0}),
				iamAccount("3", map[string]any{"user_count": 0.0}),
			},
			status: "pass", skipped: 2, evaluated: 1,
		},
		{
			name: "a skipped account cannot fail the test",
			accounts: []any{
				iamAccount("1", map[string]any{"user_count": 0.0, "mfa_coverage_pct": 0.0}),
				iamAccount("2", map[string]any{"user_count": 3.0, "mfa_coverage_pct": 100.0}),
			},
			status: "pass", skipped: 1, evaluated: 1,
		},
		{
			name: "an admitted account fails it",
			accounts: []any{
				iamAccount("1", map[string]any{"user_count": 0.0}),
				iamAccount("2", map[string]any{"user_count": 4.0, "mfa_coverage_pct": 50.0}),
			},
			status: "fail", skipped: 1, evaluated: 1,
		},
		{
			name: "an account with no count is graded on its value",
			accounts: []any{
				iamAccount("1", map[string]any{"mfa_coverage_pct": 100.0}),
				iamAccount("2", map[string]any{"mfa_coverage_pct": 90.0}),
			},
			status: "fail", skipped: 0, evaluated: 2,
		},
		{
			name: "an account with no facts keeps the test unknown",
			accounts: []any{
				iamAccount("1", map[string]any{"user_count": 2.0, "mfa_coverage_pct": 100.0}),
				map[string]any{"account_id": "2", "collection_error_code": "AccessDenied", "iam": map[string]any{}},
			},
			status: "unknown", skipped: 0, evaluated: 2,
		},
		{
			name: "every account skipped",
			accounts: []any{
				iamAccount("1", map[string]any{"user_count": 0.0}),
				iamAccount("2", map[string]any{"user_count": 0.0}),
			},
			status: "not_applicable", skipped: 2, evaluated: 0,
		},
		{
			name:     "no accounts",
			accounts: []any{},
			status:   "unknown",
		},
		{
			name:     "a null list",
			accounts: nil,
			status:   "unknown",
		},
		{
			name:         "an absent list",
			omitAccounts: true,
			status:       "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]any{"provider": "aws"}
			if !tt.omitAccounts {
				body["accounts"] = tt.accounts
			}
			result := New().Validate(makeTestContext(), profile, packOf(cloudPosture("artifacts/cloud.json", body)), "")
			req := result.Requirements[0]
			if req.Status != tt.status {
				t.Fatalf("Status = %q, want %q (%s)", req.Status, tt.status, req.Message)
			}
			gate := req.Checks[0].ApplicableWhen
			if gate.Skipped == nil || gate.Evaluated == nil {
				t.Fatalf("each reports skipped and evaluated: %+v", gate)
			}
			if *gate.Skipped != tt.skipped || *gate.Evaluated != tt.evaluated {
				t.Errorf("skipped %d, evaluated %d; want %d, %d", *gate.Skipped, *gate.Evaluated, tt.skipped, tt.evaluated)
			}
			if tt.status == "unknown" && tt.evaluated == 0 && req.Path != "$.accounts[*].iam.user_count" {
				t.Errorf("an unusable list reads as the each path absent, got path %q", req.Path)
			}
		})
	}
}

func TestValidate_ApplicableWhen_EachWithWholeArtifactConditions(t *testing.T) {
	profile := compileProfile(t, gateProfileHeader+`      any_of:
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.provider
                op: eq
                value: aws
              - path: $.accounts[*].iam.user_count
                op: gte
                value: 1
                cardinality: each
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.mfa_coverage_pct
                op: gte
                value: 100
                cardinality: all
`)
	noUsers := []any{iamAccount("1", map[string]any{"user_count": 0.0})}
	tests := []struct {
		name   string
		body   map[string]any
		status string
	}{
		{"false wins over the elements", map[string]any{"provider": "azure", "accounts": []any{iamAccount("1", map[string]any{"user_count": 2.0, "mfa_coverage_pct": 50.0})}}, "not_applicable"},
		{"unknown with every element skipped stays unknown", map[string]any{"accounts": noUsers}, "unknown"},
		{"true with every element skipped", map[string]any{"provider": "aws", "accounts": noUsers}, "not_applicable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := New().Validate(makeTestContext(), profile, packOf(cloudPosture("artifacts/cloud.json", tt.body)), "")
			if got := result.Requirements[0].Status; got != tt.status {
				t.Errorf("Status = %q, want %q", got, tt.status)
			}
		})
	}
}

func TestValidate_ApplicableWhen_AcrossArtifactsOfTheClauseType(t *testing.T) {
	profile := compileProfile(t, perAccountMFA)
	none := cloudPosture("artifacts/none.json", map[string]any{"accounts": []any{iamAccount("1", map[string]any{"user_count": 0.0})}})
	passing := cloudPosture("artifacts/passing.json", map[string]any{"accounts": []any{iamAccount("1", map[string]any{"user_count": 1.0, "mfa_coverage_pct": 100.0})}})
	failing := cloudPosture("artifacts/failing.json", map[string]any{"accounts": []any{iamAccount("1", map[string]any{"user_count": 1.0, "mfa_coverage_pct": 10.0})}})

	tests := []struct {
		name      string
		artifacts []IndexedArtifact
		status    string
		artifact  string
	}{
		{"a set-aside artifact does not block a match", []IndexedArtifact{none, passing}, "pass", "artifacts/passing.json"},
		{"a set-aside artifact does not hide a failure", []IndexedArtifact{none, failing}, "fail", "artifacts/failing.json"},
		{"every artifact set aside", []IndexedArtifact{none, none}, "not_applicable", "artifacts/none.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := New().Validate(makeTestContext(), profile, packOf(tt.artifacts...), "")
			check := result.Requirements[0].Checks[0]
			if result.Requirements[0].Status != tt.status || check.Artifact != tt.artifact {
				t.Errorf("status %q on %q, want %q on %q", result.Requirements[0].Status, check.Artifact, tt.status, tt.artifact)
			}
		})
	}

	t.Run("a stale artifact is not set aside", func(t *testing.T) {
		withFreshness := compileProfile(t, perAccountMFA+`          freshness:
            max_age_days: 30
`)
		old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		stale := cloudPosture("artifacts/stale.json", map[string]any{"accounts": []any{iamAccount("1", map[string]any{"user_count": 1.0, "mfa_coverage_pct": 100.0})}})
		stale.CollectedAt = &old
		result := New().Validate(makeTestContext(), withFreshness, packOf(stale, none), "")
		if got := result.Requirements[0].Checks[0].Status; got != "stale" {
			t.Errorf("check status %q, want stale: the gate is decided only on fresh artifacts", got)
		}
	})
}

// settingsCapture applies when a cloud posture artifact shows a workforce
// sign-in service in use.
const settingsCapture = gateProfileHeader + `      any_of:
        - type: evidencepack/settings-capture@v1
          freshness:
            max_age_days: 30
          applicable_when:
            type: evidencepack/cloud-posture@v1
            all:
              - path: $.workforce_sign_in.in_use
                op: eq
                value: true
          metadata_conditions:
            all:
              - path: $.metadata.captured_on
                op: max_age_days
                value: 365
`

func TestValidate_ApplicableWhen_AnotherType(t *testing.T) {
	profile := compileProfile(t, settingsCapture)
	inUse := cloudPosture("artifacts/aws.json", map[string]any{"workforce_sign_in": map[string]any{"in_use": true}})
	notInUse := cloudPosture("artifacts/aws-2.json", map[string]any{"workforce_sign_in": map[string]any{"in_use": false}})
	unknown := cloudPosture("artifacts/aws-old.json", map[string]any{})
	capture := artifactOf("artifacts/capture.json", "evidencepack/settings-capture@v1", map[string]any{"metadata": map[string]any{"captured_on": "2024-06-01"}})

	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	oldInUse := inUse
	oldInUse.CollectedAt = &old

	tests := []struct {
		name      string
		artifacts []IndexedArtifact
		status    string
		message   string
	}{
		{"no artifact of the gate's type", []IndexedArtifact{capture}, "missing", "no artifact with schema evidencepack/cloud-posture@v1"},
		{"one artifact, in use, capture on file", []IndexedArtifact{inUse, capture}, "pass", ""},
		{"one artifact, in use, no capture", []IndexedArtifact{inUse}, "missing", "no artifact with schema evidencepack/settings-capture@v1"},
		{"one artifact, not in use", []IndexedArtifact{notInUse}, "not_applicable", "applicable_when does not hold for any evidencepack/cloud-posture@v1 artifact"},
		{"one artifact, unknown", []IndexedArtifact{unknown, capture}, "unknown", "insufficient evidence: $.workforce_sign_in.in_use absent from artifact"},
		{"two artifacts, any true holds", []IndexedArtifact{notInUse, inUse}, "missing", "no artifact with schema evidencepack/settings-capture@v1"},
		{"two artifacts, unknown over false", []IndexedArtifact{notInUse, unknown}, "unknown", "insufficient evidence: $.workforce_sign_in.in_use absent from artifact"},
		{"two artifacts, both false", []IndexedArtifact{notInUse, notInUse}, "not_applicable", "applicable_when does not hold for any evidencepack/cloud-posture@v1 artifact"},
		{"the clause's freshness does not apply to the gate", []IndexedArtifact{oldInUse, capture}, "pass", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := New().Validate(makeTestContext(), profile, packOf(tt.artifacts...), "")
			check := result.Requirements[0].Checks[0]
			if check.Status != tt.status || check.Message != tt.message {
				t.Fatalf("check %q %q, want %q %q", check.Status, check.Message, tt.status, tt.message)
			}
			if check.ApplicableWhen == nil || check.ApplicableWhen.Type != "evidencepack/cloud-posture@v1" {
				t.Errorf("applicable_when = %+v", check.ApplicableWhen)
			}
		})
	}
}

func TestValidate_AnyOf_SetsAsideClausesThatDoNotApply(t *testing.T) {
	profile := compileProfile(t, gateProfileHeader+`      any_of:
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.accounts[*].iam.access_key_user_count
                op: eq
                value: 0
                cardinality: all
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.accounts[*].iam.access_key_user_count
                op: gte
                value: 1
                cardinality: each
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.access_key_rotation_compliant_pct
                op: gte
                value: 100
                cardinality: all
        - type: evidencepack/cloud-posture@v1
          severity: low
          applicable_when:
            all:
              - path: $.accounts[*].iam.access_key_user_count
                op: gte
                value: 1
                cardinality: each
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.access_key_rotation_compliant_pct
                op: gte
                value: 90
                cardinality: all
`)
	keys := func(count, pct float64) map[string]any {
		return map[string]any{"access_key_user_count": count, "access_key_rotation_compliant_pct": pct}
	}
	run := func(accounts ...any) RequirementResult {
		return New().Validate(makeTestContext(), profile, packOf(cloudPosture("artifacts/cloud.json", map[string]any{"accounts": accounts})), "").Requirements[0]
	}

	t.Run("a gate-only clause passes when it applies", func(t *testing.T) {
		req := run(iamAccount("1", map[string]any{"access_key_user_count": 0.0}))
		if req.Status != "pass" || !req.Checks[0].Selected || req.Checks[1].Status != "not_applicable" {
			t.Errorf("status %q, checks %+v", req.Status, req.Checks)
		}
	})

	t.Run("a graduated failure shows the first clause that applies", func(t *testing.T) {
		req := run(iamAccount("1", keys(2, 95)))
		if req.Status != "fail" || req.Severity != "low" {
			t.Fatalf("status %q severity %q", req.Status, req.Severity)
		}
		if !req.Checks[1].Selected || req.Expected == nil || req.Expected.Value != 100 || req.Actual != 95.0 {
			t.Errorf("selected %v, expected %+v, actual %v", req.Checks[1].Selected, req.Expected, req.Actual)
		}
	})

	t.Run("the default failure never selects a clause that does not apply", func(t *testing.T) {
		req := run(iamAccount("1", keys(2, 50)))
		if req.Status != "fail" || req.Severity != "high" || req.Checks[0].Selected || !req.Checks[1].Selected {
			t.Errorf("status %q severity %q checks %+v", req.Status, req.Severity, req.Checks)
		}
	})

	t.Run("no clause applies", func(t *testing.T) {
		profile := compileProfile(t, perAccountMFA)
		result := New().Validate(makeTestContext(), profile, packOf(cloudPosture("artifacts/cloud.json", map[string]any{"accounts": []any{iamAccount("1", map[string]any{"user_count": 0.0})}})), "")
		req := result.Requirements[0]
		if req.Status != "not_applicable" || req.Severity != "" || req.Checks[0].Selected {
			t.Errorf("requirement %+v", req)
		}
	})
}

func TestValidate_AllOf_FailedTestOutranksMissingType(t *testing.T) {
	missing := `        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.user_security.mfa_coverage_pct
                op: gte
                value: 100
`
	failing := `        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.mfa_coverage_pct
                op: gte
                value: 100
                cardinality: all
`
	pack := packOf(cloudPosture("artifacts/cloud.json", map[string]any{"accounts": []any{iamAccount("1", map[string]any{"mfa_coverage_pct": 50.0})}}))

	for name, clauses := range map[string]string{"missing first": missing + failing, "missing last": failing + missing} {
		t.Run(name, func(t *testing.T) {
			profile := compileProfile(t, gateProfileHeader+"      all_of:\n"+clauses)
			req := New().Validate(makeTestContext(), profile, pack, "").Requirements[0]
			if req.Status != "fail" || req.FailureKind != "condition" || req.Path != "$.accounts[*].iam.mfa_coverage_pct" {
				t.Errorf("status %q failure_kind %q path %q, want the failed comparison to decide", req.Status, req.FailureKind, req.Path)
			}
		})
	}

	t.Run("a missing type alone fails as before", func(t *testing.T) {
		profile := compileProfile(t, gateProfileHeader+"      all_of:\n"+missing+`        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.accounts
                op: exists
`)
		req := New().Validate(makeTestContext(), profile, pack, "").Requirements[0]
		if req.Status != "fail" || req.Severity != "high" || req.FailureKind != "missing" {
			t.Errorf("status %q severity %q failure_kind %q", req.Status, req.Severity, req.FailureKind)
		}
	})

	t.Run("a missing type outranks unknown", func(t *testing.T) {
		profile := compileProfile(t, gateProfileHeader+"      all_of:\n"+`        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.provider
                op: eq
                value: aws
`+missing)
		req := New().Validate(makeTestContext(), profile, pack, "").Requirements[0]
		if req.Status != "fail" || req.FailureKind != "missing" {
			t.Errorf("status %q failure_kind %q", req.Status, req.FailureKind)
		}
	})
}

func TestValidate_AllOf_SetsAsideClausesThatDoNotApply(t *testing.T) {
	gated := `        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.provider
                op: eq
                value: aws
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.mfa_coverage_pct
                op: gte
                value: 100
                cardinality: all
`
	unknown := `        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.accounts[*].iam.root_mfa_enabled
                op: eq
                value: true
                cardinality: all
`
	passing := `        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.provider
                op: eq
                value: azure
`
	pack := packOf(cloudPosture("artifacts/cloud.json", map[string]any{"provider": "azure", "accounts": []any{iamAccount("1", map[string]any{"mfa_coverage_pct": 50.0})}}))

	tests := []struct{ name, clauses, status string }{
		{"with a pass", gated + passing, "pass"},
		{"with an unknown", gated + unknown, "unknown"},
		{"alone", gated, "not_applicable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := compileProfile(t, gateProfileHeader+"      all_of:\n"+tt.clauses)
			req := New().Validate(makeTestContext(), profile, pack, "").Requirements[0]
			if req.Status != tt.status || req.Checks[0].Status != "not_applicable" {
				t.Errorf("status %q, first check %q", req.Status, req.Checks[0].Status)
			}
		})
	}
}

func TestValidate_NotApplicableIsCountedAndNeverChangesTheStatus(t *testing.T) {
	profile := compileProfile(t, perAccountMFA+`  - id: R2
    name: R2
    category: Access
    satisfied_by:
      any_of:
        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.provider
                op: eq
                value: aws
  - id: R3
    name: R3
    category: Other
    satisfied_by:
      all_of:
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.provider
                op: eq
                value: azure
`)
	pack := packOf(cloudPosture("artifacts/cloud.json", map[string]any{"provider": "aws", "accounts": []any{iamAccount("1", map[string]any{"user_count": 0.0})}}))
	result := New().Validate(makeTestContext(), profile, pack, "")

	if result.Status != "pass" || len(result.KeyFailures) != 0 {
		t.Errorf("status %q, key failures %v", result.Status, result.KeyFailures)
	}
	want := Summary{Total: 3, Passed: 1, NotApplicable: 2}
	if result.Summary != want {
		t.Errorf("Summary = %+v, want %+v", result.Summary, want)
	}
	if got := result.ByCategory["Access"]; got != (CategorySummary{Passed: 1, NotApplicable: 1}) {
		t.Errorf("Access = %+v", got)
	}
	if got := result.ByCategory["Other"]; got != (CategorySummary{NotApplicable: 1}) {
		t.Errorf("Other = %+v", got)
	}
}
