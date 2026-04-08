package validator

import (
	"testing"
	"time"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/ohler55/ojg/jp"
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
						Conditions: []compiled.CompiledCondition{makeCompiledCondition("$.nonexistent", "eq", true)}, // Will fail
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
		if !result.Passed {
			t.Error("nil conditions should pass")
		}
		result = evaluateConditionsWithDetails([]compiled.CompiledCondition{}, body)
		if !result.Passed {
			t.Error("empty conditions should pass")
		}
	})

	t.Run("single passing condition", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", true)}
		result := evaluateConditionsWithDetails(conds, body)
		if !result.Passed {
			t.Error("matching condition should pass")
		}
	})

	t.Run("single failing condition", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.enabled", "eq", false)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Passed {
			t.Error("non-matching condition should fail")
		}
	})

	t.Run("all conditions must pass", func(t *testing.T) {
		conds := []compiled.CompiledCondition{
			makeCompiledCondition("$.enabled", "eq", true),
			makeCompiledCondition("$.count", "gte", 100.0),
		}
		result := evaluateConditionsWithDetails(conds, body)
		if !result.Passed {
			t.Error("all matching conditions should pass")
		}
	})

	t.Run("one failing condition fails all", func(t *testing.T) {
		conds := []compiled.CompiledCondition{
			makeCompiledCondition("$.enabled", "eq", true),
			makeCompiledCondition("$.count", "gte", 200.0), // Fails
		}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Passed {
			t.Error("one failing condition should fail all")
		}
	})

	t.Run("missing path fails", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.nonexistent", "eq", true)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Passed {
			t.Error("missing path should fail")
		}
	})

	t.Run("returns failure details", func(t *testing.T) {
		conds := []compiled.CompiledCondition{makeCompiledCondition("$.count", "gte", 200.0)}
		result := evaluateConditionsWithDetails(conds, body)
		if result.Passed {
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
		if !result.Passed {
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

	// Compute BaseExpr for element count checking when needed:
	// - cardinality:all (for partial presence detection)
	// - exists/not_exists with any cardinality (need element count comparison)
	var baseExpr jp.Expr
	if cardinality == compiled.CardinalityAll ||
		parsedOp == condition.OpExists ||
		parsedOp == condition.OpNotExists {
		baseExpr = condition.ExtractBasePath(expr)
	}

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
		passed, _ := evaluateSingleCondition(&cond, body)
		if !passed {
			t.Error("all accounts have id, should pass")
		}
	})

	t.Run("cardinality all - one value fails", func(t *testing.T) {
		// Not all accounts have mfa_enabled = true
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", true, compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, body)
		if passed {
			t.Error("one account has mfa_enabled=false, should fail")
		}
		if detail.Actual != false {
			t.Errorf("Actual = %v, want false (the failing value)", detail.Actual)
		}
	})

	t.Run("cardinality any - at least one passes", func(t *testing.T) {
		// At least one account has mfa_enabled = false
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", false, compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, body)
		if !passed {
			t.Error("one account has mfa_enabled=false, should pass")
		}
	})

	t.Run("cardinality any - none pass", func(t *testing.T) {
		// No account has role = "superuser"
		cond := makeCompiledConditionWithCardinality("$.accounts[*].role", "eq", "superuser", compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, body)
		if passed {
			t.Error("no account has role=superuser, should fail")
		}
	})

	t.Run("cardinality none - no value passes", func(t *testing.T) {
		// No account has role = "superuser"
		cond := makeCompiledConditionWithCardinality("$.accounts[*].role", "eq", "superuser", compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, body)
		if !passed {
			t.Error("no account has role=superuser, cardinality:none should pass")
		}
	})

	t.Run("cardinality none - one value passes (fail)", func(t *testing.T) {
		// At least one account has role = "admin" (violation for none)
		cond := makeCompiledConditionWithCardinality("$.accounts[*].role", "eq", "admin", compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, body)
		if passed {
			t.Error("one account has role=admin, cardinality:none should fail")
		}
	})

	t.Run("cardinality all with numeric comparison", func(t *testing.T) {
		// All scores >= 70
		cond := makeCompiledConditionWithCardinality("$.scores[*]", "gte", 70.0, compiled.CardinalityAll)
		passed, _ := evaluateSingleCondition(&cond, body)
		if !passed {
			t.Error("all scores >= 70, should pass")
		}
	})

	t.Run("cardinality all with numeric comparison - fail", func(t *testing.T) {
		// All scores >= 90 (88 is the first value that fails)
		// scores = [95.0, 88.0, 72.0, 100.0] - 88 is checked before 72
		cond := makeCompiledConditionWithCardinality("$.scores[*]", "gte", 90.0, compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, body)
		if passed {
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

	t.Run("empty array - cardinality all fails", func(t *testing.T) {
		emptyBody := map[string]any{"items": []any{}}
		cond := makeCompiledConditionWithCardinality("$.items[*].value", "eq", true, compiled.CardinalityAll)
		passed, _ := evaluateSingleCondition(&cond, emptyBody)
		if passed {
			t.Error("empty array with cardinality:all should fail")
		}
	})

	t.Run("empty array - cardinality none passes", func(t *testing.T) {
		emptyBody := map[string]any{"items": []any{}}
		cond := makeCompiledConditionWithCardinality("$.items[*].value", "eq", true, compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, emptyBody)
		if !passed {
			t.Error("empty array with cardinality:none should pass")
		}
	})

	t.Run("cardinality all - partial presence fails", func(t *testing.T) {
		// Some accounts are missing the field entirely
		// This should fail even though the existing values all pass
		partialBody := map[string]any{
			"accounts": []any{
				map[string]any{"id": "acc1", "mfa_enabled": true},
				map[string]any{"id": "acc2", "mfa_enabled": true},
				map[string]any{"id": "acc3"}, // Missing mfa_enabled field!
			},
		}
		cond := makeCompiledConditionWithCardinality("$.accounts[*].mfa_enabled", "eq", true, compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, partialBody)
		if passed {
			t.Error("one account missing mfa_enabled field, should fail with cardinality:all")
		}
		// Should report that 2 of 3 elements have the field
		if detail.Actual == nil {
			t.Fatal("Actual should indicate missing elements")
		}
		actualStr, ok := detail.Actual.(string)
		if !ok {
			t.Fatalf("Actual should be string for partial presence, got %T", detail.Actual)
		}
		if actualStr != "2 of 3 elements have field" {
			t.Errorf("Actual = %q, want %q", actualStr, "2 of 3 elements have field")
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
		passed, _ := evaluateSingleCondition(&cond, allPresentBody)
		if !passed {
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
		passed, _ := evaluateSingleCondition(&cond, allPresentBody)
		if !passed {
			t.Error("all accounts have field, should pass")
		}
	})

	t.Run("exists + cardinality:all - partial presence fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, partialBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, partialBody)
		if !passed {
			t.Error("at least one account has deprecated_field, should pass")
		}
	})

	t.Run("exists + cardinality:any - none present fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, nonePresentBody)
		if passed {
			t.Error("no accounts have field, should fail")
		}
	})

	t.Run("exists + cardinality:none - none present passes", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, nonePresentBody)
		if !passed {
			t.Error("no accounts have deprecated_field, should pass")
		}
	})

	t.Run("exists + cardinality:none - some present fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "exists", nil, compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, partialBody)
		if passed {
			t.Error("some accounts have deprecated_field, should fail")
		}
	})

	// === NOT_EXISTS tests ===

	t.Run("not_exists + cardinality:all - none have field passes", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityAll)
		passed, _ := evaluateSingleCondition(&cond, nonePresentBody)
		if !passed {
			t.Error("no accounts have deprecated_field, should pass")
		}
	})

	t.Run("not_exists + cardinality:all - some have field fails", func(t *testing.T) {
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, partialBody)
		if passed {
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
		passed, detail := evaluateSingleCondition(&cond, partialBody)
		if !passed {
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
		passed, detail := evaluateSingleCondition(&cond, allPresentBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, allPresentBody)
		if !passed {
			t.Error("all accounts have field, cardinality:none for not_exists should pass")
		}
	})

	t.Run("not_exists + cardinality:none - some missing fails", func(t *testing.T) {
		// Some elements are missing - this violates "none should satisfy not_exists"
		cond := makeCompiledConditionWithCardinality("$.accounts[*].deprecated_field", "not_exists", nil, compiled.CardinalityNone)
		passed, detail := evaluateSingleCondition(&cond, partialBody)
		if passed {
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
		passed, detail := evaluateSingleCondition(&cond, nullBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, nullBody)
		if !passed {
			t.Error("acc2 has non-null field, should pass")
		}
	})

	t.Run("exists + cardinality:any - all null fails", func(t *testing.T) {
		// No non-null values
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "exists", nil, compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, allNullBody)
		if passed {
			t.Error("all fields are null, should fail")
		}
	})

	t.Run("not_exists + cardinality:all - all null passes", func(t *testing.T) {
		// All values are null, so all satisfy not_exists
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityAll)
		passed, _ := evaluateSingleCondition(&cond, allNullBody)
		if !passed {
			t.Error("all fields are null, should pass not_exists:all")
		}
	})

	t.Run("not_exists + cardinality:all - one non-null fails", func(t *testing.T) {
		// acc2 has non-null value, so not all satisfy not_exists
		cond := makeCompiledConditionWithCardinality("$.accounts[*].field", "not_exists", nil, compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, nullBody)
		if passed {
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
		passed, detail := evaluateSingleCondition(&cond, nullBody)
		if !passed {
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
		passed, detail := evaluateSingleCondition(&cond, nullBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, nestedBody)
		if !passed {
			t.Error("all $..field values are non-null, should pass")
		}
	})

	t.Run("exists + recursive descent + cardinality:all - some null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, nullNestedBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, noFieldBody)
		if passed {
			t.Error("no $..field values found, should fail exists:all")
		}
	})

	// exists + cardinality:any with recursive descent
	t.Run("exists + recursive descent + cardinality:any - one non-null passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, nullNestedBody)
		if !passed {
			t.Error("at least one $..field is non-null, should pass")
		}
	})

	t.Run("exists + recursive descent + cardinality:any - no matches fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, noFieldBody)
		if passed {
			t.Error("no $..field values found, should fail exists:any")
		}
	})

	// exists + cardinality:none with recursive descent
	t.Run("exists + recursive descent + cardinality:none - no matches passes", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, noFieldBody)
		if !passed {
			t.Error("no $..field values found, cardinality:none should pass")
		}
	})

	t.Run("exists + recursive descent + cardinality:none - some matches fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "exists", compiled.CardinalityNone)
		passed, _ := evaluateSingleCondition(&cond, nestedBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, allNullNestedBody)
		if !passed {
			t.Error("all $..field values are null, should pass not_exists:all")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:all - some non-null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAll)
		passed, detail := evaluateSingleCondition(&cond, nullNestedBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, nullNestedBody)
		if !passed {
			t.Error("some $..field values are null, should pass not_exists:any")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:any - all non-null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAny)
		passed, detail := evaluateSingleCondition(&cond, nestedBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, nestedBody)
		if !passed {
			t.Error("all $..field values are non-null, cardinality:none should pass (no element satisfies not_exists)")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:none - some null fails", func(t *testing.T) {
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityNone)
		passed, detail := evaluateSingleCondition(&cond, nullNestedBody)
		if passed {
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
		passed, _ := evaluateSingleCondition(&cond, noFieldBody)
		if !passed {
			t.Error("no $..field values found, not_exists:all should pass (vacuously)")
		}
	})

	t.Run("not_exists + recursive descent + cardinality:any - no matches fails", func(t *testing.T) {
		// When no values are found, not_exists:any needs at least one null to pass
		// But there are no values at all, so we can't find a null one
		cond := makeRecursiveDescentCondition("$..field", "not_exists", compiled.CardinalityAny)
		passed, _ := evaluateSingleCondition(&cond, noFieldBody)
		// This is a semantic question: should "no values found" count as "found a null"?
		// Current implementation: no values found means no null values found → fails
		if passed {
			t.Error("no $..field values found, not_exists:any should fail (no null value to find)")
		}
	})
}
