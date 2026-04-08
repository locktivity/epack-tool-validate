package validator

import (
	"encoding/json"
	"testing"
)

func TestResult_JSONMarshal(t *testing.T) {
	result := &Result{
		Status: "pass",
		Profile: ProfileInfo{
			ID:      "test-profile",
			Name:    "Test Profile",
			Version: "1.0.0",
			Digest:  "sha256:abc123",
		},
		ValidatedAt:      "2024-06-15T12:00:00Z",
		ValidatedAtLabel: "just now",
		PackDigest:       "sha256:def456",
		Summary: Summary{
			Total:    5,
			Passed:   4,
			Failed:   1,
			Missing:  0,
			Warnings: 0,
		},
		Requirements: []RequirementResult{
			{
				ID:     "REQ-001",
				Name:   "Test Requirement",
				Status: "pass",
			},
		},
		ByCategory: map[string]CategorySummary{
			"Security": {Passed: 3, Failed: 1, Missing: 0},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	// Verify it can be unmarshaled back
	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.Status != result.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, result.Status)
	}
	if decoded.Profile.ID != result.Profile.ID {
		t.Errorf("Profile.ID = %q, want %q", decoded.Profile.ID, result.Profile.ID)
	}
	if decoded.Summary.Total != result.Summary.Total {
		t.Errorf("Summary.Total = %d, want %d", decoded.Summary.Total, result.Summary.Total)
	}
}

func TestProfileInfo_JSONMarshal(t *testing.T) {
	info := ProfileInfo{
		ID:      "my-profile",
		Name:    "My Profile",
		Version: "2.0.0",
		Digest:  "sha256:xyz789",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded ProfileInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.ID != info.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, info.ID)
	}
	if decoded.Name != info.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, info.Name)
	}
	if decoded.Version != info.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, info.Version)
	}
	if decoded.Digest != info.Digest {
		t.Errorf("Digest = %q, want %q", decoded.Digest, info.Digest)
	}
}

func TestProfileInfo_OmitEmptyDigest(t *testing.T) {
	info := ProfileInfo{
		ID:      "my-profile",
		Name:    "My Profile",
		Version: "1.0.0",
		Digest:  "", // Empty digest should be omitted
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	// Should not contain "digest" key when empty
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if _, exists := m["digest"]; exists {
		t.Error("digest field should be omitted when empty")
	}
}

func TestSummary_JSONMarshal(t *testing.T) {
	summary := Summary{
		Total:    10,
		Passed:   7,
		Failed:   2,
		Missing:  1,
		Warnings: 1,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded != summary {
		t.Errorf("decoded = %+v, want %+v", decoded, summary)
	}
}

func TestCategorySummary_JSONMarshal(t *testing.T) {
	cat := CategorySummary{
		Passed:  5,
		Failed:  2,
		Missing: 1,
	}

	data, err := json.Marshal(cat)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded CategorySummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded != cat {
		t.Errorf("decoded = %+v, want %+v", decoded, cat)
	}
}

func TestKeyFailure_JSONMarshal(t *testing.T) {
	failure := KeyFailure{
		ID:       "REQ-001",
		Name:     "MFA Enforcement",
		Severity: "high",
	}

	data, err := json.Marshal(failure)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded KeyFailure
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded != failure {
		t.Errorf("decoded = %+v, want %+v", decoded, failure)
	}
}

func TestRequirementResult_JSONMarshal(t *testing.T) {
	delta := -15.0
	result := RequirementResult{
		ID:          "REQ-002",
		Name:        "MFA Coverage",
		Control:     "CC6.2",
		Category:    "Access Control",
		Severity:    "high",
		Status:      "fail",
		FailureKind: "condition",
		Expected:    &ExpectedValue{Op: "gte", Value: 100},
		Actual:      85.0,
		Delta:       &delta,
		Message:     "MFA coverage below threshold",
		Artifact:    "artifacts/idp-posture.json",
		Path:        "$.mfa_coverage",
		Checks: []CheckResult{
			{
				ClauseIndex: 0,
				Schema:      "evidencepack/idp-posture@v1",
				Status:      "fail",
				Artifact:    "artifacts/idp-posture.json",
				Message:     "conditions not satisfied",
				Conditions: []ConditionCheck{
					{
						Path:     "$.mfa_coverage",
						Expected: &ExpectedValue{Op: "gte", Value: 100},
						Actual:   85.0,
						Delta:    &delta,
						Passed:   false,
					},
				},
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded RequirementResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.ID != result.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, result.ID)
	}
	if decoded.Status != result.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, result.Status)
	}
	if decoded.FailureKind != result.FailureKind {
		t.Errorf("FailureKind = %q, want %q", decoded.FailureKind, result.FailureKind)
	}
	if decoded.Delta == nil {
		t.Error("Delta should not be nil")
	} else if *decoded.Delta != *result.Delta {
		t.Errorf("Delta = %v, want %v", *decoded.Delta, *result.Delta)
	}
	if len(decoded.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(decoded.Checks))
	}
	if decoded.Checks[0].Status != "fail" {
		t.Errorf("Checks[0].Status = %q, want %q", decoded.Checks[0].Status, "fail")
	}
	if len(decoded.Checks[0].Conditions) != 1 {
		t.Fatalf("Checks[0].Conditions length = %d, want 1", len(decoded.Checks[0].Conditions))
	}
	if decoded.Checks[0].Conditions[0].Passed {
		t.Error("Checks[0].Conditions[0].Passed = true, want false")
	}
}

func TestRequirementResult_OmitEmpty(t *testing.T) {
	result := RequirementResult{
		ID:     "REQ-001",
		Name:   "Test",
		Status: "pass",
		// All optional fields empty
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	optionalFields := []string{"control", "category", "severity", "failure_kind", "expected", "actual", "delta", "message", "artifact", "path", "checks"}
	for _, field := range optionalFields {
		if _, exists := m[field]; exists {
			t.Errorf("field %q should be omitted when empty", field)
		}
	}
}
