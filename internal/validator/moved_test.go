package validator

import (
	"testing"
	"time"
)

const movedProfile = `id: moved
name: Moved fields
version: "1.0.0"
requirements:
  - id: VCS-001
    name: Code host requires two-factor sign-in
    satisfied_by:
      any_of:
        - type: evidencepack/vcs-posture@v1
          metadata_conditions:
            all:
              - path: $.org_security.two_factor_required
                op: eq
                value: true
  - id: CLOUD-001
    name: Audit logging is on in every account
    satisfied_by:
      any_of:
        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              - path: $.accounts[*].logging.cloudtrail_enabled
                op: eq
                value: true
                cardinality: all
`

// A profile written before epack v0.10.0 names fields a later release
// removes. When an artifact no longer has one, a check reads the field that
// holds the same value: in the same artifact for a rename, or in the same
// collector run's artifact of the new schema for a move. Another run's
// artifact never stands in.
func TestValidate_MovedFields(t *testing.T) {
	profile := compileProfile(t, movedProfile)
	vcs := func(path string, body map[string]any) IndexedArtifact {
		return artifactOf(path, "evidencepack/vcs-posture@v1", body)
	}
	access := func(path string, required bool) IndexedArtifact {
		return artifactOf(path, "evidencepack/access-posture@v1", map[string]any{"sign_in": map[string]any{"mfa_required": required}})
	}
	accounts := func(field string, values ...bool) map[string]any {
		list := []any{}
		for _, value := range values {
			list = append(list, map[string]any{"logging": map[string]any{field: value}})
		}
		return map[string]any{"accounts": list}
	}
	oldGitHub := vcs("artifacts/github.vcs-posture.json", map[string]any{"org_security": map[string]any{"two_factor_required": true}})
	newGitHub := vcs("artifacts/github.vcs-posture.json", map[string]any{"repository_count": 3.0})

	cases := []struct {
		name   string
		files  []IndexedArtifact
		status string
	}{
		{"the old field, as the profile names it", []IndexedArtifact{oldGitHub, access("artifacts/github.access-posture.json", false)}, "pass"},
		{"the old field gone, and the same run's new field true", []IndexedArtifact{newGitHub, access("artifacts/github.access-posture.json", true)}, "pass"},
		{"the old field gone, and the same run's new field false", []IndexedArtifact{newGitHub, access("artifacts/github.access-posture.json", false)}, "fail"},
		{"the old field gone, and only another run has the new field", []IndexedArtifact{newGitHub, access("artifacts/okta.access-posture.json", true)}, "unknown"},
		{"the old field gone from a file at another path", []IndexedArtifact{vcs("artifacts/github.json", map[string]any{}), access("artifacts/github.access-posture.json", true)}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := New().Validate(TestContext(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)), profile, packOf(tc.files...), "sha256:test")
			got := result.Requirements[0]
			if got.Status != tc.status {
				t.Fatalf("VCS-001 status = %q, want %q (%+v)", got.Status, tc.status, got)
			}
			if tc.status == "fail" && got.Path != "$.org_security.two_factor_required" {
				t.Errorf("VCS-001 path = %q, want the profile's path", got.Path)
			}
		})
	}

	renamed := []struct {
		name   string
		body   map[string]any
		status string
	}{
		{"the old name", accounts("cloudtrail_enabled", true, true), "pass"},
		{"only the new name, every account on", accounts("audit_log_enabled", true, true), "pass"},
		{"only the new name, one account off", accounts("audit_log_enabled", true, false), "fail"},
	}
	for _, tc := range renamed {
		t.Run("renamed: "+tc.name, func(t *testing.T) {
			pack := packOf(artifactOf("artifacts/aws.cloud-posture.json", "evidencepack/cloud-posture@v1", tc.body))
			result := New().Validate(TestContext(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)), profile, pack, "sha256:test")
			if got := result.Requirements[1].Status; got != tc.status {
				t.Errorf("CLOUD-001 status = %q, want %q", got, tc.status)
			}
		})
	}
}

// Two tests on one moved field with different criteria each keep their own
// once the old field is gone, even though they share its replacement.
func TestValidate_MovedFieldsKeepEachTestsCriteria(t *testing.T) {
	profile := compileProfile(t, `id: moved-criteria
name: Moved criteria
version: "1.0.0"
requirements:
  - id: VCS-001
    name: Code host requires two-factor sign-in
    satisfied_by:
      any_of:
        - type: evidencepack/vcs-posture@v1
          metadata_conditions:
            all:
              - path: $.org_security.two_factor_required
                op: eq
                value: true
        - type: evidencepack/vcs-posture@v1
          severity: critical
          metadata_conditions:
            all:
              - path: $.org_security.two_factor_required
                op: eq
                value: false
`)
	pack := func(required bool) *PackIndex {
		return packOf(
			artifactOf("artifacts/github.vcs-posture.json", "evidencepack/vcs-posture@v1", map[string]any{"repository_count": 3.0}),
			artifactOf("artifacts/github.access-posture.json", "evidencepack/access-posture@v1", map[string]any{"sign_in": map[string]any{"mfa_required": required}}),
		)
	}
	now := TestContext(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC))

	if got := New().Validate(now, profile, pack(true), "sha256:test").Requirements[0]; got.Status != "pass" {
		t.Errorf("required: status %q, want pass", got.Status)
	}
	got := New().Validate(now, profile, pack(false), "sha256:test").Requirements[0]
	if got.Status != "fail" || got.Severity != "critical" {
		t.Errorf("not required: status %q at %q, want fail at critical", got.Status, got.Severity)
	}
}

// An applies-when condition on a moved field reads the field that holds its
// value once the old one is gone, on the clause's own type or another.
func TestValidate_MovedFieldsInGates(t *testing.T) {
	profile := compileProfile(t, `id: moved-gates
name: Moved gates
version: "1.0.0"
requirements:
  - id: IC-001
    name: Identity Center MFA settings are on file
    satisfied_by:
      any_of:
        - type: evidencepack/identity-center-mfa-settings@v1
          applicable_when:
            type: evidencepack/cloud-posture@v1
            all:
              - path: $.provider
                op: eq
                value: aws
              - path: $.workforce_sign_in.in_use
                op: eq
                value: true
          metadata_conditions:
            all:
              - path: $.metadata.captured_on
                op: exists
  - id: LOG-001
    name: Logged accounts keep logs a year
    satisfied_by:
      any_of:
        - type: evidencepack/cloud-posture@v1
          applicable_when:
            all:
              - path: $.accounts[*].logging.cloudtrail_enabled
                op: eq
                value: true
                cardinality: all
          metadata_conditions:
            all:
              - path: $.provider
                op: eq
                value: aws
`)
	now := TestContext(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC))
	pack := func(sso bool) *PackIndex {
		return packOf(
			artifactOf("artifacts/aws.cloud-posture.json", "evidencepack/cloud-posture@v1", map[string]any{
				"provider": "aws", "accounts": []any{map[string]any{"logging": map[string]any{"audit_log_enabled": true}}},
			}),
			artifactOf("artifacts/aws.access-posture.json", "evidencepack/access-posture@v1", map[string]any{"sign_in": map[string]any{"sso_configured": sso}}),
			artifactOf("artifacts/aws.identity-center-mfa-settings.json", "evidencepack/identity-center-mfa-settings@v1", map[string]any{"metadata": map[string]any{"captured_on": "2024-06-01"}}),
		)
	}

	result := New().Validate(now, profile, pack(true), "sha256:test")
	if got := result.Requirements[0].Status; got != "pass" {
		t.Errorf("IC-001 with SSO set up: status %q, want pass", got)
	}
	if got := result.Requirements[1].Status; got != "pass" {
		t.Errorf("LOG-001 with the renamed field: status %q, want pass", got)
	}
	if got := New().Validate(now, profile, pack(false), "sha256:test").Requirements[0].Status; got != "not_applicable" {
		t.Errorf("IC-001 without SSO: status %q, want not_applicable", got)
	}
}
