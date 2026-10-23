package validator

import (
	"os"
	"slices"
	"testing"
)

// cloudAccessProfilePath grades MFA and access key rotation with
// applicable_when the way a cloud baseline does. The profile's comments say
// what each clause is for.
const cloudAccessProfilePath = "../../testdata/profiles/cloud-access.yaml"

func idp(coverage float64) IndexedArtifact {
	return artifactOf("artifacts/okta.idp-posture.json", "evidencepack/idp-posture@v1", map[string]any{
		"provider":      "okta",
		"user_security": map[string]any{"mfa_coverage_pct": coverage},
	})
}

// capture is a settings capture taken on the given date; the test clock is
// 2024-06-15.
func capture(capturedOn string) IndexedArtifact {
	return artifactOf("artifacts/identity-center-mfa-settings.json", "evidencepack/identity-center-mfa-settings@v1", map[string]any{
		"metadata": map[string]any{"captured_on": capturedOn},
	})
}

func cloud(provider string, signIn map[string]any, accounts ...any) IndexedArtifact {
	body := map[string]any{"schema_version": "1.0.0", "provider": provider, "accounts": accounts}
	if signIn != nil {
		body["workforce_sign_in"] = signIn
	}
	return cloudPosture("artifacts/"+provider+".cloud-posture.json", body)
}

var (
	notInUse      = map[string]any{"in_use": false}
	serviceMFA    = map[string]any{"in_use": true, "user_count": 12.0, "mfa_source": "sign_in_service"}
	externalIdP   = map[string]any{"in_use": true, "user_count": 12.0, "mfa_source": "external_idp"}
	unknownSource = map[string]any{"in_use": true, "user_count": 12.0, "mfa_source": "unknown"}
)

// awsAccount is an account as a collector with the population counts
// reports it: the percentages are left out over an empty population.
func awsAccount(id string, users, samlProviders, keyHolders int, mfaPct, rotationPct float64) map[string]any {
	iam := map[string]any{
		"user_count":            float64(users),
		"saml_provider_count":   float64(samlProviders),
		"access_key_user_count": float64(keyHolders),
	}
	if users > 0 {
		iam["mfa_coverage_pct"] = mfaPct
	}
	if keyHolders > 0 {
		iam["access_key_rotation_compliant_pct"] = rotationPct
	}
	return iamAccount(id, iam)
}

// oldAWSAccount is an account as collectors before the counts report it.
func oldAWSAccount(id string, users, keyHolders int, mfaPct, rotationPct float64) map[string]any {
	iam := map[string]any{}
	if users > 0 {
		iam["mfa_coverage_pct"] = mfaPct
	}
	if keyHolders > 0 {
		iam["access_key_rotation_compliant_pct"] = rotationPct
	}
	return iamAccount(id, iam)
}

// failedAccount is the stub a collector writes for an account it could not
// read: nothing about the account is known.
func failedAccount(id string) map[string]any {
	return map[string]any{"account_id": id, "collection_error_code": "AccessDenied", "iam": map[string]any{}}
}

type truthRow struct {
	name        string
	artifacts   []IndexedArtifact
	status      string
	failureKind string
	severity    string
	checks      []string
}

func runTruthTable(t *testing.T, requirementID string, rows []truthRow) {
	t.Helper()
	data, err := os.ReadFile(cloudAccessProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	profile := compileProfile(t, string(data))
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			result := New().Validate(makeTestContext(), profile, packOf(row.artifacts...), "")
			var req RequirementResult
			for _, r := range result.Requirements {
				if r.ID == requirementID {
					req = r
				}
			}
			var checks []string
			for _, c := range req.Checks {
				checks = append(checks, c.Status)
			}
			if req.Status != row.status || req.FailureKind != row.failureKind || req.Severity != row.severity || !slices.Equal(checks, row.checks) {
				t.Errorf("got %s (%s, %s) checks %v\nwant %s (%s, %s) checks %v\nmessage: %s",
					req.Status, req.FailureKind, req.Severity, checks,
					row.status, row.failureKind, row.severity, row.checks, req.Message)
			}
		})
	}
}

// The checks are, in order: the IdP test, no IAM users, IAM user MFA, and
// the settings capture.
func TestTruthTable_MFA(t *testing.T) {
	noUsers := awsAccount("111111111111", 0, 0, 0, 0, 0)
	noUsers2 := awsAccount("222222222222", 0, 0, 0, 0, 0)
	withUsers := awsAccount("333333333333", 4, 0, 0, 100, 0)
	lacksMFA := awsAccount("444444444444", 4, 0, 0, 50, 0)

	runTruthTable(t, "MFA", []truthRow{
		// The design table. Each row has an AWS account and a passing IdP test.
		{
			name:      "no IAM users, sign-in service not in use",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", notInUse, noUsers, noUsers2)},
			status:    "pass",
			checks:    []string{"pass", "pass", "not_applicable", "not_applicable"},
		},
		{
			name:      "no IAM users, sign-in service in use, no capture",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, noUsers)},
			status:    "fail", failureKind: "missing", severity: "high",
			checks: []string{"pass", "not_applicable", "not_applicable", "missing"},
		},
		{
			name:      "no IAM users, sign-in service in use, capture on file",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, noUsers), capture("2024-03-01")},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "not_applicable", "pass"},
		},
		{
			name:      "IAM users with MFA, sign-in service not in use",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", notInUse, withUsers, noUsers)},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "pass", "not_applicable"},
		},
		{
			name:      "IAM users with MFA, sign-in service in use, no capture",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, withUsers)},
			status:    "fail", failureKind: "missing", severity: "high",
			checks: []string{"pass", "not_applicable", "pass", "missing"},
		},
		{
			name:      "IAM users with MFA, sign-in service in use, capture on file",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, withUsers), capture("2024-03-01")},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "pass", "pass"},
		},
		{
			name:      "an IAM user without MFA, sign-in service not in use",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", notInUse, withUsers, lacksMFA)},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"pass", "not_applicable", "fail", "not_applicable"},
		},
		{
			name:      "an IAM user without MFA, sign-in service in use, no capture",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, lacksMFA)},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"pass", "not_applicable", "fail", "missing"},
		},
		{
			name:      "an IAM user without MFA, sign-in service in use, capture on file",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, lacksMFA), capture("2024-03-01")},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"pass", "not_applicable", "fail", "pass"},
		},

		// The cases the design table left out.
		{
			name:      "sign-in service users have MFA at an external IdP",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", externalIdP, noUsers)},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "not_applicable", "not_applicable"},
		},
		{
			name:      "sign-in service in use, MFA source unknown",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", unknownSource, noUsers)},
			status:    "fail", failureKind: "missing", severity: "high",
			checks: []string{"pass", "not_applicable", "not_applicable", "missing"},
		},
		{
			name:      "no IAM users, an account trusts a SAML provider directly",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", notInUse, noUsers, awsAccount("555555555555", 0, 1, 0, 0, 0))},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "not_applicable", "not_applicable"},
		},
		{
			name: "the SAML provider listing was denied",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", notInUse, noUsers, iamAccount("666666666666", map[string]any{
				"user_count": 0.0, "access_key_user_count": 0.0,
			}))},
			status: "pass",
			checks: []string{"pass", "not_applicable", "not_applicable", "not_applicable"},
		},
		{
			name:      "the settings capture is over 12 months old",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", serviceMFA, noUsers), capture("2023-01-15")},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"pass", "not_applicable", "not_applicable", "fail"},
		},
		{
			name:      "some accounts have IAM users and some don't",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", notInUse, noUsers, withUsers, noUsers2)},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "pass", "not_applicable"},
		},
		{
			name:      "the collector couldn't read an account",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", nil, withUsers, failedAccount("777777777777"))},
			status:    "unknown", failureKind: "insufficient_evidence",
			checks: []string{"pass", "not_applicable", "unknown", "unknown"},
		},
		{
			name:      "an older collector, an IAM user without MFA",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", nil, oldAWSAccount("111111111111", 4, 0, 50, 0))},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"pass", "not_applicable", "fail", "unknown"},
		},
		{
			name:      "an older collector, every IAM user has MFA",
			artifacts: []IndexedArtifact{idp(100), cloud("aws", nil, oldAWSAccount("111111111111", 4, 0, 100, 0), oldAWSAccount("222222222222", 0, 0, 0, 0))},
			status:    "unknown", failureKind: "insufficient_evidence",
			checks: []string{"pass", "not_applicable", "unknown", "unknown"},
		},
		{
			name:      "a Microsoft cloud pack is graded on its percentage",
			artifacts: []IndexedArtifact{idp(100), cloud("azure", nil, iamAccount("sub-1", map[string]any{"mfa_coverage_pct": 100.0}))},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "pass", "not_applicable"},
		},
		{
			name:      "a Microsoft cloud pack below 100%",
			artifacts: []IndexedArtifact{idp(100), cloud("azure", nil, iamAccount("sub-1", map[string]any{"mfa_coverage_pct": 80.0}))},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"pass", "not_applicable", "fail", "not_applicable"},
		},
		{
			name:      "no IdP evidence",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, noUsers)},
			status:    "fail", failureKind: "missing", severity: "high",
			checks: []string{"missing", "pass", "not_applicable", "not_applicable"},
		},
		{
			name:      "no IdP evidence and an IAM user without MFA",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, lacksMFA)},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"missing", "not_applicable", "fail", "not_applicable"},
		},
		{
			name:      "the IdP test fails",
			artifacts: []IndexedArtifact{idp(90), cloud("aws", notInUse, noUsers)},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"fail", "pass", "not_applicable", "not_applicable"},
		},
	})
}

// The checks are, in order: no access keys, rotation, and rotation at low
// severity.
func TestTruthTable_KeyRotation(t *testing.T) {
	noKeys := awsAccount("111111111111", 4, 0, 0, 100, 0)
	noKeys2 := awsAccount("222222222222", 0, 0, 0, 0, 0)

	runTruthTable(t, "KEY-ROTATION", []truthRow{
		// The design table.
		{
			name:      "no access keys in any account",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, noKeys, noKeys2)},
			status:    "pass",
			checks:    []string{"pass", "not_applicable", "not_applicable"},
		},
		{
			name:      "every key rotated",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, awsAccount("333333333333", 4, 0, 2, 100, 100))},
			status:    "pass",
			checks:    []string{"not_applicable", "pass", "fail"},
		},
		{
			name:      "90% or more in every account with keys",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, awsAccount("333333333333", 4, 0, 10, 100, 90), awsAccount("444444444444", 4, 0, 10, 100, 100))},
			status:    "fail", severity: "low",
			checks: []string{"not_applicable", "fail", "fail"},
		},
		{
			name:      "under 90% in an account",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, awsAccount("333333333333", 4, 0, 10, 100, 80), awsAccount("444444444444", 4, 0, 10, 100, 100))},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"not_applicable", "fail", "fail"},
		},

		// The cases the design table left out.
		{
			name:      "accounts without keys are skipped when others have them",
			artifacts: []IndexedArtifact{cloud("aws", notInUse, noKeys, awsAccount("333333333333", 4, 0, 2, 100, 100))},
			status:    "pass",
			checks:    []string{"not_applicable", "pass", "fail"},
		},
		{
			name:      "the collector couldn't read an account",
			artifacts: []IndexedArtifact{cloud("aws", nil, awsAccount("333333333333", 4, 0, 2, 100, 100), failedAccount("777777777777"))},
			status:    "unknown", failureKind: "insufficient_evidence",
			checks: []string{"not_applicable", "unknown", "unknown"},
		},
		{
			name:      "an older collector, every key rotated",
			artifacts: []IndexedArtifact{cloud("aws", nil, oldAWSAccount("333333333333", 4, 2, 100, 100))},
			status:    "pass",
			checks:    []string{"not_applicable", "pass", "fail"},
		},
		{
			name:      "an older collector, 90% or more",
			artifacts: []IndexedArtifact{cloud("aws", nil, oldAWSAccount("333333333333", 4, 2, 100, 95))},
			status:    "fail", severity: "low",
			checks: []string{"not_applicable", "fail", "fail"},
		},
		{
			name:      "an older collector, an account with no keys",
			artifacts: []IndexedArtifact{cloud("aws", nil, oldAWSAccount("333333333333", 4, 2, 100, 100), oldAWSAccount("444444444444", 4, 0, 100, 0))},
			status:    "unknown", failureKind: "insufficient_evidence",
			checks: []string{"not_applicable", "unknown", "unknown"},
		},
		{
			name:      "an older collector, under 90% in an account",
			artifacts: []IndexedArtifact{cloud("aws", nil, oldAWSAccount("333333333333", 4, 2, 100, 50), oldAWSAccount("444444444444", 4, 0, 100, 0))},
			status:    "fail", failureKind: "condition", severity: "high",
			checks: []string{"not_applicable", "fail", "fail"},
		},
		{
			name:      "a Microsoft cloud pack is graded on its percentage",
			artifacts: []IndexedArtifact{cloud("azure", nil, iamAccount("sub-1", map[string]any{"access_key_rotation_compliant_pct": 95.0}))},
			status:    "fail", severity: "low",
			checks: []string{"not_applicable", "fail", "fail"},
		},
	})
}
