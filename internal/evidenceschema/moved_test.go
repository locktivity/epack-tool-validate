package evidenceschema

import "testing"

func TestMovedFieldReadsTheSchemasReplacements(t *testing.T) {
	r, err := Bundled()
	if err != nil {
		t.Fatal(err)
	}

	renamed, ok := r.MovedField("evidencepack/cloud-posture@v1", "$.accounts[*].logging.cloudtrail_enabled")
	if !ok || renamed != (Moved{Schema: "evidencepack/cloud-posture@v1", Path: "$.accounts[*].logging.audit_log_enabled", Same: true, Reason: renamed.Reason}) || renamed.Reason == "" {
		t.Errorf("cloudtrail_enabled: got %+v, %v", renamed, ok)
	}

	moved, ok := r.MovedField("evidencepack/vcs-posture@v1", "$['org_security'].two_factor_required")
	if !ok || moved.Schema != "evidencepack/access-posture@v1" || moved.Path != "$.sign_in.mfa_required" || !moved.Same {
		t.Errorf("two_factor_required: got %+v, %v", moved, ok)
	}
	if moved.Reason == "" {
		t.Error("two_factor_required has no reason, though its block has one")
	}

	differs, ok := r.MovedField("evidencepack/cloud-posture@v1", "$.accounts[0].iam.access_key_rotation_compliant_pct")
	if !ok || differs.Same || differs.Path == "" {
		t.Errorf("access_key_rotation_compliant_pct: got %+v, %v", differs, ok)
	}

	if got, ok := r.MovedField("evidencepack/cloud-posture@v1", "$.accounts[*].logging.audit_log_enabled"); ok {
		t.Errorf("audit_log_enabled is not deprecated, got %+v", got)
	}
	if _, ok := r.MovedField("evidencepack/cloud-posture@v1", "$..cloudtrail_enabled"); ok {
		t.Error("a recursive-descent path matched a field")
	}
}
