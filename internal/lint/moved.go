package lint

import (
	"fmt"
	"strings"
)

const (
	accessPosture = "evidencepack/access-posture@v1"
	vulnScanning  = "evidencepack/vuln-scanning@v1"
)

// movedBlocks lists, for each type, the objects epack v0.10.0 moved out of
// it and the type that now holds their values.
var movedBlocks = map[string]map[string]string{
	"evidencepack/cloud-posture@v1": {
		"iam":               accessPosture,
		"workforce_sign_in": accessPosture,
		"vuln_scanning":     vulnScanning,
	},
	"evidencepack/vcs-posture@v1": {
		"org_security":      accessPosture,
		"security_features": vulnScanning,
	},
}

// movedFields says where each moved field's value is now, keyed by its
// object and name. An empty value means the field has no new one.
var movedFields = map[string]string{
	"iam.users_present":                       "members.local_members_present",
	"iam.user_count":                          "members.local_member_count",
	"iam.mfa_user_count":                      "members.local_mfa_member_count",
	"iam.mfa_coverage_pct":                    "members.local_mfa_coverage_pct",
	"iam.root_mfa_enabled":                    "root.root_mfa_coverage_pct",
	"iam.root_access_protected":               "root.root_mfa_coverage_pct at 100 with root.root_access_keys_present false",
	"iam.access_keys_present":                 "credentials.credentials_present",
	"iam.access_key_user_count":               "credentials.credential_count",
	"iam.access_key_rotation_compliant_pct":   "credentials.rotation_overdue_pct, which counts the keys not rotated in time",
	"iam.rotation_compliant_user_count":       "credentials.rotation_overdue_credential_count, which counts the keys not rotated in time",
	"iam.saml_providers_present":              "sign_in.sso_configured",
	"iam.saml_provider_count":                 "",
	"workforce_sign_in.in_use":                "sign_in.sso_configured",
	"workforce_sign_in.user_count":            "members.sso_member_count",
	"workforce_sign_in.mfa_source":            "",
	"vuln_scanning.enabled":                   "scanners[*].enabled",
	"vuln_scanning.scanned_resources_present": "scanners[*].resources_present",
	"vuln_scanning.scanned_resource_count":    "scanners[*].scanned_resource_count",
	"vuln_scanning.unpatched_resource_count":  "",
	"vuln_scanning.unpatched_pct":             "",
	"org_security.two_factor_required":        "sign_in.mfa_required",
}

// movedPath returns the warning for a condition whose path reads a field
// epack v0.10.0 moved to another type, where block is the first field the
// type no longer declares. It reports false for any other unknown field.
// A profile keeps such a condition beside one on the new field while
// collectors upgrade, so the finding is a warning.
func movedPath(typ, path, block string) (string, bool) {
	to, ok := movedBlocks[typ][block]
	if !ok {
		return "", false
	}
	leaf := fieldAfter(path, block)
	where, known := movedFields[block+"."+leaf]
	switch {
	case !known && block == "security_features" && strings.HasSuffix(leaf, "_pct"):
		where, known = "the coverage_pct of the scanner's entry in scanners", true
	case !known && block == "security_features" && strings.HasSuffix(leaf, "_repository_count"):
		where, known = "the scanned_resource_count of the scanner's entry in scanners", true
	}
	var now string
	switch {
	case !known:
		now = fmt.Sprintf("Its values are in %s now", to)
	case where == "":
		now = fmt.Sprintf("Nothing in %s replaces it", to)
	default:
		now = fmt.Sprintf("Read %s in %s", where, to)
	}
	return fmt.Sprintf("%s left %s in epack v0.10.0. %s. Keep this condition beside one on the new field while collectors upgrade", path, typ, now), true
}

// fieldAfter returns the name of the field that follows block in path, or
// "" when path ends at block.
func fieldAfter(path, block string) string {
	i := strings.Index(path, "."+block+".")
	if i < 0 {
		return ""
	}
	rest := path[i+len(block)+2:]
	if j := strings.IndexAny(rest, ".["); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
