package lint

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lintProfile(t *testing.T, profile string, mutate ...func(dir string, opts *Options)) *Report {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "profile.yaml", profile)
	opts := Options{ProjectRoot: dir, ProfilePath: "profile.yaml"}
	for _, m := range mutate {
		m(dir, &opts)
	}
	report, err := Run(opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return report
}

func codes(r *Report) []string {
	var out []string
	for _, d := range r.Diagnostics {
		out = append(out, d.Code)
	}
	return out
}

func find(t *testing.T, r *Report, code string) Diagnostic {
	t.Helper()
	for _, d := range r.Diagnostics {
		if d.Code == code {
			return d
		}
	}
	t.Fatalf("no %s finding; got %v", code, codes(r))
	return Diagnostic{}
}

const header = `id: p
name: P
version: "1.0.0"
requirements:
`

func requirement(id, typ, conditions string) string {
	return `  - id: ` + id + `
    name: ` + id + ` statement
    satisfied_by:
      any_of:
        - type: ` + typ + `
          metadata_conditions:
            all:
` + conditions
}

func TestRun_CleanProfilePasses(t *testing.T) {
	r := lintProfile(t, header+requirement("IAM-001", "evidencepack/idp-posture@v1", `              - path: $.user_security.mfa_coverage_pct
                op: gte
                value: 100
`))
	if r.Status != "pass" || len(r.Diagnostics) != 0 {
		t.Errorf("status %s, findings %v", r.Status, codes(r))
	}
	if r.Profile.ID != "p" || !strings.HasPrefix(r.Profile.Digest, "sha256:") {
		t.Errorf("profile info = %+v", r.Profile)
	}
}

func TestRun_UnknownPathSuggestsTheDeclaredField(t *testing.T) {
	r := lintProfile(t, header+requirement("IAM-001", "evidencepack/idp-posture@v1", `              - path: $.user_security.mfa_coverage
                op: gte
                value: 100
`))
	d := find(t, r, CodeUnknownPath)
	if r.Status != "fail" || d.Severity != SeverityError {
		t.Errorf("status %s severity %s", r.Status, d.Severity)
	}
	if d.Requirement != "IAM-001" || d.Location != "any_of[0].metadata_conditions.all[0]" {
		t.Errorf("located at %s %s", d.Requirement, d.Location)
	}
	if !slices.Contains(d.Suggestions, "$.user_security.mfa_coverage_pct") {
		t.Errorf("suggestions %v", d.Suggestions)
	}
}

func TestRun_ImpossibleComparisons(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		code      string
		severity  string
	}{
		{"enum value that is never produced", "path: $.provider\n                op: eq\n                value: Okta", CodeNeverMatches, SeverityError},
		{"neq against an impossible value", "path: $.provider\n                op: neq\n                value: Okta", CodeAlwaysMatches, SeverityWarning},
		{"numeric operator on a string", "path: $.provider\n                op: gte\n                value: 1", CodeOperatorMismatch, SeverityError},
		{"number written as a string", "path: $.user_security.mfa_coverage_pct\n                op: gte\n                value: \"90\"", CodeNeverMatches, SeverityError},
		{"boolean compared to a number field", "path: $.user_security.mfa_coverage_pct\n                op: eq\n                value: true", CodeNeverMatches, SeverityError},
		{"comparison against an object", "path: $.user_security\n                op: eq\n                value: true", CodeNeverMatches, SeverityError},
		{"comparison with no value", "path: $.user_security.mfa_coverage_pct\n                op: gte", CodeMissingValue, SeverityError},
		{"field on a scalar", "path: $.provider.name\n                op: exists", CodePathShape, SeverityError},
		{"recursive descent", "path: $..mfa_coverage_pct\n                op: gte\n                value: 1\n                cardinality: all", CodePathUnchecked, SeverityWarning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := lintProfile(t, header+requirement("R", "evidencepack/idp-posture@v1", "              - "+tt.condition+"\n"))
			d := find(t, r, tt.code)
			if d.Severity != tt.severity {
				t.Errorf("severity %s, want %s: %s", d.Severity, tt.severity, d.Message)
			}
		})
	}
}

func TestRun_NullableFieldsNameNullLast(t *testing.T) {
	r := lintProfile(t, header+requirement("R", "evidencepack/idp-posture@v1", `              - path: $.user_security.mfa_coverage_pct
                op: eq
                value: true
              - path: $.user_security
                op: eq
                value: true
`))
	var messages []string
	for _, d := range r.Diagnostics {
		messages = append(messages, d.Message)
	}
	want := []string{
		"eq can never pass: the value true is a boolean, but the field is a number or null",
		"eq can never pass: the path is an object or null, not a single value; compare a field inside it",
	}
	if !slices.Equal(messages, want) {
		t.Errorf("messages %q, want %q", messages, want)
	}
}

func TestRun_EnumThroughRefsAndNullableBranches(t *testing.T) {
	r := lintProfile(t, header+requirement("EMAIL-001", "evidencepack/email-dns@v1", `              - path: $.domains[*].dmarc.policy
                op: eq
                value: reject
                cardinality: all
`))
	if len(r.Diagnostics) != 0 {
		t.Errorf("findings %v", codes(r))
	}
}

func TestRun_VacuousShapes(t *testing.T) {
	tests := []struct{ name, condition string }{
		{"none over a list", "path: $.accounts[*].storage.encryption_pct\n                op: lt\n                value: 100\n                cardinality: none"},
		{"not_exists all", "path: $.accounts[*].iam.root_access_protected\n                op: not_exists\n                cardinality: all"},
		{"exists none", "path: $.accounts[*].iam.root_access_protected\n                op: exists\n                cardinality: none"},
		{"single not_exists", "path: $.provider\n                op: not_exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := lintProfile(t, header+requirement("R", "evidencepack/cloud-posture@v1", "              - "+tt.condition+"\n"))
			if d := find(t, r, CodeVacuousPass); d.Severity != SeverityWarning {
				t.Errorf("severity %s", d.Severity)
			}
			if r.Status != "pass" {
				t.Errorf("warnings alone should pass, got %s", r.Status)
			}
		})
	}
}

func TestRun_AllOverAListIsNotVacuous(t *testing.T) {
	r := lintProfile(t, header+requirement("R", "evidencepack/cloud-posture@v1", `              - path: $.accounts[*].iam.root_access_protected
                op: eq
                value: true
                cardinality: all
`))
	if slices.Contains(codes(r), CodeVacuousPass) {
		t.Errorf("all over an empty list scores as not evaluated, not a pass: %v", codes(r))
	}
}

func TestRun_UnknownTypeWarnsUntilASchemaIsGiven(t *testing.T) {
	profile := header + requirement("R", "acme/thing@v1", `              - path: $.ok
                op: eq
                value: true
`)
	r := lintProfile(t, profile)
	find(t, r, CodeTypeUnchecked)

	r = lintProfile(t, profile, func(dir string, opts *Options) {
		writeFile(t, dir, "schemas/thing.json", `{"type":"object","properties":{"healthy":{"type":"boolean"}}}`)
		opts.SchemaPaths = map[string]string{"acme/thing@v1": "schemas/thing.json"}
	})
	d := find(t, r, CodeUnknownPath)
	if !strings.Contains(d.Message, "healthy") {
		t.Errorf("message should list the declared fields: %s", d.Message)
	}
	if r.Schemas["acme/thing@v1"] != "schemas/thing.json" {
		t.Errorf("schemas %v", r.Schemas)
	}
}

func TestRun_UnreadableSchemaIsAnError(t *testing.T) {
	r := lintProfile(t, header+requirement("R", "acme/thing@v1", "              - path: $.ok\n                op: exists\n"), func(dir string, opts *Options) {
		writeFile(t, dir, "schemas/bad.json", `{not json`)
		opts.SchemaPaths = map[string]string{"acme/thing@v1": "schemas/bad.json"}
	})
	find(t, r, CodeSchemaLoad)
}

func TestRun_ReportsEveryCompileErrorNotJustTheFirst(t *testing.T) {
	r := lintProfile(t, header+requirement("A", "evidencepack/idp-posture@v1", `              - path: $.provider
                op: equalz
                value: okta
              - path: $.provider
                op: eq
                value: okta
                cardinality: sometimes
`)+requirement("B", "evidencepack/idp-posture@v1", `              - path: $.provider
                op: like
                value: okta
`))
	var operators, cardinalities int
	for _, d := range r.Diagnostics {
		switch d.Code {
		case "INVALID_OPERATOR":
			operators++
			if strings.HasPrefix(d.Message, "requirement ") {
				t.Errorf("location prefix not stripped: %s", d.Message)
			}
		case "INVALID_CARDINALITY":
			cardinalities++
		}
	}
	if operators != 2 || cardinalities != 1 {
		t.Errorf("got %v", codes(r))
	}
}

func TestRun_MissingVersionAndRequirementFields(t *testing.T) {
	r := lintProfile(t, `id: p
name: P
requirements:
  - satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
`)
	var missing int
	for _, d := range r.Diagnostics {
		if d.Code == "MISSING_FIELD" {
			missing++
		}
	}
	if missing != 3 {
		t.Errorf("want profile version and requirement id and name; got %v", codes(r))
	}
}

func TestRun_FreshnessOfZeroIsIgnored(t *testing.T) {
	r := lintProfile(t, header+`  - id: R
    name: Pentest is recent
    satisfied_by:
      any_of:
        - type: evidencepack/pentest-report@v1
          freshness:
            max_age_days: 0
`)
	find(t, r, CodeFreshnessIgnored)
	if slices.Contains(codes(r), CodeTypeUnchecked) {
		t.Errorf("a clause with no conditions has no paths to leave unchecked: %v", codes(r))
	}
}

func TestRun_OverlaysAreLintedAsMerged(t *testing.T) {
	r := lintProfile(t, header+requirement("IAM-001", "evidencepack/idp-posture@v1", `              - path: $.user_security.mfa_coverage_pct
                op: gte
                value: 100
`), func(dir string, opts *Options) {
		writeFile(t, dir, "overlays/strict.yaml", `modify:
  - id: IAM-001
    name: Stricter
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.user_security.mfa_coverage_percent
                op: gte
                value: 100
`)
		opts.OverlayPaths = []string{"overlays/strict.yaml"}
	})
	d := find(t, r, CodeUnknownPath)
	if d.File != "overlays/strict.yaml" {
		t.Errorf("finding attributed to %q, want the overlay", d.File)
	}
}

func TestRun_UnparseableProfileIsOneFinding(t *testing.T) {
	r := lintProfile(t, header+"  - id: R\n    name: R\n    unexpected_key: true\n")
	if len(r.Diagnostics) != 1 || r.Diagnostics[0].Code != CodeProfileLoad {
		t.Errorf("got %v", codes(r))
	}
}

func TestReport_TextListsErrorsBeforeWarningsInDocumentOrder(t *testing.T) {
	r := lintProfile(t, header+
		requirement("FIRST", "evidencepack/cloud-posture@v1", "              - path: $.provider\n                op: not_exists\n")+
		requirement("SECOND", "evidencepack/idp-posture@v1", "              - path: $.nope\n                op: exists\n")+
		requirement("THIRD", "evidencepack/idp-posture@v1", "              - path: $.also_nope\n                op: exists\n"))
	var buf bytes.Buffer
	r.WriteText(&buf)
	out := buf.String()
	second, third, first := strings.Index(out, "SECOND"), strings.Index(out, "THIRD"), strings.Index(out, "FIRST")
	if second > third || third > first {
		t.Errorf("order wrong:\n%s", out)
	}
	if !strings.Contains(out, "2 errors, 1 warning") {
		t.Errorf("summary line wrong:\n%s", out)
	}
}
