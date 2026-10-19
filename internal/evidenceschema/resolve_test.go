package evidenceschema

import (
	"errors"
	"slices"
	"testing"

	"github.com/ohler55/ojg/jp"
)

func resolve(t *testing.T, typ, path string) (*Node, error) {
	t.Helper()
	reg, err := Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	schema := reg.Lookup(typ)
	if schema == nil {
		t.Fatalf("no bundled schema for %s", typ)
	}
	expr, err := jp.ParseString(path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return schema.Resolve(expr)
}

func TestBundled_HoldsEveryNormalizedType(t *testing.T) {
	reg, err := Bundled()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"evidencepack/cloud-posture@v1",
		"evidencepack/email-dns@v1",
		"evidencepack/idp-posture@v1",
		"evidencepack/tls@v1",
		"evidencepack/vcs-posture@v1",
	}
	if got := reg.Types(); !slices.Equal(got, want) {
		t.Errorf("Types() = %v, want %v", got, want)
	}
}

func TestResolve_DeclaredLeaf(t *testing.T) {
	node, err := resolve(t, "evidencepack/idp-posture@v1", "$.user_security.mfa_coverage_pct")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !node.Allows("number") || node.Allows("boolean") {
		t.Errorf("Types = %v, want a number", node.Types)
	}
}

func TestResolve_WildcardIntoArrayItems(t *testing.T) {
	node, err := resolve(t, "evidencepack/cloud-posture@v1", "$.accounts[*].iam.root_access_protected")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !node.Allows("boolean") {
		t.Errorf("Types = %v, want boolean", node.Types)
	}
}

func TestResolve_FollowsRefsThroughNullableOneOf(t *testing.T) {
	node, err := resolve(t, "evidencepack/email-dns@v1", "$.domains[*].dmarc.policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !slices.Contains(node.Enum, any("reject")) {
		t.Errorf("Enum = %v, want the DMARC policy values", node.Enum)
	}
}

func TestResolve_UnknownFieldSuggestsTheDeclaredOne(t *testing.T) {
	_, err := resolve(t, "evidencepack/idp-posture@v1", "$.user_security.mfa_coverage")
	var unknown *UnknownFieldError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want UnknownFieldError", err)
	}
	if unknown.Parent != "$.user_security" || unknown.Field != "mfa_coverage" {
		t.Errorf("got parent %q field %q", unknown.Parent, unknown.Field)
	}
	if !slices.Contains(unknown.Suggestions, "$.user_security.mfa_coverage_pct") {
		t.Errorf("Suggestions = %v, want mfa_coverage_pct", unknown.Suggestions)
	}
	if !slices.Contains(unknown.Known, "mfa_coverage_pct") {
		t.Errorf("Known = %v, want the declared siblings", unknown.Known)
	}
}

func TestResolve_RightFieldWrongNestingIsSuggested(t *testing.T) {
	_, err := resolve(t, "evidencepack/idp-posture@v1", "$.mfa_coverage_pct")
	var unknown *UnknownFieldError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want UnknownFieldError", err)
	}
	if len(unknown.Suggestions) == 0 || unknown.Suggestions[0] != "$.user_security.mfa_coverage_pct" {
		t.Errorf("Suggestions = %v, want the nested field first", unknown.Suggestions)
	}
}

func TestResolve_FieldOnScalarIsAShapeError(t *testing.T) {
	_, err := resolve(t, "evidencepack/idp-posture@v1", "$.provider.name")
	var shape *ShapeError
	if !errors.As(err, &shape) {
		t.Fatalf("err = %v, want ShapeError", err)
	}
}

func TestResolve_DescentIsUnchecked(t *testing.T) {
	_, err := resolve(t, "evidencepack/idp-posture@v1", "$..mfa_coverage_pct")
	var unchecked *UncheckedError
	if !errors.As(err, &unchecked) {
		t.Fatalf("err = %v, want UncheckedError", err)
	}
}

func TestResolve_UndeclaredFieldsUnderAnOpenObject(t *testing.T) {
	reg := &Registry{schemas: map[string]*Schema{}}
	schema := `{"type":"object","properties":{"labels":{"type":"object","additionalProperties":{"type":"string"}},"extra":{"type":"object"}}}`
	if err := reg.Add("custom@v1", []byte(schema), "test"); err != nil {
		t.Fatal(err)
	}
	expr := jp.MustParseString("$.labels.team")
	node, err := reg.Lookup("custom@v1").Resolve(expr)
	if err != nil || !node.Allows("string") || node.Allows("boolean") {
		t.Errorf("map values: node=%+v err=%v", node, err)
	}
	node, err = reg.Lookup("custom@v1").Resolve(jp.MustParseString("$.extra.anything.deeper"))
	if err != nil || !node.Open {
		t.Errorf("free-form object: node=%+v err=%v", node, err)
	}
}

func TestPaths_ListsNestedAndArrayPaths(t *testing.T) {
	reg, _ := Bundled()
	paths := reg.Lookup("evidencepack/cloud-posture@v1").Paths()
	if !slices.Contains(paths, "$.accounts[*].iam.root_access_protected") {
		t.Errorf("Paths missing the per-account IAM field: %v", paths)
	}
}
