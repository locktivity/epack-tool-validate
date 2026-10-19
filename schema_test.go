package main

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/locktivity/epack-tool-validate/internal/profile/raw"
)

// These tests keep schema/*.schema.json in step with the grammar the parser
// and compiler accept. Editors and agents read the schema; the tool reads
// the Go types. A field or operator added to one must reach the other.

func loadSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func def(t *testing.T, schema map[string]any, name string) map[string]any {
	t.Helper()
	defs, _ := schema["$defs"].(map[string]any)
	d, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("schema has no $defs/%s", name)
	}
	return d
}

func propertyNames(t *testing.T, node map[string]any) []string {
	t.Helper()
	props, ok := node["properties"].(map[string]any)
	if !ok {
		t.Fatal("node has no properties")
	}
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func yamlFields(v any) []string {
	var names []string
	typ := reflect.TypeOf(v)
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("yaml"), ",")[0]
		if tag != "" && tag != "-" {
			names = append(names, tag)
		}
	}
	sort.Strings(names)
	return names
}

func enumStrings(t *testing.T, node map[string]any, property string) []string {
	t.Helper()
	prop := node["properties"].(map[string]any)[property].(map[string]any)
	var out []string
	for _, v := range prop["enum"].([]any) {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

func TestProfileSchema_FieldsMatchTheGrammar(t *testing.T) {
	schema := loadSchema(t, "schema/profile.schema.json")
	freshness := def(t, schema, "clause")["properties"].(map[string]any)["freshness"].(map[string]any)
	conditions := def(t, schema, "clause")["properties"].(map[string]any)["metadata_conditions"].(map[string]any)

	tests := []struct {
		name   string
		node   map[string]any
		fields any
	}{
		{"profile", schema, raw.RawProfile{}},
		{"requirement", def(t, schema, "requirement"), raw.RawRequirement{}},
		{"satisfied_by", def(t, schema, "satisfied_by"), raw.RawSatisfiedBy{}},
		{"clause", def(t, schema, "clause"), raw.RawClause{}},
		{"freshness", freshness, raw.RawFreshness{}},
		{"metadata_conditions", conditions, raw.RawConditions{}},
		{"condition", def(t, schema, "condition"), raw.RawCondition{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := propertyNames(t, tt.node), yamlFields(tt.fields); !slices.Equal(got, want) {
				t.Errorf("schema properties %v, grammar fields %v", got, want)
			}
		})
	}
}

func TestOverlaySchema_FieldsMatchTheGrammar(t *testing.T) {
	schema := loadSchema(t, "schema/overlay.schema.json")
	if got, want := propertyNames(t, schema), yamlFields(raw.RawOverlay{}); !slices.Equal(got, want) {
		t.Errorf("overlay properties %v, grammar fields %v", got, want)
	}
	if got, want := propertyNames(t, def(t, schema, "modify")), yamlFields(raw.RawModify{}); !slices.Equal(got, want) {
		t.Errorf("modify properties %v, grammar fields %v", got, want)
	}
}

func TestProfileSchema_EnumsMatchTheCompiler(t *testing.T) {
	schema := loadSchema(t, "schema/profile.schema.json")
	cond := def(t, schema, "condition")

	ops := enumStrings(t, cond, "op")
	for _, op := range ops {
		if _, err := condition.ParseOperator(op); err != nil {
			t.Errorf("schema allows op %q, which the compiler rejects", op)
		}
	}
	for op := condition.OpEq; op <= condition.OpMaxAgeDays; op++ {
		if !slices.Contains(ops, op.String()) {
			t.Errorf("compiler accepts op %q, which the schema omits", op)
		}
	}

	var cardinalities []string
	for name := range compiled.ValidCardinalities {
		cardinalities = append(cardinalities, name)
	}
	sort.Strings(cardinalities)
	if got := enumStrings(t, cond, "cardinality"); !slices.Equal(got, cardinalities) {
		t.Errorf("schema cardinalities %v, compiler %v", got, cardinalities)
	}

	var severities []string
	for name := range compiled.ValidSeverities {
		severities = append(severities, name)
	}
	sort.Strings(severities)
	if got := enumStrings(t, def(t, schema, "clause"), "severity"); !slices.Equal(got, severities) {
		t.Errorf("schema severities %v, compiler %v", got, severities)
	}
}
