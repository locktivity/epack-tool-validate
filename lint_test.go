package main

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestLintOptions_FromToolConfig(t *testing.T) {
	opts, err := lintOptions(map[string]any{
		"profile":  "profiles/base.yaml",
		"overlays": []any{"overlays/prod.yaml"},
		"schemas":  map[string]any{"acme/thing@v1": "schemas/thing.json"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.ProfilePath != "profiles/base.yaml" || !slices.Equal(opts.OverlayPaths, []string{"overlays/prod.yaml"}) {
		t.Errorf("opts = %+v", opts)
	}
	if opts.SchemaPaths["acme/thing@v1"] != "schemas/thing.json" {
		t.Errorf("schemas = %v", opts.SchemaPaths)
	}
}

func TestLintOptions_ArgumentsReplaceConfig(t *testing.T) {
	opts, err := lintOptions(map[string]any{
		"profile":  "profiles/base.yaml",
		"overlays": []any{"overlays/prod.yaml"},
		"schemas":  map[string]any{"acme/thing@v1": "schemas/thing.json"},
	}, []string{"profiles/draft.yaml", "--overlay", "overlays/a.yaml", "--overlay", "overlays/b.yaml", "--schema", "acme/other@v1=schemas/other.json"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ProfilePath != "profiles/draft.yaml" {
		t.Errorf("profile = %s", opts.ProfilePath)
	}
	if !slices.Equal(opts.OverlayPaths, []string{"overlays/a.yaml", "overlays/b.yaml"}) {
		t.Errorf("overlays = %v", opts.OverlayPaths)
	}
	want := map[string]string{"acme/thing@v1": "schemas/thing.json", "acme/other@v1": "schemas/other.json"}
	if !maps.Equal(opts.SchemaPaths, want) {
		t.Errorf("schemas = %v", opts.SchemaPaths)
	}
}

func TestLintOptions_Errors(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
		args   []string
		want   string
	}{
		{"no profile anywhere", nil, nil, "no profile to lint"},
		{"two profiles", nil, []string{"a.yaml", "b.yaml"}, "one profile at a time"},
		{"unknown flag", nil, []string{"a.yaml", "--strict"}, "unknown argument"},
		{"flag without value", nil, []string{"a.yaml", "--overlay"}, "needs a value"},
		{"schema without type", nil, []string{"a.yaml", "--schema", "schemas/x.json"}, "type=path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lintOptions(tt.config, tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
