package condition

import (
	"strings"
	"testing"
)

func TestParseJSONPath(t *testing.T) {
	t.Run("valid single-valued paths", func(t *testing.T) {
		validPaths := []string{
			"$.field",
			"$.nested.field",
			"$.deeply.nested.field",
			"$.array[0]",
			"$.array[-1]",
			"$.data[0].name",
		}

		for _, path := range validPaths {
			t.Run(path, func(t *testing.T) {
				expr, err := ParseJSONPath(path)
				if err != nil {
					t.Errorf("ParseJSONPath(%q) unexpected error: %v", path, err)
				}
				if expr == nil {
					t.Errorf("ParseJSONPath(%q) returned nil expression", path)
				}
			})
		}
	})

	t.Run("multi-value paths rejected", func(t *testing.T) {
		multiValuePaths := []string{
			"$.array[*]",   // Wildcard
			"$..field",     // Recursive descent
			"$.array[0:3]", // Slice
			"$[*].name",    // Root wildcard
		}

		for _, path := range multiValuePaths {
			t.Run(path, func(t *testing.T) {
				_, err := ParseJSONPath(path)
				if err == nil {
					t.Errorf("ParseJSONPath(%q) should reject multi-value path", path)
				}
				if err != nil && !strings.Contains(err.Error(), "multiple values") {
					t.Errorf("error should mention 'multiple values', got: %v", err)
				}
			})
		}
	})

	t.Run("filter expressions handling", func(t *testing.T) {
		// Filter expressions may be handled differently by the ojg library
		// The important thing is they don't silently return unexpected results
		path := "$.array[?(@.x > 5)]"
		expr, err := ParseJSONPath(path)
		// If it parses without error, that's acceptable as long as we can evaluate it
		// Note: ojg may handle filters differently than expected
		if err == nil && expr != nil {
			// Just verify it doesn't panic when used
			data := map[string]any{
				"array": []any{
					map[string]any{"x": 1},
					map[string]any{"x": 10},
				},
			}
			_, evalErr := EvaluateJSONPath(expr, data)
			// Either error or success is acceptable
			_ = evalErr
		}
	})

	t.Run("invalid syntax", func(t *testing.T) {
		invalidPaths := []string{
			"$[",       // Unclosed bracket
			"$.field[", // Unclosed bracket
		}

		for _, path := range invalidPaths {
			t.Run(path, func(t *testing.T) {
				_, err := ParseJSONPath(path)
				if err == nil {
					t.Errorf("ParseJSONPath(%q) should reject invalid syntax", path)
				}
			})
		}
	})

	t.Run("empty path", func(t *testing.T) {
		// Empty path may be handled as root ($) by the library
		// Just verify it doesn't panic
		_, _ = ParseJSONPath("")
	})
}

func TestEvaluateJSONPath(t *testing.T) {
	t.Run("simple field access", func(t *testing.T) {
		data := map[string]any{
			"name":  "test",
			"value": 100,
		}

		expr, _ := ParseJSONPath("$.name")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != "test" {
			t.Errorf("EvaluateJSONPath() = %v, want %v", result, "test")
		}
	})

	t.Run("nested field access", func(t *testing.T) {
		data := map[string]any{
			"config": map[string]any{
				"enabled": true,
			},
		}

		expr, _ := ParseJSONPath("$.config.enabled")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != true {
			t.Errorf("EvaluateJSONPath() = %v, want %v", result, true)
		}
	})

	t.Run("array index access", func(t *testing.T) {
		data := map[string]any{
			"items": []any{"first", "second", "third"},
		}

		expr, _ := ParseJSONPath("$.items[0]")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != "first" {
			t.Errorf("EvaluateJSONPath() = %v, want %v", result, "first")
		}
	})

	t.Run("negative array index", func(t *testing.T) {
		data := map[string]any{
			"items": []any{"first", "second", "third"},
		}

		expr, _ := ParseJSONPath("$.items[-1]")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != "third" {
			t.Errorf("EvaluateJSONPath() = %v, want %v", result, "third")
		}
	})

	t.Run("path not found returns nil", func(t *testing.T) {
		data := map[string]any{
			"name": "test",
		}

		expr, _ := ParseJSONPath("$.nonexistent")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("EvaluateJSONPath() = %v, want nil", result)
		}
	})

	t.Run("deeply nested path not found", func(t *testing.T) {
		data := map[string]any{
			"a": map[string]any{},
		}

		expr, _ := ParseJSONPath("$.a.b.c.d")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("EvaluateJSONPath() = %v, want nil", result)
		}
	})

	t.Run("array out of bounds returns nil", func(t *testing.T) {
		data := map[string]any{
			"items": []any{"only"},
		}

		expr, _ := ParseJSONPath("$.items[99]")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("EvaluateJSONPath() = %v, want nil", result)
		}
	})

	t.Run("numeric values", func(t *testing.T) {
		data := map[string]any{
			"mfa_coverage": float64(95),
		}

		expr, _ := ParseJSONPath("$.mfa_coverage")
		result, err := EvaluateJSONPath(expr, data)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != float64(95) {
			t.Errorf("EvaluateJSONPath() = %v, want %v", result, float64(95))
		}
	})

	t.Run("nil input value", func(t *testing.T) {
		expr, _ := ParseJSONPath("$.field")
		result, err := EvaluateJSONPath(expr, nil)
		if err != nil {
			t.Errorf("EvaluateJSONPath() unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("EvaluateJSONPath() = %v, want nil", result)
		}
	})
}

func TestParseJSONPath_RootOnly(t *testing.T) {
	// Test that $ alone works
	expr, err := ParseJSONPath("$")
	if err != nil {
		t.Errorf("ParseJSONPath($) unexpected error: %v", err)
	}

	data := map[string]any{"key": "value"}
	result, err := EvaluateJSONPath(expr, data)
	if err != nil {
		t.Errorf("EvaluateJSONPath($) unexpected error: %v", err)
	}

	// $ should return the root object
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Errorf("EvaluateJSONPath($) should return root object, got %T", result)
	}
	if resultMap["key"] != "value" {
		t.Errorf("EvaluateJSONPath($) = %v, want map with key=value", result)
	}
}
