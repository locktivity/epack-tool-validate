package safeyaml

import (
	"strings"
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/limits"
)

type testStruct struct {
	Name  string `yaml:"name"`
	Value int    `yaml:"value"`
}

func TestUnmarshal(t *testing.T) {
	t.Run("valid YAML", func(t *testing.T) {
		data := []byte("name: test\nvalue: 42")
		var result testStruct
		if err := Unmarshal(data, limits.ProfileFile, &result); err != nil {
			t.Errorf("Unmarshal() unexpected error: %v", err)
		}
		if result.Name != "test" || result.Value != 42 {
			t.Errorf("Unmarshal() = %+v, want {Name:test, Value:42}", result)
		}
	})

	t.Run("exceeds size limit", func(t *testing.T) {
		data := []byte("name: test\nvalue: 42")
		var result testStruct
		err := Unmarshal(data, limits.SizeLimit(5), &result)
		if err == nil {
			t.Error("Unmarshal() should have returned error for oversized data")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("error should mention 'too large', got: %v", err)
		}
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		data := []byte("name: [unclosed")
		var result testStruct
		err := Unmarshal(data, limits.ProfileFile, &result)
		if err == nil {
			t.Error("Unmarshal() should have returned error for invalid syntax")
		}
		if !strings.Contains(err.Error(), "parsing YAML") {
			t.Errorf("error should mention parsing, got: %v", err)
		}
	})

	t.Run("extra fields allowed", func(t *testing.T) {
		data := []byte("name: test\nvalue: 42\nextra: ignored")
		var result testStruct
		// Unmarshal (non-strict) should allow extra fields
		if err := Unmarshal(data, limits.ProfileFile, &result); err != nil {
			t.Errorf("Unmarshal() should allow extra fields: %v", err)
		}
	})

	t.Run("empty document", func(t *testing.T) {
		data := []byte("")
		var result testStruct
		// Empty document should unmarshal to zero value
		if err := Unmarshal(data, limits.ProfileFile, &result); err != nil {
			t.Errorf("Unmarshal() unexpected error for empty doc: %v", err)
		}
	})
}

func TestUnmarshalStrict(t *testing.T) {
	t.Run("valid YAML", func(t *testing.T) {
		data := []byte("name: test\nvalue: 42")
		var result testStruct
		if err := UnmarshalStrict(data, limits.ProfileFile, &result); err != nil {
			t.Errorf("UnmarshalStrict() unexpected error: %v", err)
		}
		if result.Name != "test" || result.Value != 42 {
			t.Errorf("UnmarshalStrict() = %+v, want {Name:test, Value:42}", result)
		}
	})

	t.Run("exceeds size limit", func(t *testing.T) {
		data := []byte("name: test\nvalue: 42")
		var result testStruct
		err := UnmarshalStrict(data, limits.SizeLimit(5), &result)
		if err == nil {
			t.Error("UnmarshalStrict() should have returned error for oversized data")
		}
	})

	t.Run("rejects unknown fields", func(t *testing.T) {
		data := []byte("name: test\nvalue: 42\nunknown: field")
		var result testStruct
		err := UnmarshalStrict(data, limits.ProfileFile, &result)
		if err == nil {
			t.Error("UnmarshalStrict() should have returned error for unknown field")
		}
		// The error should mention the unknown field or parsing issue
		if !strings.Contains(err.Error(), "parsing YAML") && !strings.Contains(err.Error(), "unknown") {
			t.Errorf("error should mention parsing or unknown field, got: %v", err)
		}
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		data := []byte("name: {bad")
		var result testStruct
		err := UnmarshalStrict(data, limits.ProfileFile, &result)
		if err == nil {
			t.Error("UnmarshalStrict() should have returned error for invalid syntax")
		}
	})
}

func TestUnmarshal_AliasBomb(t *testing.T) {
	// Create YAML with alias bomb pattern
	var b strings.Builder
	b.WriteString("anchor: &a value\nlist:\n")
	for i := 0; i < 150; i++ {
		b.WriteString("  - *a\n")
	}
	data := []byte(b.String())

	var result map[string]any
	err := Unmarshal(data, limits.ProfileFile, &result)
	if err == nil {
		t.Error("Unmarshal() should detect alias bomb")
	}
	if !strings.Contains(err.Error(), "alias bomb") {
		t.Errorf("error should mention 'alias bomb', got: %v", err)
	}
}

func TestUnmarshalStrict_AliasBomb(t *testing.T) {
	// Create YAML with alias bomb pattern
	var b strings.Builder
	b.WriteString("anchor: &a value\nlist:\n")
	for i := 0; i < 150; i++ {
		b.WriteString("  - *a\n")
	}
	data := []byte(b.String())

	var result map[string]any
	err := UnmarshalStrict(data, limits.ProfileFile, &result)
	if err == nil {
		t.Error("UnmarshalStrict() should detect alias bomb")
	}
	if !strings.Contains(err.Error(), "alias bomb") {
		t.Errorf("error should mention 'alias bomb', got: %v", err)
	}
}
