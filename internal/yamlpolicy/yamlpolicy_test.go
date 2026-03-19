package yamlpolicy

import (
	"strings"
	"testing"
)

func TestValidateBeforeParse(t *testing.T) {
	t.Run("valid small YAML", func(t *testing.T) {
		data := []byte("key: value")
		if err := ValidateBeforeParse(data, 1024); err != nil {
			t.Errorf("ValidateBeforeParse() unexpected error: %v", err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		data := []byte("key: value") // 10 bytes
		err := ValidateBeforeParse(data, 5)
		if err == nil {
			t.Error("ValidateBeforeParse() should have returned error for oversized data")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("error message should contain 'too large', got: %v", err)
		}
	})

	t.Run("exactly at limit", func(t *testing.T) {
		data := []byte("k: v") // 4 bytes
		if err := ValidateBeforeParse(data, 4); err != nil {
			t.Errorf("ValidateBeforeParse() should allow data at exact limit: %v", err)
		}
	})
}

func TestCheckAliasAbuse(t *testing.T) {
	t.Run("no aliases", func(t *testing.T) {
		data := []byte(`
items:
  - name: foo
  - name: bar
`)
		if err := CheckAliasAbuse(data); err != nil {
			t.Errorf("CheckAliasAbuse() unexpected error: %v", err)
		}
	})

	t.Run("valid alias usage", func(t *testing.T) {
		data := []byte(`
defaults: &defaults
  timeout: 30
  retries: 3

service1:
  <<: *defaults
  name: svc1

service2:
  <<: *defaults
  name: svc2
`)
		if err := CheckAliasAbuse(data); err != nil {
			t.Errorf("CheckAliasAbuse() unexpected error for valid alias usage: %v", err)
		}
	})

	t.Run("alias bomb pattern", func(t *testing.T) {
		// Create YAML with many aliases relative to anchors
		// 1 anchor, 100+ aliases would exceed the 10:1 limit
		var b strings.Builder
		b.WriteString("anchor: &a value\nlist:\n")
		for i := 0; i < 150; i++ {
			b.WriteString("  - *a\n")
		}
		data := []byte(b.String())

		err := CheckAliasAbuse(data)
		if err == nil {
			t.Error("CheckAliasAbuse() should detect alias bomb pattern")
		}
		if !strings.Contains(err.Error(), "alias bomb") {
			t.Errorf("error should mention 'alias bomb', got: %v", err)
		}
	})

	t.Run("too many aliases absolute", func(t *testing.T) {
		// More than 100 aliases (MaxYAMLAliasExpansion * 10) without anchors
		// Actually without anchors there can't be aliases in valid YAML
		// But if there are anchors with too many aliases...
		var b strings.Builder
		b.WriteString("a1: &a1 v1\na2: &a2 v2\na3: &a3 v3\nlist:\n")
		// 3 anchors allows 30 aliases max (10:1 ratio)
		// But absolute limit is 100 aliases
		for i := 0; i < 101; i++ {
			b.WriteString("  - *a1\n")
		}
		data := []byte(b.String())

		err := CheckAliasAbuse(data)
		if err == nil {
			t.Error("CheckAliasAbuse() should detect too many aliases")
		}
	})

	t.Run("invalid YAML syntax passthrough", func(t *testing.T) {
		// Invalid YAML should pass through (let main parser report errors)
		data := []byte("invalid: yaml: : : content")
		if err := CheckAliasAbuse(data); err != nil {
			t.Errorf("CheckAliasAbuse() should pass invalid YAML through: %v", err)
		}
	})

	t.Run("empty document", func(t *testing.T) {
		data := []byte("")
		if err := CheckAliasAbuse(data); err != nil {
			t.Errorf("CheckAliasAbuse() unexpected error for empty doc: %v", err)
		}
	})

	t.Run("comment only", func(t *testing.T) {
		data := []byte("# just a comment")
		if err := CheckAliasAbuse(data); err != nil {
			t.Errorf("CheckAliasAbuse() unexpected error for comment: %v", err)
		}
	})
}

func TestCheckAliasAbuse_DeepNesting(t *testing.T) {
	// Create deeply nested YAML that exceeds recursion limit
	var b strings.Builder
	for i := 0; i < 150; i++ {
		for j := 0; j < i; j++ {
			b.WriteString("  ")
		}
		b.WriteString("level")
		b.WriteString(string(rune('0' + i%10)))
		b.WriteString(":\n")
	}
	data := []byte(b.String())

	err := CheckAliasAbuse(data)
	if err == nil {
		t.Error("CheckAliasAbuse() should detect deep nesting")
	}
	if !strings.Contains(err.Error(), "nesting too deep") {
		t.Errorf("error should mention nesting, got: %v", err)
	}
}
