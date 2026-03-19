// Package safeyaml provides secure YAML parsing with mandatory pre-validation.
package safeyaml

import (
	"bytes"
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/limits"
	"github.com/locktivity/epack-tool-validate/internal/yamlpolicy"
	"gopkg.in/yaml.v3"
)

// Unmarshal parses YAML data with mandatory security validation.
func Unmarshal(data []byte, limit limits.SizeLimit, v any) error {
	if err := yamlpolicy.ValidateBeforeParse(data, limit.Bytes()); err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}
	return nil
}

// UnmarshalStrict is like Unmarshal but returns an error for unknown fields.
func UnmarshalStrict(data []byte, limit limits.SizeLimit, v any) error {
	if err := yamlpolicy.ValidateBeforeParse(data, limit.Bytes()); err != nil {
		return err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}
	return nil
}
