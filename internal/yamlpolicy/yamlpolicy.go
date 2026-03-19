// Package yamlpolicy provides YAML security checks before parsing.
package yamlpolicy

import (
	"bytes"
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/limits"
	"gopkg.in/yaml.v3"
)

// ValidateBeforeParse performs security checks before YAML parsing.
func ValidateBeforeParse(data []byte, maxSize int64) error {
	if int64(len(data)) > maxSize {
		return fmt.Errorf("YAML data too large: %d bytes exceeds limit of %d bytes",
			len(data), maxSize)
	}

	if err := CheckAliasAbuse(data); err != nil {
		return err
	}

	return nil
}

// CheckAliasAbuse scans raw YAML for potential alias bomb patterns.
func CheckAliasAbuse(data []byte) error {
	var root yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&root); err != nil {
		// Let the main Unmarshal report syntax errors
		return nil
	}

	var anchors, aliases int
	guard := limits.NewRecursionGuard(limits.MaxRecursionDepth)
	if err := countAliasesWithGuard(&root, &anchors, &aliases, guard); err != nil {
		return fmt.Errorf("YAML nesting too deep: %w", err)
	}

	if anchors > 0 && aliases > anchors*limits.MaxYAMLAliasExpansion {
		return fmt.Errorf("potential YAML alias bomb detected: %d aliases for %d anchors (max ratio %d:1)",
			aliases, anchors, limits.MaxYAMLAliasExpansion)
	}

	if aliases > limits.MaxYAMLAliasExpansion*10 {
		return fmt.Errorf("potential YAML alias bomb detected: %d aliases exceeds limit", aliases)
	}

	return nil
}

func countAliasesWithGuard(node *yaml.Node, anchors, aliases *int, guard *limits.RecursionGuard) error {
	if node == nil {
		return nil
	}

	if err := guard.Enter(); err != nil {
		return err
	}
	defer guard.Leave()

	if node.Anchor != "" {
		*anchors++
	}
	if node.Kind == yaml.AliasNode {
		*aliases++
	}

	for _, child := range node.Content {
		if err := countAliasesWithGuard(child, anchors, aliases, guard); err != nil {
			return err
		}
	}
	return nil
}
