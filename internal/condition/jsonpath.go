// Package condition provides JSONPath parsing and evaluation utilities.
package condition

import (
	"fmt"

	"github.com/ohler55/ojg/jp"
)

// ParseJSONPath parses a JSONPath expression and validates it returns single values.
// For multi-value paths, use ParseJSONPathMulti instead.
func ParseJSONPath(path string) (jp.Expr, error) {
	expr, err := jp.ParseString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid JSONPath %q: %w", path, err)
	}

	if ContainsMultiValueOperator(expr) {
		return nil, fmt.Errorf("JSONPath %q may return multiple values; use single-valued paths or specify cardinality", path)
	}

	return expr, nil
}

// ParseJSONPathMulti parses a JSONPath expression that may return multiple values.
// Returns the expression and whether it contains multi-value operators.
func ParseJSONPathMulti(path string) (jp.Expr, bool, error) {
	expr, err := jp.ParseString(path)
	if err != nil {
		return nil, false, fmt.Errorf("invalid JSONPath %q: %w", path, err)
	}

	isMulti := ContainsMultiValueOperator(expr)
	return expr, isMulti, nil
}

// ContainsMultiValueOperator checks if a JSONPath expression contains operators
// that can return multiple values.
func ContainsMultiValueOperator(expr jp.Expr) bool {
	for _, frag := range expr {
		switch frag.(type) {
		case jp.Wildcard:
			return true
		case jp.Descent:
			return true
		case jp.Slice:
			return true
		case jp.Filter:
			return true
		}
	}
	return false
}

// EvaluateJSONPath evaluates a pre-parsed expression against a value.
// Returns the single value or an error if the path doesn't match or returns multiple values.
func EvaluateJSONPath(expr jp.Expr, value any) (any, error) {
	results := expr.Get(value)

	if len(results) == 0 {
		return nil, nil // Path not found - return nil
	}

	if len(results) > 1 {
		// Should never happen if ParseJSONPath validated correctly, but defensive
		return nil, fmt.Errorf("JSONPath returned %d values, expected 1", len(results))
	}

	return results[0], nil
}

// EvaluateJSONPathMulti evaluates a pre-parsed expression and returns all matching values.
// Returns nil slice if path not found.
func EvaluateJSONPathMulti(expr jp.Expr, value any) []any {
	return expr.Get(value)
}

// ExtractBasePath extracts the array path that a wildcard operates on.
// For $.accounts[*].mfa_enabled, returns $.accounts (the array itself).
// For $.data.accounts[*].iam.field, returns $.data.accounts.
// Returns nil if no wildcard found or if the path uses recursive descent.
func ExtractBasePath(expr jp.Expr) jp.Expr {
	// Find the last Wildcard (we don't support Descent for this)
	lastWildcardIdx := -1
	for i, frag := range expr {
		switch frag.(type) {
		case jp.Wildcard:
			lastWildcardIdx = i
		case jp.Descent:
			// Recursive descent has no single base array - can't extract
			return nil
		}
	}

	if lastWildcardIdx < 0 {
		return nil // No wildcard found
	}

	// Return path up to (but not including) the wildcard
	// This gives us the array path
	basePath := make(jp.Expr, lastWildcardIdx)
	copy(basePath, expr[:lastWildcardIdx])
	return basePath
}

// GetArrayLength evaluates a base path and returns the length of the array at that path.
// Returns -1 if the path doesn't exist or doesn't point to an array.
func GetArrayLength(basePath jp.Expr, value any) int {
	if basePath == nil {
		return -1
	}

	results := basePath.Get(value)
	if len(results) != 1 {
		return -1 // Path should return exactly one value (the array)
	}

	// Check if it's a slice/array
	switch arr := results[0].(type) {
	case []any:
		return len(arr)
	case []map[string]any:
		return len(arr)
	default:
		return -1
	}
}
