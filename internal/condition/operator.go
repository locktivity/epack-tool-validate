// Package condition provides operators and JSONPath utilities for validation.
package condition

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// Operator represents a comparison operator.
type Operator int

const (
	OpInvalid   Operator = iota
	OpEq                 // equals
	OpNeq                // not equals
	OpGt                 // greater than
	OpGte                // greater than or equal
	OpLt                 // less than
	OpLte                // less than or equal
	OpExists             // path exists (value is non-nil)
	OpNotExists          // path does not exist (value is nil)
)

func (op Operator) String() string {
	switch op {
	case OpEq:
		return "eq"
	case OpNeq:
		return "neq"
	case OpGt:
		return "gt"
	case OpGte:
		return "gte"
	case OpLt:
		return "lt"
	case OpLte:
		return "lte"
	case OpExists:
		return "exists"
	case OpNotExists:
		return "not_exists"
	default:
		return "invalid"
	}
}

// ParseOperator converts a string operator to the Operator enum.
func ParseOperator(s string) (Operator, error) {
	switch s {
	case "eq", "==", "equals":
		return OpEq, nil
	case "neq", "!=", "not_equals":
		return OpNeq, nil
	case "gt", ">":
		return OpGt, nil
	case "gte", ">=":
		return OpGte, nil
	case "lt", "<":
		return OpLt, nil
	case "lte", "<=":
		return OpLte, nil
	case "exists":
		return OpExists, nil
	case "not_exists":
		return OpNotExists, nil
	default:
		return OpInvalid, fmt.Errorf("unknown operator: %q", s)
	}
}

// Apply evaluates the operator against actual and expected values.
func (op Operator) Apply(actual, expected any) bool {
	switch op {
	case OpEq:
		return equalValues(actual, expected)
	case OpNeq:
		return !equalValues(actual, expected)
	case OpGt, OpGte, OpLt, OpLte:
		// Numeric operators require both operands to be numeric
		cmp, ok := compareNumeric(actual, expected)
		if !ok {
			return false // Non-numeric comparison fails
		}
		switch op {
		case OpGt:
			return cmp > 0
		case OpGte:
			return cmp >= 0
		case OpLt:
			return cmp < 0
		case OpLte:
			return cmp <= 0
		}
	case OpExists:
		return actual != nil
	case OpNotExists:
		return actual == nil
	}
	return false
}

// equalValues compares two values with type normalization.
func equalValues(actual, expected any) bool {
	// Normalize numerics for comparison
	if actualNum, aOK := NormalizeNumeric(actual); aOK {
		if expectedNum, eOK := NormalizeNumeric(expected); eOK {
			return actualNum == expectedNum
		}
	}
	// Fall back to DeepEqual for non-numerics
	return reflect.DeepEqual(actual, expected)
}

// compareNumeric compares two values numerically.
// Returns (-1, 0, or 1) and true if both values are numeric.
// Returns (0, false) if either value is not numeric.
func compareNumeric(actual, expected any) (int, bool) {
	actualNum, aOK := NormalizeNumeric(actual)
	expectedNum, eOK := NormalizeNumeric(expected)
	if !aOK || !eOK {
		return 0, false // Non-numeric comparison fails
	}

	if actualNum < expectedNum {
		return -1, true
	}
	if actualNum > expectedNum {
		return 1, true
	}
	return 0, true
}

// NormalizeNumeric converts any numeric type to float64 for comparison.
// Returns (value, true) if numeric, (0, false) if not numeric.
func NormalizeNumeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
