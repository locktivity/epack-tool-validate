// Package condition provides operators and JSONPath utilities for validation.
package condition

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Operator represents a comparison operator.
type Operator int

const (
	OpInvalid    Operator = iota
	OpEq                  // equals
	OpNeq                 // not equals
	OpGt                  // greater than
	OpGte                 // greater than or equal
	OpLt                  // less than
	OpLte                 // less than or equal
	OpExists              // path exists (value is non-nil)
	OpNotExists           // path does not exist (value is nil)
	OpMaxAgeDays          // ISO date or RFC3339 timestamp is not older than N days
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
	case OpMaxAgeDays:
		return "max_age_days"
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
	case "max_age_days":
		return OpMaxAgeDays, nil
	default:
		return OpInvalid, fmt.Errorf("unknown operator: %q", s)
	}
}

// Apply evaluates the operator against actual and expected values.
// OpMaxAgeDays needs a clock and always returns false here; use ApplyAt.
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

// ApplyAt evaluates the operator against actual and expected values,
// using now as the clock for time-based operators.
func (op Operator) ApplyAt(actual, expected any, now time.Time) bool {
	if op == OpMaxAgeDays {
		return maxAgeDays(actual, expected, now)
	}
	return op.Apply(actual, expected)
}

func maxAgeDays(actual, expected any, now time.Time) bool {
	maxDays, ok := NormalizeNumeric(expected)
	if !ok || maxDays < 0 {
		return false
	}

	t, dateOnly, ok := parseTimeValue(actual)
	if !ok {
		return false
	}

	maxAge := time.Duration(maxDays) * 24 * time.Hour
	if dateOnly {
		// Date-only values carry no timezone; tolerate one day in the
		// future so a document dated "today" in a timezone ahead of UTC
		// does not fail until UTC catches up.
		age := utcDate(now).Sub(utcDate(t))
		return age >= -24*time.Hour && age <= maxAge
	}

	age := now.Sub(t)
	return age >= 0 && age <= maxAge
}

func parseTimeValue(value any) (time.Time, bool, bool) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, false, false
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return time.Time{}, false, false
	}

	if parsed, err := time.Parse("2006-01-02", text); err == nil {
		return parsed, true, true
	}

	if parsed, err := time.Parse(time.RFC3339, text); err == nil {
		return parsed, false, true
	}

	return time.Time{}, false, false
}

func utcDate(t time.Time) time.Time {
	year, month, day := t.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
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
