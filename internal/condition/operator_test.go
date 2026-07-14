package condition

import (
	"encoding/json"
	"testing"
	"time"
)

func TestOperator_String(t *testing.T) {
	tests := []struct {
		op   Operator
		want string
	}{
		{OpEq, "eq"},
		{OpNeq, "neq"},
		{OpGt, "gt"},
		{OpGte, "gte"},
		{OpLt, "lt"},
		{OpLte, "lte"},
		{OpExists, "exists"},
		{OpNotExists, "not_exists"},
		{OpMaxAgeDays, "max_age_days"},
		{OpInvalid, "invalid"},
		{Operator(99), "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.op.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseOperator(t *testing.T) {
	tests := []struct {
		input   string
		want    Operator
		wantErr bool
	}{
		// Standard names
		{"eq", OpEq, false},
		{"neq", OpNeq, false},
		{"gt", OpGt, false},
		{"gte", OpGte, false},
		{"lt", OpLt, false},
		{"lte", OpLte, false},
		{"exists", OpExists, false},
		{"not_exists", OpNotExists, false},
		{"max_age_days", OpMaxAgeDays, false},

		// Symbol aliases
		{"==", OpEq, false},
		{"!=", OpNeq, false},
		{">", OpGt, false},
		{">=", OpGte, false},
		{"<", OpLt, false},
		{"<=", OpLte, false},

		// Word aliases
		{"equals", OpEq, false},
		{"not_equals", OpNeq, false},

		// Invalid
		{"invalid", OpInvalid, true},
		{"", OpInvalid, true},
		{"EQ", OpInvalid, true}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseOperator(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOperator(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseOperator(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestOperator_Apply(t *testing.T) {
	t.Run("eq with identical values", func(t *testing.T) {
		if !OpEq.Apply(100, 100) {
			t.Error("eq(100, 100) should be true")
		}
		if !OpEq.Apply("test", "test") {
			t.Error("eq(test, test) should be true")
		}
		if !OpEq.Apply(true, true) {
			t.Error("eq(true, true) should be true")
		}
	})

	t.Run("eq with numeric type normalization", func(t *testing.T) {
		// JSON numbers come as float64, YAML may come as int
		if !OpEq.Apply(float64(100), int(100)) {
			t.Error("eq(float64(100), int(100)) should be true")
		}
		if !OpEq.Apply(int64(100), float64(100.0)) {
			t.Error("eq(int64(100), float64(100.0)) should be true")
		}
	})

	t.Run("eq with different values", func(t *testing.T) {
		if OpEq.Apply(100, 200) {
			t.Error("eq(100, 200) should be false")
		}
		if OpEq.Apply("a", "b") {
			t.Error("eq(a, b) should be false")
		}
	})

	t.Run("neq", func(t *testing.T) {
		if !OpNeq.Apply(100, 200) {
			t.Error("neq(100, 200) should be true")
		}
		if OpNeq.Apply(100, 100) {
			t.Error("neq(100, 100) should be false")
		}
	})

	t.Run("gt", func(t *testing.T) {
		if !OpGt.Apply(100, 50) {
			t.Error("gt(100, 50) should be true")
		}
		if OpGt.Apply(50, 100) {
			t.Error("gt(50, 100) should be false")
		}
		if OpGt.Apply(100, 100) {
			t.Error("gt(100, 100) should be false")
		}
	})

	t.Run("gte", func(t *testing.T) {
		if !OpGte.Apply(100, 50) {
			t.Error("gte(100, 50) should be true")
		}
		if !OpGte.Apply(100, 100) {
			t.Error("gte(100, 100) should be true")
		}
		if OpGte.Apply(50, 100) {
			t.Error("gte(50, 100) should be false")
		}
	})

	t.Run("lt", func(t *testing.T) {
		if !OpLt.Apply(50, 100) {
			t.Error("lt(50, 100) should be true")
		}
		if OpLt.Apply(100, 50) {
			t.Error("lt(100, 50) should be false")
		}
		if OpLt.Apply(100, 100) {
			t.Error("lt(100, 100) should be false")
		}
	})

	t.Run("lte", func(t *testing.T) {
		if !OpLte.Apply(50, 100) {
			t.Error("lte(50, 100) should be true")
		}
		if !OpLte.Apply(100, 100) {
			t.Error("lte(100, 100) should be true")
		}
		if OpLte.Apply(100, 50) {
			t.Error("lte(100, 50) should be false")
		}
	})

	t.Run("exists", func(t *testing.T) {
		if !OpExists.Apply("value", nil) {
			t.Error("exists(value) should be true")
		}
		if !OpExists.Apply(0, nil) {
			t.Error("exists(0) should be true (zero is not nil)")
		}
		if OpExists.Apply(nil, nil) {
			t.Error("exists(nil) should be false")
		}
	})

	t.Run("not_exists", func(t *testing.T) {
		if !OpNotExists.Apply(nil, nil) {
			t.Error("not_exists(nil) should be true")
		}
		if OpNotExists.Apply("value", nil) {
			t.Error("not_exists(value) should be false")
		}
	})

	t.Run("non-numeric comparison fails", func(t *testing.T) {
		// All numeric operators (gt, gte, lt, lte) return false for non-numeric values
		if OpGt.Apply("abc", "def") {
			t.Error("gt(abc, def) should be false for non-numeric")
		}
		if OpLt.Apply("abc", 100) {
			t.Error("lt(abc, 100) should be false for mixed types")
		}
		if OpGte.Apply("abc", "def") {
			t.Error("gte(abc, def) should be false for non-numeric")
		}
		if OpLte.Apply("unknown", 100) {
			t.Error("lte(unknown, 100) should be false for non-numeric")
		}
		// String that looks like a number but isn't parsed as one
		if OpGte.Apply("85", 80) {
			t.Error("gte(\"85\", 80) should be false - string is not numeric")
		}
	})

	t.Run("invalid operator", func(t *testing.T) {
		if OpInvalid.Apply(100, 100) {
			t.Error("invalid operator should return false")
		}
	})
}

func TestOperator_ApplyAt_MaxAgeDays(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		actual   any
		expected any
		want     bool
	}{
		{"date within limit", "2024-01-15", 365, true},
		{"date exactly at limit", "2023-06-16", 365, true},
		{"date one day past limit", "2023-06-15", 365, false},
		{"date today", "2024-06-15", 365, true},
		{"date one day in future (timezone tolerance)", "2024-06-16", 365, true},
		{"date two days in future", "2024-06-17", 365, false},
		{"rfc3339 within limit", "2024-06-14T12:00:00Z", 365, true},
		{"rfc3339 exactly at limit", "2023-06-16T12:00:00Z", 365, true},
		{"rfc3339 one second past limit", "2023-06-16T11:59:59Z", 365, false},
		{"rfc3339 in future fails (no tolerance)", "2024-06-15T12:00:01Z", 365, false},
		{"rfc3339 with offset", "2024-06-15T13:00:00+02:00", 365, true},
		{"whitespace around date", " 2024-01-15 ", 365, true},
		{"malformed date", "June 15, 2024", 365, false},
		{"empty string", "", 365, false},
		{"non-string actual", 20240115, 365, false},
		{"nil actual", nil, 365, false},
		{"zero days allows today only", "2024-06-15", 0, true},
		{"zero days rejects yesterday", "2024-06-14", 0, false},
		{"float days truncate", "2024-06-14", 1.9, true},
		{"nil expected", "2024-01-15", nil, false},
		{"string expected", "2024-01-15", "365", false},
		{"negative expected", "2024-01-15", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OpMaxAgeDays.ApplyAt(tt.actual, tt.expected, now); got != tt.want {
				t.Errorf("ApplyAt(%v, %v) = %v, want %v", tt.actual, tt.expected, got, tt.want)
			}
		})
	}

	t.Run("Apply without clock returns false", func(t *testing.T) {
		if OpMaxAgeDays.Apply("2024-06-15", 365) {
			t.Error("Apply(max_age_days) should be false; it has no clock")
		}
	})

	t.Run("ApplyAt delegates non-time operators to Apply", func(t *testing.T) {
		if !OpEq.ApplyAt(100, 100, now) {
			t.Error("ApplyAt should delegate eq to Apply")
		}
		if OpGt.ApplyAt(50, 100, now) {
			t.Error("ApplyAt should delegate gt to Apply")
		}
	})
}

func TestNormalizeNumeric(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   float64
		wantOK bool
	}{
		{"float64", float64(100.5), 100.5, true},
		{"float32", float32(100.5), float64(float32(100.5)), true},
		{"int", int(100), 100.0, true},
		{"int8", int8(100), 100.0, true},
		{"int16", int16(100), 100.0, true},
		{"int32", int32(100), 100.0, true},
		{"int64", int64(100), 100.0, true},
		{"uint", uint(100), 100.0, true},
		{"uint8", uint8(100), 100.0, true},
		{"uint16", uint16(100), 100.0, true},
		{"uint32", uint32(100), 100.0, true},
		{"uint64", uint64(100), 100.0, true},
		{"json.Number", json.Number("100.5"), 100.5, true},
		{"string", "100", 0, false},
		{"bool", true, 0, false},
		{"nil", nil, 0, false},
		{"slice", []int{1, 2, 3}, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeNumeric(tt.input)
			if ok != tt.wantOK {
				t.Errorf("NormalizeNumeric() ok = %v, wantOK %v", ok, tt.wantOK)
				return
			}
			if ok && got != tt.want {
				t.Errorf("NormalizeNumeric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOperator_Apply_NumericEdgeCases(t *testing.T) {
	t.Run("negative numbers", func(t *testing.T) {
		if !OpGt.Apply(0, -100) {
			t.Error("0 > -100 should be true")
		}
		if !OpLt.Apply(-100, 0) {
			t.Error("-100 < 0 should be true")
		}
	})

	t.Run("floating point", func(t *testing.T) {
		if !OpGt.Apply(100.1, 100.0) {
			t.Error("100.1 > 100.0 should be true")
		}
		if !OpEq.Apply(100.0, 100.0) {
			t.Error("100.0 == 100.0 should be true")
		}
	})

	t.Run("mixed int and float", func(t *testing.T) {
		if !OpGte.Apply(int(100), float64(99.9)) {
			t.Error("int(100) >= float64(99.9) should be true")
		}
	})
}
