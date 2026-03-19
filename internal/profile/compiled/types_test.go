package compiled

import (
	"testing"
)

func TestClauseMode_String(t *testing.T) {
	tests := []struct {
		mode ClauseMode
		want string
	}{
		{ClauseModeAny, "any_of"},
		{ClauseModeAll, "all_of"},
		{ClauseMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidSeverities(t *testing.T) {
	valid := []string{"", "critical", "high", "medium", "low"}
	invalid := []string{"warning", "error", "info", "CRITICAL", "HIGH"}

	for _, s := range valid {
		if !ValidSeverities[s] {
			t.Errorf("ValidSeverities[%q] = false, want true", s)
		}
	}

	for _, s := range invalid {
		if ValidSeverities[s] {
			t.Errorf("ValidSeverities[%q] = true, want false", s)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	// Verify severity ordering (higher index = more severe)
	if SeverityOrder[""] >= SeverityOrder["low"] {
		t.Error("empty severity should be less than low")
	}
	if SeverityOrder["low"] >= SeverityOrder["medium"] {
		t.Error("low should be less than medium")
	}
	if SeverityOrder["medium"] >= SeverityOrder["high"] {
		t.Error("medium should be less than high")
	}
	if SeverityOrder["high"] >= SeverityOrder["critical"] {
		t.Error("high should be less than critical")
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"", "", ""},
		{"", "low", "low"},
		{"low", "", "low"},
		{"low", "medium", "medium"},
		{"medium", "low", "medium"},
		{"high", "critical", "critical"},
		{"critical", "high", "critical"},
		{"critical", "critical", "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := MaxSeverity(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("MaxSeverity(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
