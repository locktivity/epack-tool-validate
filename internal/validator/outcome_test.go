package validator

import (
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
)

func TestFailureKind_String(t *testing.T) {
	tests := []struct {
		kind FailureKind
		want string
	}{
		{FailureKindNone, "none"},
		{FailureKindNoMatch, "no_match"},
		{FailureKindFreshness, "freshness"},
		{FailureKindFreshnessMissing, "freshness_missing"},
		{FailureKindCondition, "condition"},
		{FailureKind(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClauseOutcome_Fields(t *testing.T) {
	origin := compiled.Origin{
		RequirementID: "REQ-001",
		ClauseIndex:   0,
		SourceFile:    "profiles/test.yaml",
	}

	t.Run("matched outcome", func(t *testing.T) {
		outcome := ClauseOutcome{
			Matched:      true,
			Severity:     "",
			ArtifactPath: "artifacts/test.json",
			FailureKind:  FailureKindNone,
			Origin:       origin,
		}

		if !outcome.Matched {
			t.Error("Matched should be true")
		}
		if outcome.Severity != "" {
			t.Errorf("Severity = %q, want empty", outcome.Severity)
		}
		if outcome.ArtifactPath != "artifacts/test.json" {
			t.Errorf("ArtifactPath = %q, want %q", outcome.ArtifactPath, "artifacts/test.json")
		}
		if outcome.FailureKind != FailureKindNone {
			t.Errorf("FailureKind = %v, want FailureKindNone", outcome.FailureKind)
		}
	})

	t.Run("matched with severity", func(t *testing.T) {
		outcome := ClauseOutcome{
			Matched:      true,
			Severity:     "medium",
			ArtifactPath: "artifacts/test.json",
			FailureKind:  FailureKindNone,
			Origin:       origin,
		}

		if !outcome.Matched {
			t.Error("Matched should be true")
		}
		if outcome.Severity != "medium" {
			t.Errorf("Severity = %q, want %q", outcome.Severity, "medium")
		}
	})

	t.Run("no match outcome", func(t *testing.T) {
		outcome := ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindNoMatch,
			FailureDetail: "no artifact with schema evidencepack/test@v1",
			Origin:        origin,
		}

		if outcome.Matched {
			t.Error("Matched should be false")
		}
		if outcome.FailureKind != FailureKindNoMatch {
			t.Errorf("FailureKind = %v, want FailureKindNoMatch", outcome.FailureKind)
		}
		if outcome.FailureDetail == "" {
			t.Error("FailureDetail should not be empty")
		}
	})

	t.Run("freshness failure", func(t *testing.T) {
		outcome := ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindFreshness,
			FailureDetail: "artifact too old",
			ArtifactPath:  "artifacts/old.json",
			Origin:        origin,
		}

		if outcome.Matched {
			t.Error("Matched should be false")
		}
		if outcome.FailureKind != FailureKindFreshness {
			t.Errorf("FailureKind = %v, want FailureKindFreshness", outcome.FailureKind)
		}
		if outcome.ArtifactPath == "" {
			t.Error("ArtifactPath should not be empty for freshness failure")
		}
	})

	t.Run("freshness missing failure", func(t *testing.T) {
		outcome := ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindFreshnessMissing,
			FailureDetail: "artifact missing collected_at timestamp",
			Origin:        origin,
		}

		if outcome.Matched {
			t.Error("Matched should be false")
		}
		if outcome.FailureKind != FailureKindFreshnessMissing {
			t.Errorf("FailureKind = %v, want FailureKindFreshnessMissing", outcome.FailureKind)
		}
	})

	t.Run("condition failure", func(t *testing.T) {
		outcome := ClauseOutcome{
			Matched:       false,
			FailureKind:   FailureKindCondition,
			FailureDetail: "expected >= 100, got 85",
			ArtifactPath:  "artifacts/test.json",
			Origin:        origin,
		}

		if outcome.Matched {
			t.Error("Matched should be false")
		}
		if outcome.FailureKind != FailureKindCondition {
			t.Errorf("FailureKind = %v, want FailureKindCondition", outcome.FailureKind)
		}
	})
}

func TestClauseOutcome_Origin(t *testing.T) {
	origin := compiled.Origin{
		RequirementID: "REQ-TEST",
		ClauseIndex:   2,
		SourceFile:    "profiles/custom.yaml",
	}

	outcome := ClauseOutcome{
		Matched: true,
		Origin:  origin,
	}

	if outcome.Origin.RequirementID != "REQ-TEST" {
		t.Errorf("Origin.RequirementID = %q, want %q", outcome.Origin.RequirementID, "REQ-TEST")
	}
	if outcome.Origin.ClauseIndex != 2 {
		t.Errorf("Origin.ClauseIndex = %d, want 2", outcome.Origin.ClauseIndex)
	}
	if outcome.Origin.SourceFile != "profiles/custom.yaml" {
		t.Errorf("Origin.SourceFile = %q, want %q", outcome.Origin.SourceFile, "profiles/custom.yaml")
	}
}
