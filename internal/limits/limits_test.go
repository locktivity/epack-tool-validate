package limits

import (
	"testing"
)

func TestSizeLimit_Bytes(t *testing.T) {
	tests := []struct {
		name  string
		limit SizeLimit
		want  int64
	}{
		{"ProfileFile", ProfileFile, 1024 * 1024},
		{"OverlayFile", OverlayFile, 1024 * 1024},
		{"Custom", SizeLimit(500), 500},
		{"Zero", SizeLimit(0), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.limit.Bytes(); got != tt.want {
				t.Errorf("SizeLimit.Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecursionGuard_Enter(t *testing.T) {
	t.Run("below limit", func(t *testing.T) {
		g := NewRecursionGuard(3)

		// Should allow 3 levels
		for i := 0; i < 3; i++ {
			if err := g.Enter(); err != nil {
				t.Errorf("Enter() at depth %d returned error: %v", i, err)
			}
		}

		// 4th should fail
		err := g.Enter()
		if err == nil {
			t.Error("Enter() should have returned error at max depth")
		}

		// Verify error type
		if _, ok := err.(*ErrRecursionLimitExceeded); !ok {
			t.Errorf("Enter() error type = %T, want *ErrRecursionLimitExceeded", err)
		}
	})

	t.Run("zero max depth", func(t *testing.T) {
		g := NewRecursionGuard(0)
		err := g.Enter()
		if err == nil {
			t.Error("Enter() with max depth 0 should return error")
		}
	})
}

func TestRecursionGuard_Leave(t *testing.T) {
	t.Run("decrement depth", func(t *testing.T) {
		g := NewRecursionGuard(5)

		// Enter 3 times
		for i := 0; i < 3; i++ {
			_ = g.Enter()
		}

		// Leave 3 times
		for i := 0; i < 3; i++ {
			g.Leave()
		}

		// Should be able to enter 5 more times now (back to 0)
		for i := 0; i < 5; i++ {
			if err := g.Enter(); err != nil {
				t.Errorf("Enter() after Leave() at depth %d returned error: %v", i, err)
			}
		}
	})

	t.Run("leave at zero depth", func(t *testing.T) {
		g := NewRecursionGuard(5)
		// Should not panic when leaving at depth 0
		g.Leave()
		g.Leave() // Multiple leaves should be safe
	})
}

func TestErrRecursionLimitExceeded_Error(t *testing.T) {
	err := &ErrRecursionLimitExceeded{Depth: 101, MaxDepth: 100}
	if got := err.Error(); got != "recursion depth exceeded" {
		t.Errorf("Error() = %q, want %q", got, "recursion depth exceeded")
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values
	if MaxRecursionDepth != 100 {
		t.Errorf("MaxRecursionDepth = %d, want 100", MaxRecursionDepth)
	}
	if MaxYAMLAliasExpansion != 10 {
		t.Errorf("MaxYAMLAliasExpansion = %d, want 10", MaxYAMLAliasExpansion)
	}
	if StandardDirMode != 0755 {
		t.Errorf("StandardDirMode = %o, want 0755", StandardDirMode)
	}
	if StandardFileMode != 0644 {
		t.Errorf("StandardFileMode = %o, want 0644", StandardFileMode)
	}
}
