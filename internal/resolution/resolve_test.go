package resolution

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/packspec"
)

func TestParseToolConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		tc := ParseToolConfig(nil)
		if len(tc.Profiles) != 0 {
			t.Errorf("Profiles = %v, want empty", tc.Profiles)
		}
		if len(tc.Overlays) != 0 {
			t.Errorf("Overlays = %v, want empty", tc.Overlays)
		}
	})

	t.Run("profiles array", func(t *testing.T) {
		cfg := map[string]any{
			"profiles": []any{"profiles/test.yaml", "profiles/other.yaml"},
		}
		tc := ParseToolConfig(cfg)
		if len(tc.Profiles) != 2 {
			t.Errorf("Profiles count = %d, want 2", len(tc.Profiles))
		}
		if tc.Profiles[0] != "profiles/test.yaml" {
			t.Errorf("Profiles[0] = %q, want %q", tc.Profiles[0], "profiles/test.yaml")
		}
	})

	t.Run("singular profile", func(t *testing.T) {
		cfg := map[string]any{
			"profile": "profiles/single.yaml",
		}
		tc := ParseToolConfig(cfg)
		if len(tc.Profiles) != 1 {
			t.Errorf("Profiles count = %d, want 1", len(tc.Profiles))
		}
		if tc.Profiles[0] != "profiles/single.yaml" {
			t.Errorf("Profiles[0] = %q, want %q", tc.Profiles[0], "profiles/single.yaml")
		}
	})

	t.Run("profiles takes precedence over profile", func(t *testing.T) {
		cfg := map[string]any{
			"profiles": []any{"profiles/list.yaml"},
			"profile":  "profiles/single.yaml",
		}
		tc := ParseToolConfig(cfg)
		if len(tc.Profiles) != 1 {
			t.Errorf("Profiles count = %d, want 1", len(tc.Profiles))
		}
		if tc.Profiles[0] != "profiles/list.yaml" {
			t.Errorf("Profiles[0] = %q, want %q (profiles takes precedence)", tc.Profiles[0], "profiles/list.yaml")
		}
	})

	t.Run("overlays", func(t *testing.T) {
		cfg := map[string]any{
			"profiles": []any{"profiles/test.yaml"},
			"overlays": []any{"overlays/a.yaml", "overlays/b.yaml"},
		}
		tc := ParseToolConfig(cfg)
		if len(tc.Overlays) != 2 {
			t.Errorf("Overlays count = %d, want 2", len(tc.Overlays))
		}
		if tc.Overlays[0] != "overlays/a.yaml" {
			t.Errorf("Overlays[0] = %q, want %q", tc.Overlays[0], "overlays/a.yaml")
		}
	})

	t.Run("non-string values ignored", func(t *testing.T) {
		cfg := map[string]any{
			"profiles": []any{"valid.yaml", 123, nil, "another.yaml"},
		}
		tc := ParseToolConfig(cfg)
		if len(tc.Profiles) != 2 {
			t.Errorf("Profiles count = %d, want 2 (non-strings filtered)", len(tc.Profiles))
		}
	})
}

func TestResolve(t *testing.T) {
	t.Run("single profile", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/test.yaml"},
		}
		plan, err := Resolve(tc, nil)
		if err != nil {
			t.Errorf("Resolve() unexpected error: %v", err)
		}
		if plan.ProfilePath != "profiles/test.yaml" {
			t.Errorf("ProfilePath = %q, want %q", plan.ProfilePath, "profiles/test.yaml")
		}
		if plan.Reason != "from tool config" {
			t.Errorf("Reason = %q, want %q", plan.Reason, "from tool config")
		}
	})

	t.Run("with overlays", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/test.yaml"},
			Overlays: []string{"overlays/a.yaml", "overlays/b.yaml"},
		}
		plan, err := Resolve(tc, nil)
		if err != nil {
			t.Errorf("Resolve() unexpected error: %v", err)
		}
		if len(plan.OverlayPaths) != 2 {
			t.Errorf("OverlayPaths count = %d, want 2", len(plan.OverlayPaths))
		}
	})

	t.Run("no profiles configured", func(t *testing.T) {
		tc := ToolConfig{}
		_, err := Resolve(tc, nil)
		if err == nil {
			t.Error("Resolve() should fail with no profiles")
		}
		if !strings.Contains(err.Error(), "no profiles") {
			t.Errorf("error should mention 'no profiles', got: %v", err)
		}
	})

	t.Run("multi-profile rejected for MVP", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/a.yaml", "profiles/b.yaml"},
		}
		_, err := Resolve(tc, nil)
		if err == nil {
			t.Error("Resolve() should reject multi-profile for MVP")
		}
		if !strings.Contains(err.Error(), "multi-profile") {
			t.Errorf("error should mention 'multi-profile', got: %v", err)
		}
	})

	t.Run("digest check from manifest", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/test.yaml"},
		}
		manifest := &packspec.Manifest{
			Profiles: []packspec.ProfileRef{
				{
					Source: "profiles/test.yaml",
					Digest: "sha256:abc123",
				},
			},
		}

		plan, err := Resolve(tc, manifest)
		if err != nil {
			t.Errorf("Resolve() unexpected error: %v", err)
		}
		if plan.DigestCheck == nil {
			t.Fatal("DigestCheck should not be nil")
		}
		if plan.DigestCheck.ExpectedDigest != "sha256:abc123" {
			t.Errorf("ExpectedDigest = %q, want %q", plan.DigestCheck.ExpectedDigest, "sha256:abc123")
		}
		if plan.DigestCheck.Source != "profiles/test.yaml" {
			t.Errorf("Source = %q, want %q", plan.DigestCheck.Source, "profiles/test.yaml")
		}
	})

	t.Run("no digest check when manifest has no digest", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/test.yaml"},
		}
		manifest := &packspec.Manifest{
			Profiles: []packspec.ProfileRef{
				{
					Source: "profiles/test.yaml",
					Digest: "", // No digest
				},
			},
		}

		plan, err := Resolve(tc, manifest)
		if err != nil {
			t.Errorf("Resolve() unexpected error: %v", err)
		}
		if plan.DigestCheck != nil {
			t.Error("DigestCheck should be nil when manifest has no digest")
		}
	})

	t.Run("multi-profile manifest rejected for MVP", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/test.yaml"},
		}
		manifest := &packspec.Manifest{
			Profiles: []packspec.ProfileRef{
				{Source: "profiles/a.yaml", Digest: "sha256:abc"},
				{Source: "profiles/b.yaml", Digest: "sha256:def"},
			},
		}

		_, err := Resolve(tc, manifest)
		if err == nil {
			t.Error("Resolve() should reject multi-profile manifest for MVP")
		}
		if !strings.Contains(err.Error(), "multi-profile") {
			t.Errorf("error should mention 'multi-profile', got: %v", err)
		}
	})

	t.Run("nil manifest is allowed", func(t *testing.T) {
		tc := ToolConfig{
			Profiles: []string{"profiles/test.yaml"},
		}
		plan, err := Resolve(tc, nil)
		if err != nil {
			t.Errorf("Resolve() unexpected error: %v", err)
		}
		if plan.DigestCheck != nil {
			t.Error("DigestCheck should be nil with nil manifest")
		}
	})
}

func TestPlan_Fields(t *testing.T) {
	tc := ToolConfig{
		Profiles: []string{"profiles/test.yaml"},
		Overlays: []string{"overlays/a.yaml"},
	}
	plan, err := Resolve(tc, nil)
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if plan.ProfilePath == "" {
		t.Error("ProfilePath should not be empty")
	}
	if len(plan.OverlayPaths) != 1 {
		t.Error("OverlayPaths should have 1 item")
	}
	if plan.Reason == "" {
		t.Error("Reason should not be empty")
	}
}
