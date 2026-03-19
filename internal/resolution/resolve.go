// Package resolution provides profile resolution from tool config.
package resolution

import (
	"fmt"

	"github.com/locktivity/epack/packspec"
)

// ToolConfig represents the tool configuration from epack.yaml.
type ToolConfig struct {
	Profiles []string // Profile paths from config
	Overlays []string // Overlay paths from config
}

// ParseToolConfig extracts resolution config from the tool config map.
func ParseToolConfig(cfg map[string]any) ToolConfig {
	var tc ToolConfig

	if cfg == nil {
		return tc
	}

	// Parse profiles
	if v, ok := cfg["profiles"].([]any); ok {
		for _, p := range v {
			if s, ok := p.(string); ok {
				tc.Profiles = append(tc.Profiles, s)
			}
		}
	}
	// Also support singular "profile"
	if v, ok := cfg["profile"].(string); ok && len(tc.Profiles) == 0 {
		tc.Profiles = []string{v}
	}

	// Parse overlays
	if v, ok := cfg["overlays"].([]any); ok {
		for _, o := range v {
			if s, ok := o.(string); ok {
				tc.Overlays = append(tc.Overlays, s)
			}
		}
	}

	return tc
}

// Resolve builds a resolution plan from tool config and manifest.
// MVP: single profile only, errors on multi-profile.
func Resolve(toolCfg ToolConfig, manifest *packspec.Manifest) (*Plan, error) {
	if len(toolCfg.Profiles) == 0 {
		return nil, fmt.Errorf("no profiles configured in tool config")
	}
	if len(toolCfg.Profiles) > 1 {
		return nil, fmt.Errorf("multi-profile support deferred to v2 (found %d profiles)", len(toolCfg.Profiles))
	}

	plan := &Plan{
		ProfilePath:  toolCfg.Profiles[0],
		OverlayPaths: toolCfg.Overlays,
		Reason:       "from tool config",
	}

	// Add digest check if manifest has single profile ref with digest
	if manifest != nil && len(manifest.Profiles) == 1 && manifest.Profiles[0].Digest != "" {
		plan.DigestCheck = &DigestCheck{
			ExpectedDigest: manifest.Profiles[0].Digest,
			Source:         manifest.Profiles[0].Source,
		}
	} else if manifest != nil && len(manifest.Profiles) > 1 {
		return nil, fmt.Errorf("multi-profile packs require explicit mapping (v2)")
	}

	return plan, nil
}
