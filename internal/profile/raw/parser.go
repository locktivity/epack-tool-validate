// Package raw provides YAML parsing for profile files.
package raw

import (
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/limits"
	"github.com/locktivity/epack-tool-validate/internal/safeyaml"
)

// ParseProfileFromBytes parses profile YAML from pre-read bytes.
// Caller is responsible for using fileref.Load() to get bounded, validated bytes.
func ParseProfileFromBytes(data []byte) (*RawProfile, error) {
	var profile RawProfile
	if err := safeyaml.UnmarshalStrict(data, limits.ProfileFile, &profile); err != nil {
		return nil, fmt.Errorf("invalid profile YAML: %w", err)
	}

	// Basic validation
	if profile.ID == "" {
		return nil, fmt.Errorf("profile missing required field: id")
	}
	if profile.Name == "" {
		return nil, fmt.Errorf("profile missing required field: name")
	}
	if len(profile.Requirements) == 0 {
		return nil, fmt.Errorf("profile has no requirements")
	}

	return &profile, nil
}

// ParseOverlayFromBytes parses overlay YAML from pre-read bytes.
func ParseOverlayFromBytes(data []byte) (*RawOverlay, error) {
	var overlay RawOverlay
	if err := safeyaml.UnmarshalStrict(data, limits.OverlayFile, &overlay); err != nil {
		return nil, fmt.Errorf("invalid overlay YAML: %w", err)
	}

	return &overlay, nil
}

// SetSourceFile sets the SourceFile field on all requirements in a profile.
// This is used to track where requirements came from for error attribution.
func (p *RawProfile) SetSourceFile(sourceFile string) {
	for i := range p.Requirements {
		p.Requirements[i].SourceFile = sourceFile
	}
}

// SetSourceFile sets the SourceFile field on the overlay and all its requirements.
// This is used to track where requirements came from for error attribution.
func (o *RawOverlay) SetSourceFile(sourceFile string) {
	o.SourceFile = sourceFile
	for i := range o.Add {
		o.Add[i].SourceFile = sourceFile
	}
}
