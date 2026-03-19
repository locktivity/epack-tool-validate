// Package raw provides overlay application logic.
package raw

import (
	"fmt"
)

// ApplyOverlays applies overlays in order to produce a canonical merged profile.
// Uses last-write-wins semantics for modifications.
func ApplyOverlays(base *RawProfile, overlays []*RawOverlay) (*RawProfile, error) {
	if base == nil {
		return nil, fmt.Errorf("base profile is nil")
	}

	// Make a copy to avoid mutating the original
	result := copyProfile(base)

	for i, overlay := range overlays {
		if overlay == nil {
			continue
		}

		// Build index of current requirement IDs for validation
		reqIndex := buildRequirementIndex(result.Requirements)

		// Process skip directives
		for _, skipID := range overlay.Skip {
			if _, exists := reqIndex[skipID]; !exists {
				return nil, fmt.Errorf("overlay[%d]: skip target %q not found in profile", i, skipID)
			}
			delete(reqIndex, skipID)
		}

		// Process modify directives
		for _, mod := range overlay.Modify {
			idx, exists := reqIndex[mod.ID]
			if !exists {
				return nil, fmt.Errorf("overlay[%d]: modify target %q not found in profile", i, mod.ID)
			}
			applyModification(&result.Requirements[idx], &mod, overlay.SourceFile)
		}

		// Process add directives
		for _, add := range overlay.Add {
			if _, exists := reqIndex[add.ID]; exists {
				return nil, fmt.Errorf("overlay[%d]: add would overwrite existing requirement %q", i, add.ID)
			}
			result.Requirements = append(result.Requirements, add)
			reqIndex[add.ID] = len(result.Requirements) - 1
		}

		// Remove skipped requirements
		result.Requirements = filterSkipped(result.Requirements, overlay.Skip)
	}

	return result, nil
}

func copyProfile(p *RawProfile) *RawProfile {
	result := &RawProfile{
		ID:          p.ID,
		Name:        p.Name,
		Version:     p.Version,
		Description: p.Description,
	}
	result.Requirements = make([]RawRequirement, len(p.Requirements))
	copy(result.Requirements, p.Requirements)
	return result
}

func buildRequirementIndex(reqs []RawRequirement) map[string]int {
	index := make(map[string]int, len(reqs))
	for i, req := range reqs {
		index[req.ID] = i
	}
	return index
}

// applyModification replaces the entire requirement with the modification.
// The ID is preserved (used for lookup), all other fields come from the modification.
// This is a full replacement, not a patch - unspecified fields will be empty/zero.
// sourceFile is the overlay that introduced this modification (for error attribution).
func applyModification(target *RawRequirement, mod *RawModify, sourceFile string) {
	// ID stays the same (it's the lookup key)
	target.Control = mod.Control
	target.Name = mod.Name
	target.Category = mod.Category
	target.SourceFile = sourceFile // Track that this requirement came from an overlay
	if mod.SatisfiedBy != nil {
		target.SatisfiedBy = *mod.SatisfiedBy
	} else {
		target.SatisfiedBy = RawSatisfiedBy{} // Clear if not specified
	}
}

func filterSkipped(reqs []RawRequirement, skipIDs []string) []RawRequirement {
	if len(skipIDs) == 0 {
		return reqs
	}

	skipSet := make(map[string]bool, len(skipIDs))
	for _, id := range skipIDs {
		skipSet[id] = true
	}

	result := make([]RawRequirement, 0, len(reqs))
	for _, req := range reqs {
		if !skipSet[req.ID] {
			result = append(result, req)
		}
	}
	return result
}
