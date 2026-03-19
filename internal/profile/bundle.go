// Package profile provides profile loading and management.
package profile

import (
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/fileref"
	"github.com/locktivity/epack-tool-validate/internal/limits"
	"github.com/locktivity/epack-tool-validate/internal/profile/raw"
)

// Bundle holds all loaded profile data before compilation.
// This prevents main.go from juggling parallel slices.
type Bundle struct {
	BaseRef     *fileref.LocalFileRef // Profile file ref (path, data, digest)
	BaseProfile *raw.RawProfile       // Parsed profile

	OverlayRefs     []*fileref.LocalFileRef // Overlay file refs (in order)
	OverlayProfiles []*raw.RawOverlay       // Parsed overlays (parallel to refs)
}

// LoadBundle loads and parses a profile with its overlays.
// All file I/O uses LocalFileRef for consistent path/digest handling.
func LoadBundle(baseDir string, profilePath string, overlayPaths []string) (*Bundle, error) {
	// Load base profile
	baseRef, err := fileref.Load(baseDir, profilePath, limits.ProfileFile)
	if err != nil {
		return nil, fmt.Errorf("loading profile %s: %w", profilePath, err)
	}

	baseProfile, err := raw.ParseProfileFromBytes(baseRef.Data)
	if err != nil {
		return nil, fmt.Errorf("parsing profile %s: %w", profilePath, err)
	}
	baseProfile.SetSourceFile(profilePath)

	// Load overlays in order
	overlayRefs := make([]*fileref.LocalFileRef, len(overlayPaths))
	overlayProfiles := make([]*raw.RawOverlay, len(overlayPaths))

	for i, overlayPath := range overlayPaths {
		ref, err := fileref.Load(baseDir, overlayPath, limits.OverlayFile)
		if err != nil {
			return nil, fmt.Errorf("loading overlay %s: %w", overlayPath, err)
		}

		overlay, err := raw.ParseOverlayFromBytes(ref.Data)
		if err != nil {
			return nil, fmt.Errorf("parsing overlay %s: %w", overlayPath, err)
		}
		overlay.SetSourceFile(overlayPath)

		overlayRefs[i] = ref
		overlayProfiles[i] = overlay
	}

	return &Bundle{
		BaseRef:         baseRef,
		BaseProfile:     baseProfile,
		OverlayRefs:     overlayRefs,
		OverlayProfiles: overlayProfiles,
	}, nil
}

// Digest returns the base profile digest (for manifest verification).
func (b *Bundle) Digest() string {
	return b.BaseRef.Digest
}

// Merge applies overlays and returns the canonical raw profile.
func (b *Bundle) Merge() (*raw.RawProfile, error) {
	return raw.ApplyOverlays(b.BaseProfile, b.OverlayProfiles)
}

// ProfilePath returns the original config path of the base profile.
func (b *Bundle) ProfilePath() string {
	return b.BaseRef.Path
}
