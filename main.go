// epack-tool-validate validates evidence packs against profile YAML files.
package main

import (
	"fmt"
	"os"

	"github.com/locktivity/epack-tool-validate/internal/profile"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/locktivity/epack-tool-validate/internal/resolution"
	"github.com/locktivity/epack-tool-validate/internal/validator"
	"github.com/locktivity/epack/componentsdk"
)

// Version is set by ldflags at build time.
var Version = "dev"

func main() {
	componentsdk.RunTool(componentsdk.ToolSpec{
		Name:         "validate",
		Version:      Version,
		Description:  "Validates evidence packs against compliance profiles",
		RequiresPack: true,
		Network:      false,
	}, run)
}

func run(ctx componentsdk.ToolContext) error {
	pack := ctx.Pack()
	manifest := pack.Manifest()

	// Parse tool config
	toolCfg := resolution.ParseToolConfig(ctx.Config())

	// Resolve which profile to use
	plan, err := resolution.Resolve(toolCfg, manifest)
	if err != nil {
		return fmt.Errorf("resolving profile: %w", err)
	}

	// Get project root for relative path resolution
	projectRoot := os.Getenv("EPACK_PROJECT_ROOT")
	if projectRoot == "" {
		// Fall back to current directory if not set
		projectRoot, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
	}

	// Load and parse profile bundle
	bundle, err := profile.LoadBundle(projectRoot, plan.ProfilePath, plan.OverlayPaths)
	if err != nil {
		return fmt.Errorf("loading profile: %w", err)
	}

	// Verify digest if required
	if plan.DigestCheck != nil {
		if bundle.Digest() != plan.DigestCheck.ExpectedDigest {
			return fmt.Errorf("profile digest mismatch: manifest=%s, actual=%s (source was %s)",
				plan.DigestCheck.ExpectedDigest, bundle.Digest(), plan.DigestCheck.Source)
		}
	}

	// Merge overlays
	merged, err := bundle.Merge()
	if err != nil {
		return fmt.Errorf("merging overlays: %w", err)
	}

	// Compile profile
	compiledProfile, err := compiled.Compile(merged, bundle.ProfilePath())
	if err != nil {
		return fmt.Errorf("compiling profile: %w", err)
	}

	// Build pack index
	packIndex, err := validator.BuildPackIndex(pack)
	if err != nil {
		return fmt.Errorf("indexing pack: %w", err)
	}

	// Run validation
	v := validator.New()
	validationCtx := validator.DefaultContext()
	result := v.Validate(validationCtx, compiledProfile, packIndex, bundle.Digest())

	// Write validation output
	return ctx.WriteOutput(OutputFile, result)
}

// Output file name
const OutputFile = "validation.json"
