package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack-tool-validate/internal/lint"
	"github.com/locktivity/epack-tool-validate/internal/resolution"
	"github.com/locktivity/epack/componentsdk"
)

// LintOutputFile is the lint report written on packless runs.
const LintOutputFile = "lint.json"

const lintUsage = "usage: validate [profile.yaml] [--overlay path]... [--schema type=path]..."

func runLint(ctx componentsdk.ToolContext, args []string) error {
	root, err := projectRoot()
	if err != nil {
		return err
	}
	opts, err := lintOptions(ctx.Config(), args)
	if err != nil {
		return err
	}
	opts.ProjectRoot = root

	report, err := lint.Run(opts)
	if err != nil {
		return err
	}
	report.WriteText(os.Stderr)

	for _, d := range report.Diagnostics {
		if d.Severity == lint.SeverityError {
			ctx.Error(d.Code, d.Message, d.File)
		}
	}
	if report.Summary.Warnings > 0 {
		noun := "warnings"
		if report.Summary.Warnings == 1 {
			noun = "warning"
		}
		ctx.Warn("LINT_WARNINGS", fmt.Sprintf("profile lint found %d %s; see %s", report.Summary.Warnings, noun, LintOutputFile), report.Profile.Path)
	}
	return ctx.WriteOutput(LintOutputFile, report)
}

// lintOptions reads the profile, overlays and schemas from tool config,
// letting command-line arguments replace each one.
func lintOptions(config map[string]any, args []string) (lint.Options, error) {
	toolCfg := resolution.ParseToolConfig(config)
	opts := lint.Options{OverlayPaths: toolCfg.Overlays, SchemaPaths: schemaPaths(config)}

	var profiles, overlays []string
	schemas := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--overlay" || arg == "--schema":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("%s needs a value\n%s", arg, lintUsage)
			}
			i++
			if arg == "--overlay" {
				overlays = append(overlays, args[i])
				continue
			}
			typ, path, ok := strings.Cut(args[i], "=")
			if !ok || typ == "" || path == "" {
				return opts, fmt.Errorf("--schema takes type=path, got %q\n%s", args[i], lintUsage)
			}
			schemas[typ] = path
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown argument %q\n%s", arg, lintUsage)
		default:
			profiles = append(profiles, arg)
		}
	}

	if len(profiles) == 0 {
		profiles = toolCfg.Profiles
	}
	switch len(profiles) {
	case 0:
		return opts, fmt.Errorf("no profile to lint: pass a profile path or set profile in the tool config\n%s", lintUsage)
	case 1:
		opts.ProfilePath = profiles[0]
	default:
		return opts, fmt.Errorf("lint checks one profile at a time, got %d", len(profiles))
	}
	if len(overlays) > 0 {
		opts.OverlayPaths = overlays
	}
	for typ, path := range schemas {
		if opts.SchemaPaths == nil {
			opts.SchemaPaths = map[string]string{}
		}
		opts.SchemaPaths[typ] = path
	}
	return opts, nil
}

func schemaPaths(config map[string]any) map[string]string {
	raw, ok := config["schemas"].(map[string]any)
	if !ok {
		return nil
	}
	paths := map[string]string{}
	for typ, path := range raw {
		if s, ok := path.(string); ok {
			paths[typ] = s
		}
	}
	return paths
}
