package lint

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/locktivity/epack-tool-validate/internal/evidenceschema"
)

// Severities. An error means the profile will not evaluate as written; a
// warning means it will, but probably not the way its author intended.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Report is the lint output, written as lint.json.
type Report struct {
	Status      string            `json:"status"` // "pass" | "fail"
	Profile     ProfileInfo       `json:"profile"`
	Overlays    []string          `json:"overlays,omitempty"`
	Schemas     map[string]string `json:"schemas"` // artifact type to where its schema came from
	Summary     Summary           `json:"summary"`
	Diagnostics []Diagnostic      `json:"diagnostics"`
}

// ProfileInfo identifies the linted profile.
type ProfileInfo struct {
	Path    string `json:"path"`
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// Summary counts findings by severity.
type Summary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

// Diagnostic is one finding. Location is relative to the requirement, in
// the profile's own YAML keys, such as any_of[0].metadata_conditions.all[1].
type Diagnostic struct {
	Severity    string   `json:"severity"`
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	File        string   `json:"file,omitempty"`
	Requirement string   `json:"requirement,omitempty"`
	Location    string   `json:"location,omitempty"`
	Path        string   `json:"path,omitempty"`
	Type        string   `json:"type,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`

	order int // requirement position in the merged profile, -1 for profile-level findings
}

func newReport(opts Options) *Report {
	r := &Report{
		Profile:     ProfileInfo{Path: opts.ProfilePath},
		Overlays:    opts.OverlayPaths,
		Schemas:     map[string]string{},
		Diagnostics: []Diagnostic{},
	}
	if registry, err := evidenceschema.Bundled(); err == nil {
		for _, typ := range registry.Types() {
			r.Schemas[typ] = evidenceschema.SourceBundled
		}
	}
	for typ, path := range opts.SchemaPaths {
		r.Schemas[typ] = path
	}
	return r
}

func (r *Report) add(d Diagnostic) {
	r.Diagnostics = append(r.Diagnostics, d)
}

func (r *Report) finish() *Report {
	r.Summary = Summary{}
	for _, d := range r.Diagnostics {
		if d.Severity == SeverityError {
			r.Summary.Errors++
		} else {
			r.Summary.Warnings++
		}
	}
	r.Status = "pass"
	if r.Summary.Errors > 0 {
		r.Status = "fail"
	}
	sort.SliceStable(r.Diagnostics, func(i, j int) bool {
		a, b := r.Diagnostics[i], r.Diagnostics[j]
		if (a.Severity == SeverityError) != (b.Severity == SeverityError) {
			return a.Severity == SeverityError
		}
		return a.order < b.order
	})
	return r
}

// WriteText renders the report for a terminal or an agent reading stderr.
func (r *Report) WriteText(w io.Writer) {
	name := r.Profile.Path
	if r.Profile.ID != "" {
		name = fmt.Sprintf("%s (%s %s)", r.Profile.Path, r.Profile.ID, r.Profile.Version)
	}
	_, _ = fmt.Fprintf(w, "lint %s: %s\n", name, r.countLine())

	for _, d := range r.Diagnostics {
		_, _ = fmt.Fprintf(w, "\n%-7s %s", d.Severity, d.Code)
		if where := d.where(); where != "" {
			_, _ = fmt.Fprintf(w, "  %s", where)
		}
		_, _ = fmt.Fprintf(w, "\n        %s\n", d.Message)
		if d.Path != "" && d.Code != CodeUnknownPath {
			_, _ = fmt.Fprintf(w, "        path: %s\n", d.Path)
		}
		if len(d.Suggestions) > 0 {
			_, _ = fmt.Fprintf(w, "        did you mean: %s\n", strings.Join(d.Suggestions, ", "))
		}
	}
}

func (r *Report) countLine() string {
	if r.Summary.Errors == 0 && r.Summary.Warnings == 0 {
		return "no problems found"
	}
	return fmt.Sprintf("%s, %s", plural(r.Summary.Errors, "error"), plural(r.Summary.Warnings, "warning"))
}

func (d Diagnostic) where() string {
	var parts []string
	if d.Requirement != "" {
		parts = append(parts, d.Requirement)
	}
	if d.Location != "" {
		parts = append(parts, d.Location)
	}
	return strings.Join(parts, " ")
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
