package mapping

import (
	"fmt"

	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/locktivity/epack-tool-validate/internal/validator"
)

// Report is the outcome of processing a pack's control mappings against the
// validated profile.
type Report struct {
	// Support holds asserted support entries keyed by profile ID.
	Support map[string][]validator.AssertedSupportEntry
	// Warnings collects every mapping-related warning, in pack order.
	Warnings []validator.WarningResult
}

// Process reads the pack's control mapping artifacts, joins their entries to
// the profile's requirements, and resolves each entry's evidence reference.
// It runs even when the pack carries no mappings: manual requirements with no
// asserted support still warrant a MANUAL_UNSUPPORTED warning.
func Process(profile *compiled.CompiledProfile, profileDigest string, pack PackReader) *Report {
	report := &Report{}
	joiner := newJoiner(profile)
	docs := loadDocumentIndexes(pack)
	supported := make(map[string]bool)

	for _, artifact := range pack.Artifacts() {
		if artifact.Schema != Schema {
			continue
		}
		doc, err := readMappingArtifact(pack, artifact.Path)
		if err != nil {
			report.warn(CodeInvalidMappingEntry, err.Error(), artifact.Path)
			continue
		}

		// A mapping naming a different profile belongs to that profile's
		// validation, not this one.
		if doc.Profile.ID != "" && doc.Profile.ID != profile.ID {
			continue
		}

		stale := doc.Profile.Digest != "" && profileDigest != "" && doc.Profile.Digest != profileDigest
		if stale {
			report.warn(CodeMappingProfileMismatch,
				fmt.Sprintf("mapping asserts against profile digest %s, but %s was validated; entries are reported as stale",
					doc.Profile.Digest, profileDigest),
				artifact.Path)
		}

		for i := range doc.Mappings {
			entry := &doc.Mappings[i]
			if err := entry.Validate(); err != nil {
				report.warn(CodeInvalidMappingEntry, fmt.Sprintf("entry %d: %v", i, err), artifact.Path)
				continue
			}

			out := supportEntry(entry, artifact.Path, stale)
			if req := joiner.join(entry); req != nil {
				out.RequirementID = req.ID
				supported[req.ID] = true
			} else {
				report.warn(CodeMappingUnresolved,
					fmt.Sprintf("entry %d references %s not present in the profile", i, entry.claimedReference()),
					artifact.Path)
			}

			resolved := resolveEvidence(entry.Evidence, pack, docs)
			out.Resolution = resolved.State
			out.Value = resolved.Value
			if resolved.Detail != "" {
				report.warn(CodeMappingUnresolved, fmt.Sprintf("entry %d: %s", i, resolved.Detail), artifact.Path)
			}

			if report.Support == nil {
				report.Support = make(map[string][]validator.AssertedSupportEntry)
			}
			report.Support[profile.ID] = append(report.Support[profile.ID], out)
		}
	}

	for _, req := range profile.Requirements {
		if req.Manual && !supported[req.ID] {
			report.warn(CodeManualUnsupported,
				fmt.Sprintf("manual requirement %s has no asserted support", req.ID), "")
		}
	}

	return report
}

func (r *Report) warn(code, message, path string) {
	r.Warnings = append(r.Warnings, validator.WarningResult{Code: code, Message: message, Path: path})
}

func readMappingArtifact(pack PackReader, path string) (*Document, error) {
	data, err := pack.ReadArtifact(path)
	if err != nil {
		return nil, fmt.Errorf("mapping artifact could not be read: %v", err)
	}
	return Parse(data)
}

// claimedReference names the join field an entry carries, for warnings.
func (e *Entry) claimedReference() string {
	switch {
	case e.Requirement != "":
		return fmt.Sprintf("requirement %q", e.Requirement)
	case e.Control != "":
		return fmt.Sprintf("control %q", e.Control)
	default:
		return fmt.Sprintf("type %q", e.Type)
	}
}

// supportEntry echoes a mapping entry into the report shape.
func supportEntry(entry *Entry, source string, stale bool) validator.AssertedSupportEntry {
	out := validator.AssertedSupportEntry{
		Requirement: entry.Requirement,
		Control:     entry.Control,
		Type:        entry.Type,
		Label:       entry.Label,
		Note:        entry.Note,
		MappedAt:    entry.MappedAt,
		MappedBy:    entry.MappedBy,
		Stale:       stale,
		Source:      source,
	}

	ev := entry.Evidence
	echo := &validator.SupportEvidence{
		Artifact:   ev.Artifact,
		Pointer:    ev.Pointer,
		DocumentID: ev.DocumentID,
	}
	if ev.Quote != nil {
		echo.Quote = &validator.SupportQuote{Exact: ev.Quote.Exact, Prefix: ev.Quote.Prefix, Suffix: ev.Quote.Suffix}
	}
	if ev.TextPosition != nil {
		echo.TextPosition = &validator.SupportTextPosition{Start: ev.TextPosition.Start, End: ev.TextPosition.End}
	}
	if ev.Table != nil {
		echo.Table = &validator.SupportTable{Sheet: ev.Table.Sheet, Where: ev.Table.Where, Columns: ev.Table.Columns, Range: ev.Table.Range}
	}
	out.Evidence = echo
	return out
}

// joiner joins mapping entries to the profile's requirements.
type joiner struct {
	byID      map[string]*compiled.CompiledRequirement
	byControl map[string]*compiled.CompiledRequirement
	bySchema  map[string][]*compiled.CompiledRequirement
}

func newJoiner(profile *compiled.CompiledProfile) *joiner {
	j := &joiner{
		byID:      make(map[string]*compiled.CompiledRequirement),
		byControl: make(map[string]*compiled.CompiledRequirement),
		bySchema:  make(map[string][]*compiled.CompiledRequirement),
	}
	for i := range profile.Requirements {
		req := &profile.Requirements[i]
		if req.ID != "" {
			j.byID[req.ID] = req
		}
		// First requirement in profile order wins a shared control value.
		if req.Control != "" {
			if _, taken := j.byControl[req.Control]; !taken {
				j.byControl[req.Control] = req
			}
		}
		seen := make(map[string]bool)
		for _, clause := range req.Clauses {
			if seen[clause.Schema] {
				continue
			}
			seen[clause.Schema] = true
			j.bySchema[clause.Schema] = append(j.bySchema[clause.Schema], req)
		}
	}
	return j
}

// join returns the requirement an entry references, or nil when the
// reference matches nothing. A type reference joins only when exactly one
// requirement uses that schema; an ambiguous type matches nothing.
func (j *joiner) join(entry *Entry) *compiled.CompiledRequirement {
	switch {
	case entry.Requirement != "":
		return j.byID[entry.Requirement]
	case entry.Control != "":
		return j.byControl[entry.Control]
	default:
		if reqs := j.bySchema[entry.Type]; len(reqs) == 1 {
			return reqs[0]
		}
		return nil
	}
}
