// Package mapping reads control mapping artifacts
// (evidencepack/control-mapping@v1) and reports their entries as asserted
// support beside the validator's computed findings. Mappings are publisher
// assertions: nothing in this package affects any requirement outcome or the
// overall validation status.
package mapping

import (
	"encoding/json"
	"fmt"
)

// Artifact schemas this package consumes.
const (
	// Schema identifies a control mapping artifact.
	Schema = "evidencepack/control-mapping@v1"

	// DocumentIndexSchema identifies the document index artifact through
	// which document_id references resolve.
	DocumentIndexSchema = "evidencepack/document-index@v1"
)

// Resolution states for a mapping entry's evidence reference.
const (
	ResolutionResolved     = "resolved"      // Target (and anchor, where an extraction exists) found
	ResolutionDocumentOnly = "document_only" // Document found, anchor's extraction absent
	ResolutionUnresolved   = "unresolved"    // Target or anchor not found in the pack
)

// Warning codes emitted while processing mappings. All are warnings, never
// errors: a broken mapping cannot fail a pack.
const (
	CodeInvalidMappingEntry    = "INVALID_MAPPING_ENTRY"
	CodeMappingUnresolved      = "MAPPING_UNRESOLVED"
	CodeMappingProfileMismatch = "MAPPING_PROFILE_MISMATCH"
	CodeManualUnsupported      = "MANUAL_UNSUPPORTED"
)

// Document mirrors the JSON structure of a control mapping artifact.
// Unknown fields are accepted and ignored at every level.
type Document struct {
	SchemaVersion string     `json:"schema_version"`
	CapturedAt    string     `json:"captured_at"`
	Profile       ProfileRef `json:"profile"`
	Mappings      []Entry    `json:"mappings"`
}

// ProfileRef names the profile a mapping document asserts against.
type ProfileRef struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// Entry is one mapping from a requirement to a piece of evidence.
type Entry struct {
	Requirement string    `json:"requirement"`
	Control     string    `json:"control"`
	Type        string    `json:"type"`
	Evidence    *Evidence `json:"evidence"`
	Label       string    `json:"label"`
	Note        string    `json:"note"`
	MappedAt    string    `json:"mapped_at"`
	MappedBy    string    `json:"mapped_by"`
}

// Evidence is an entry's evidence reference: exactly one of Artifact or
// DocumentID, with optional anchors.
type Evidence struct {
	Artifact     string        `json:"artifact"`
	Pointer      string        `json:"pointer"`
	DocumentID   string        `json:"document_id"`
	Quote        *Quote        `json:"quote"`
	TextPosition *TextPosition `json:"text_position"`
	Table        *Table        `json:"table"`
}

// Quote anchors an entry to a verbatim passage in a document's extracted text.
type Quote struct {
	Exact  string `json:"exact"`
	Prefix string `json:"prefix"`
	Suffix string `json:"suffix"`
}

// TextPosition is the byte-offset secondary anchor for a quote.
type TextPosition struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Table anchors an entry to rows of a document's tabular extraction.
type Table struct {
	Sheet   string         `json:"sheet"`
	Where   map[string]any `json:"where"`
	Columns []string       `json:"columns"`
	Range   string         `json:"range"`
}

// Parse decodes a control mapping artifact. Unknown fields are accepted.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid mapping JSON: %w", err)
	}
	return &doc, nil
}

// Validate checks the entry constraints from the control mapping schema.
// A violating entry is malformed: it is reported and skipped, never fatal.
func (e *Entry) Validate() error {
	joins := 0
	if e.Requirement != "" {
		joins++
	}
	if e.Control != "" {
		joins++
	}
	if e.Type != "" {
		joins++
	}
	if joins != 1 {
		return fmt.Errorf("must reference exactly one of requirement, control, or type")
	}

	if e.Evidence == nil {
		return fmt.Errorf("missing evidence reference")
	}
	ev := e.Evidence
	if (ev.Artifact == "") == (ev.DocumentID == "") {
		return fmt.Errorf("evidence must reference exactly one of artifact or document_id")
	}
	if ev.Pointer != "" && ev.Artifact == "" {
		return fmt.Errorf("pointer requires an artifact reference")
	}
	if (ev.Quote != nil || ev.Table != nil || ev.TextPosition != nil) && ev.DocumentID == "" {
		return fmt.Errorf("quote, table, and text_position require a document_id reference")
	}
	if ev.Quote != nil && ev.Table != nil {
		return fmt.Errorf("evidence cannot carry both quote and table")
	}
	if ev.TextPosition != nil && ev.Quote == nil {
		return fmt.Errorf("text_position requires a quote")
	}
	if ev.Quote != nil && ev.Quote.Exact == "" {
		return fmt.Errorf("quote missing exact passage")
	}
	if ev.TextPosition != nil && (ev.TextPosition.Start < 0 || ev.TextPosition.End < ev.TextPosition.Start) {
		return fmt.Errorf("text_position offsets are invalid")
	}
	if ev.Table != nil && len(ev.Table.Where) == 0 {
		return fmt.Errorf("table anchor missing where")
	}
	return nil
}
