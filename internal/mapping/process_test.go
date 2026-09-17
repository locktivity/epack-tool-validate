package mapping

import (
	"fmt"
	"strings"
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
	"github.com/locktivity/epack-tool-validate/internal/validator"
	"github.com/locktivity/epack/componentsdk"
)

type fakePack struct {
	artifacts []componentsdk.Artifact
	files     map[string][]byte
}

func (f *fakePack) Artifacts() []componentsdk.Artifact { return f.artifacts }

func (f *fakePack) HasArtifact(path string) bool {
	_, ok := f.files[path]
	return ok
}

func (f *fakePack) ReadArtifact(path string) ([]byte, error) {
	data, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", path)
	}
	return data, nil
}

func (f *fakePack) add(path, schema string, data []byte) {
	f.artifacts = append(f.artifacts, componentsdk.Artifact{Type: "embedded", Path: path, Schema: schema})
	if f.files == nil {
		f.files = make(map[string][]byte)
	}
	f.files[path] = data
}

func testProfile() *compiled.CompiledProfile {
	return &compiled.CompiledProfile{
		ID:   "acme/security-baseline@v1",
		Name: "Security Baseline",
		Requirements: []compiled.CompiledRequirement{
			{
				ID:      "REQ-001",
				Control: "CC6.1",
				Name:    "Access Control Policy",
				Clauses: []compiled.CompiledClause{{Schema: "evidencepack/idp-posture@v1"}},
			},
			{
				ID:      "REQ-002",
				Control: "CC7.1",
				Name:    "Vulnerability Management",
				Clauses: []compiled.CompiledClause{{Schema: "evidencepack/vuln-scan@v1"}},
			},
			{
				ID:      "REQ-003",
				Control: "PL-01",
				Name:    "Information Security Policy",
				Manual:  true,
			},
		},
	}
}

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func mappingJSON(body string) []byte {
	return []byte(`{
		"schema_version": "1.0.0",
		"captured_at": "2026-08-28T14:02:11Z",
		"profile": {"id": "acme/security-baseline@v1", "digest": "` + testDigest + `"},
		"mappings": [` + body + `]
	}`)
}

func supportFor(t *testing.T, report *Report) []validator.AssertedSupportEntry {
	t.Helper()
	entries, ok := report.Support["acme/security-baseline@v1"]
	if !ok {
		t.Fatalf("no asserted support for the profile; Support = %+v", report.Support)
	}
	return entries
}

func warningCodes(report *Report) []string {
	codes := make([]string, 0, len(report.Warnings))
	for _, w := range report.Warnings {
		codes = append(codes, w.Code)
	}
	return codes
}

func TestProcess_ResolvedArtifactPointer(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{"policy": {"mfa_coverage": 92}}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"requirement": "REQ-001",
		 "evidence": {"artifact": "artifacts/idp-posture.json", "pointer": "/policy/mfa_coverage"},
		 "label": "MFA coverage", "mapped_by": "dana@acme.com"}
	`))

	report := Process(testProfile(), testDigest, pack)

	entries := supportFor(t, report)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.RequirementID != "REQ-001" {
		t.Errorf("RequirementID = %q", entry.RequirementID)
	}
	if entry.Resolution != ResolutionResolved {
		t.Errorf("Resolution = %q", entry.Resolution)
	}
	if entry.Value != 92.0 {
		t.Errorf("Value = %v, want 92", entry.Value)
	}
	if entry.Stale {
		t.Error("matching digest should not be stale")
	}
	if entry.Source != "artifacts/control-mappings.json" {
		t.Errorf("Source = %q", entry.Source)
	}
	// REQ-003 is manual with no support: exactly one warning expected.
	if codes := warningCodes(report); len(codes) != 1 || codes[0] != CodeManualUnsupported {
		t.Errorf("warnings = %v, want only MANUAL_UNSUPPORTED for REQ-003", codes)
	}
}

func TestProcess_JoinByControlAndType(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"control": "CC7.1", "evidence": {"artifact": "artifacts/idp-posture.json"}},
		{"type": "evidencepack/vuln-scan@v1", "evidence": {"artifact": "artifacts/idp-posture.json"}}
	`))

	report := Process(testProfile(), testDigest, pack)

	entries := supportFor(t, report)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].RequirementID != "REQ-002" {
		t.Errorf("control join: RequirementID = %q, want REQ-002", entries[0].RequirementID)
	}
	if entries[1].RequirementID != "REQ-002" {
		t.Errorf("type join: RequirementID = %q, want REQ-002", entries[1].RequirementID)
	}
}

func TestProcess_UnmatchedJoinWarns(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"requirement": "REQ-999", "evidence": {"artifact": "artifacts/idp-posture.json"}}
	`))

	report := Process(testProfile(), testDigest, pack)

	entries := supportFor(t, report)
	if len(entries) != 1 {
		t.Fatalf("unmatched entry must still be reported; entries = %d", len(entries))
	}
	if entries[0].RequirementID != "" {
		t.Errorf("RequirementID = %q, want empty", entries[0].RequirementID)
	}
	if entries[0].Requirement != "REQ-999" {
		t.Errorf("claimed requirement should be echoed; got %q", entries[0].Requirement)
	}
	found := false
	for _, w := range report.Warnings {
		if w.Code == CodeMappingUnresolved && strings.Contains(w.Message, `requirement "REQ-999"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MAPPING_UNRESOLVED for the unmatched join; warnings = %+v", report.Warnings)
	}
}

func TestProcess_UnresolvedArtifactAndPointer(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{"policy": {}}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"requirement": "REQ-001", "evidence": {"artifact": "artifacts/absent.json"}},
		{"requirement": "REQ-001", "evidence": {"artifact": "artifacts/idp-posture.json", "pointer": "/policy/absent"}}
	`))

	report := Process(testProfile(), testDigest, pack)

	entries := supportFor(t, report)
	if entries[0].Resolution != ResolutionUnresolved || entries[1].Resolution != ResolutionUnresolved {
		t.Errorf("resolutions = %q, %q, want unresolved", entries[0].Resolution, entries[1].Resolution)
	}
	unresolved := 0
	for _, w := range report.Warnings {
		if w.Code == CodeMappingUnresolved {
			unresolved++
		}
	}
	if unresolved != 2 {
		t.Errorf("MAPPING_UNRESOLVED warnings = %d, want 2", unresolved)
	}
}

func TestProcess_DocumentQuoteResolution(t *testing.T) {
	index := []byte(`{
		"snapshot_id": "snap-1",
		"captured_at": "2026-08-28T14:00:00Z",
		"documents": [
			{"document_id": "doc-with-text",
			 "name": "Information Security Policy.pdf",
			 "file": {"path": "artifacts/documents/doc-with-text/file.pdf"},
			 "text": {"path": "artifacts/documents/doc-with-text/text.txt"}},
			{"document_id": "doc-without-text",
			 "name": "Old Scan.pdf",
			 "file": {"path": "artifacts/documents/doc-without-text/file.pdf"}}
		]
	}`)

	pack := &fakePack{}
	pack.add("artifacts/documents.json", DocumentIndexSchema, index)
	pack.add("artifacts/documents/doc-with-text/file.pdf", "", []byte("%PDF"))
	pack.add("artifacts/documents/doc-with-text/text.txt", "", []byte("This policy is reviewed at least annually and approved by the CISO."))
	pack.add("artifacts/documents/doc-without-text/file.pdf", "", []byte("%PDF"))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"control": "PL-01",
		 "evidence": {"document_id": "doc-with-text",
		              "quote": {"exact": "reviewed at least annually", "prefix": "policy is "}}},
		{"control": "PL-01",
		 "evidence": {"document_id": "doc-with-text",
		              "quote": {"exact": "reviewed on Tuesdays"}}},
		{"control": "PL-01",
		 "evidence": {"document_id": "doc-without-text",
		              "quote": {"exact": "anything"}}},
		{"control": "PL-01",
		 "evidence": {"document_id": "doc-with-text"}},
		{"control": "PL-01",
		 "evidence": {"document_id": "doc-absent"}},
		{"control": "PL-01",
		 "evidence": {"document_id": "doc-without-text",
		              "table": {"where": {"Employee": "jsmith@acme.com"}}}}
	`))

	report := Process(testProfile(), testDigest, pack)

	entries := supportFor(t, report)
	want := []string{
		ResolutionResolved,     // quote found in extracted text
		ResolutionUnresolved,   // quote absent from extracted text
		ResolutionDocumentOnly, // no text extraction for the document
		ResolutionResolved,     // whole-document citation
		ResolutionUnresolved,   // document not indexed
		ResolutionDocumentOnly, // table anchor: no tabular extraction exists
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %d, want %d", len(entries), len(want))
	}
	for i, state := range want {
		if entries[i].Resolution != state {
			t.Errorf("entry %d resolution = %q, want %q", i, entries[i].Resolution, state)
		}
	}
	// All six entries join the manual REQ-003, so no MANUAL_UNSUPPORTED.
	for _, w := range report.Warnings {
		if w.Code == CodeManualUnsupported {
			t.Errorf("manual requirement with support must not warn: %+v", w)
		}
	}
}

func TestProcess_MalformedEntrySkipped(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"requirement": "REQ-001", "control": "CC6.1", "evidence": {"artifact": "artifacts/idp-posture.json"}},
		{"requirement": "REQ-001", "evidence": {"artifact": "artifacts/idp-posture.json"}}
	`))

	report := Process(testProfile(), testDigest, pack)

	entries := supportFor(t, report)
	if len(entries) != 1 {
		t.Fatalf("malformed entry must be skipped; entries = %d", len(entries))
	}
	found := false
	for _, w := range report.Warnings {
		if w.Code == CodeInvalidMappingEntry && strings.Contains(w.Message, "entry 0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected INVALID_MAPPING_ENTRY for entry 0; warnings = %+v", report.Warnings)
	}
}

func TestProcess_ProfileDigestMismatchMarksStale(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"requirement": "REQ-001", "evidence": {"artifact": "artifacts/idp-posture.json"}}
	`))

	otherDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	report := Process(testProfile(), otherDigest, pack)

	entries := supportFor(t, report)
	if !entries[0].Stale {
		t.Error("entry should be marked stale on digest mismatch")
	}
	if entries[0].Resolution != ResolutionResolved {
		t.Errorf("stale entries still resolve; Resolution = %q", entries[0].Resolution)
	}
	mismatches := 0
	for _, w := range report.Warnings {
		if w.Code == CodeMappingProfileMismatch {
			mismatches++
		}
	}
	if mismatches != 1 {
		t.Errorf("MAPPING_PROFILE_MISMATCH warnings = %d, want 1 per mapping artifact", mismatches)
	}
}

func TestProcess_MappingForOtherProfileSkipped(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/control-mappings.json", Schema, []byte(`{
		"schema_version": "1.0.0",
		"captured_at": "2026-08-28T14:02:11Z",
		"profile": {"id": "other/profile@v1"},
		"mappings": [{"requirement": "REQ-001", "evidence": {"artifact": "artifacts/absent.json"}}]
	}`))

	report := Process(testProfile(), testDigest, pack)

	if report.Support != nil {
		t.Errorf("mapping for another profile must be ignored; Support = %+v", report.Support)
	}
	for _, w := range report.Warnings {
		if w.Code != CodeManualUnsupported {
			t.Errorf("unexpected warning: %+v", w)
		}
	}
}

func TestProcess_ManualUnsupportedWithoutAnyMappings(t *testing.T) {
	report := Process(testProfile(), testDigest, &fakePack{})

	if report.Support != nil {
		t.Errorf("Support = %+v, want nil", report.Support)
	}
	codes := warningCodes(report)
	if len(codes) != 1 || codes[0] != CodeManualUnsupported {
		t.Errorf("warnings = %v, want one MANUAL_UNSUPPORTED", codes)
	}
	if !strings.Contains(report.Warnings[0].Message, "REQ-003") {
		t.Errorf("warning should name the requirement: %q", report.Warnings[0].Message)
	}
}

func TestProcess_AmbiguousTypeJoinMatchesNothing(t *testing.T) {
	profile := testProfile()
	// Both machine-checked requirements now share a schema.
	profile.Requirements[1].Clauses = []compiled.CompiledClause{{Schema: "evidencepack/idp-posture@v1"}}

	pack := &fakePack{}
	pack.add("artifacts/idp-posture.json", "evidencepack/idp-posture@v1", []byte(`{}`))
	pack.add("artifacts/control-mappings.json", Schema, mappingJSON(`
		{"type": "evidencepack/idp-posture@v1", "evidence": {"artifact": "artifacts/idp-posture.json"}}
	`))

	report := Process(profile, testDigest, pack)

	entries := supportFor(t, report)
	if entries[0].RequirementID != "" {
		t.Errorf("ambiguous type join must match nothing; RequirementID = %q", entries[0].RequirementID)
	}
}

func TestProcess_UnparsableMappingWarns(t *testing.T) {
	pack := &fakePack{}
	pack.add("artifacts/control-mappings.json", Schema, []byte("{broken"))

	report := Process(testProfile(), testDigest, pack)

	found := false
	for _, w := range report.Warnings {
		if w.Code == CodeInvalidMappingEntry && w.Path == "artifacts/control-mappings.json" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected INVALID_MAPPING_ENTRY for the unparsable artifact; warnings = %+v", report.Warnings)
	}
}

func TestQuoteFound_CollapsesWhitespace(t *testing.T) {
	text := []byte("This policy is\nreviewed   at least\nannually and approved by the CISO.")
	quote := &Quote{Exact: "reviewed at least annually", Prefix: "policy is ", Suffix: " and approved"}
	if !quoteFound(text, quote, nil) {
		t.Fatalf("expected collapsed-whitespace quote to resolve")
	}
	if quoteFound(text, &Quote{Exact: "reviewed on Tuesdays"}, nil) {
		t.Fatalf("expected absent quote to stay unresolved")
	}
}

func TestQuoteFound_ReadsTheTextOutOfTheArtifactJSON(t *testing.T) {
	// The shape a document-text artifact actually has in a pack: the passage
	// crosses a line break, which JSON carries as an escape, not whitespace.
	text := []byte(`{"document_id":"doc-1","page_count":1,"chunks":[` +
		`{"chunk_id":0,"page":1,"text":"This report is based on the evidence provided\nduring the engagement window."}]}`)

	quote := &Quote{Exact: "based on the evidence provided during the engagement window"}
	if !quoteFound(text, quote, nil) {
		t.Fatalf("expected a passage crossing a line break to resolve")
	}
	if quoteFound(text, &Quote{Exact: "based on the evidence we invented"}, nil) {
		t.Fatalf("expected an absent passage to stay unresolved")
	}
}

func TestQuoteFound_SpanningChunks(t *testing.T) {
	text := []byte(`{"chunks":[{"chunk_id":0,"page":1,"text":"powers over"},` +
		`{"chunk_id":1,"page":2,"text":"business affairs"}]}`)

	if !quoteFound(text, &Quote{Exact: "powers over business affairs"}, nil) {
		t.Fatalf("expected a passage crossing two chunks to resolve")
	}
}

func TestQuoteFound_SpacingAtTextItemBoundaries(t *testing.T) {
	// The collector's extractor runs adjacent items together; the viewer's
	// text layer puts a space between them.
	text := []byte(`{"chunks":[{"chunk_id":0,"page":1,"text":"Version1.0\nReport date2025-12-16"}]}`)

	if !quoteFound(text, &Quote{Exact: "Report date 2025-12-16"}, nil) {
		t.Fatalf("expected a passage to resolve despite item-boundary spacing")
	}
}
