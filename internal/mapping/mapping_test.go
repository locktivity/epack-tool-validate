package mapping

import (
	"strings"
	"testing"
)

func TestParse_AcceptsUnknownFields(t *testing.T) {
	doc, err := Parse([]byte(`{
		"schema_version": "1.0.0",
		"captured_at": "2026-08-28T14:02:11Z",
		"future_field": {"nested": true},
		"profile": {"id": "acme/security-baseline@v1", "extra": 1},
		"mappings": [
			{"requirement": "REQ-001", "evidence": {"artifact": "artifacts/idp-posture.json"}, "surprise": "ok"}
		]
	}`))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if doc.Profile.ID != "acme/security-baseline@v1" {
		t.Errorf("Profile.ID = %q", doc.Profile.ID)
	}
	if len(doc.Mappings) != 1 || doc.Mappings[0].Requirement != "REQ-001" {
		t.Errorf("Mappings = %+v", doc.Mappings)
	}
}

func TestParse_RejectsInvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestEntryValidate(t *testing.T) {
	artifactRef := &Evidence{Artifact: "artifacts/a.json"}
	documentRef := &Evidence{DocumentID: "doc-1"}

	tests := []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{
			name:  "requirement join with artifact",
			entry: Entry{Requirement: "REQ-001", Evidence: artifactRef},
		},
		{
			name:  "control join with document",
			entry: Entry{Control: "CC6.1", Evidence: documentRef},
		},
		{
			name:  "type join",
			entry: Entry{Type: "evidencepack/idp-posture@v1", Evidence: artifactRef},
		},
		{
			name:    "no join",
			entry:   Entry{Evidence: artifactRef},
			wantErr: "exactly one of requirement, control, or type",
		},
		{
			name:    "two joins",
			entry:   Entry{Requirement: "REQ-001", Control: "CC6.1", Evidence: artifactRef},
			wantErr: "exactly one of requirement, control, or type",
		},
		{
			name:    "no evidence",
			entry:   Entry{Requirement: "REQ-001"},
			wantErr: "missing evidence",
		},
		{
			name:    "both artifact and document",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{Artifact: "artifacts/a.json", DocumentID: "doc-1"}},
			wantErr: "exactly one of artifact or document_id",
		},
		{
			name:    "neither artifact nor document",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{}},
			wantErr: "exactly one of artifact or document_id",
		},
		{
			name:    "pointer without artifact",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{DocumentID: "doc-1", Pointer: "/a"}},
			wantErr: "pointer requires an artifact",
		},
		{
			name:    "quote on artifact reference",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{Artifact: "artifacts/a.json", Quote: &Quote{Exact: "x"}}},
			wantErr: "require a document_id",
		},
		{
			name: "quote and table together",
			entry: Entry{Requirement: "REQ-001", Evidence: &Evidence{
				DocumentID: "doc-1",
				Quote:      &Quote{Exact: "x"},
				Table:      &Table{Where: map[string]any{"A": "b"}},
			}},
			wantErr: "both quote and table",
		},
		{
			name:    "text_position without quote",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{DocumentID: "doc-1", TextPosition: &TextPosition{Start: 0, End: 4}}},
			wantErr: "text_position requires a quote",
		},
		{
			name:    "quote missing exact",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{DocumentID: "doc-1", Quote: &Quote{Prefix: "p"}}},
			wantErr: "missing exact",
		},
		{
			name: "text_position end before start",
			entry: Entry{Requirement: "REQ-001", Evidence: &Evidence{
				DocumentID:   "doc-1",
				Quote:        &Quote{Exact: "x"},
				TextPosition: &TextPosition{Start: 10, End: 4},
			}},
			wantErr: "offsets are invalid",
		},
		{
			name:    "table missing where",
			entry:   Entry{Requirement: "REQ-001", Evidence: &Evidence{DocumentID: "doc-1", Table: &Table{Sheet: "Q2"}}},
			wantErr: "missing where",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestResolvePointer(t *testing.T) {
	body := map[string]any{
		"policy": map[string]any{
			"mfa_coverage": 92.0,
			"a/b":          "slash",
			"til~de":       "tilde",
		},
		"accounts": []any{
			map[string]any{"name": "prod"},
			map[string]any{"name": "staging"},
		},
	}

	tests := []struct {
		pointer   string
		wantValue any
		wantFound bool
	}{
		{"", body, true},
		{"/policy/mfa_coverage", 92.0, true},
		{"/accounts/1/name", "staging", true},
		{"/policy/a~1b", "slash", true},
		{"/policy/til~0de", "tilde", true},
		{"/policy/absent", nil, false},
		{"/accounts/2", nil, false},
		{"/accounts/-1", nil, false},
		{"/accounts/01", nil, false},
		{"/accounts/name", nil, false},
		{"no-leading-slash", nil, false},
		{"/policy/mfa_coverage/deeper", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.pointer, func(t *testing.T) {
			value, found := resolvePointer(body, tt.pointer)
			if found != tt.wantFound {
				t.Fatalf("resolvePointer(%q) found = %v, want %v", tt.pointer, found, tt.wantFound)
			}
			if found && tt.pointer == "/policy/mfa_coverage" && value != 92.0 {
				t.Errorf("value = %v", value)
			}
		})
	}
}

func TestQuoteFound(t *testing.T) {
	text := []byte("This policy is reviewed at least annually and approved by the CISO. Exceptions require sign-off.")

	if !quoteFound(text, &Quote{Exact: "reviewed at least annually"}, nil) {
		t.Error("bare exact should be found")
	}
	if !quoteFound(text, &Quote{Exact: "reviewed at least annually", Prefix: "policy is ", Suffix: " and approved"}, nil) {
		t.Error("contextualized quote should be found")
	}
	if !quoteFound(text, &Quote{Exact: "reviewed at least annually", Prefix: "drifted prefix "}, nil) {
		t.Error("exact alone should still be found when the prefix drifted")
	}
	if quoteFound(text, &Quote{Exact: "reviewed monthly"}, nil) {
		t.Error("absent passage should not be found")
	}
	if !quoteFound(text, &Quote{Exact: "This policy"}, &TextPosition{Start: 0, End: 11}) {
		t.Error("quote should be found")
	}
	if quoteFound([]byte("abc"), &Quote{Exact: "zzz"}, &TextPosition{Start: 0, End: 99}) {
		t.Error("out-of-bounds text_position should not match")
	}
}

func TestScalarValue(t *testing.T) {
	if scalarValue("s") != "s" || scalarValue(true) != true || scalarValue(1.5) != 1.5 {
		t.Error("scalars should pass through")
	}
	if scalarValue(map[string]any{"a": 1}) != nil || scalarValue([]any{1}) != nil || scalarValue(nil) != nil {
		t.Error("non-scalars should be dropped")
	}
}
