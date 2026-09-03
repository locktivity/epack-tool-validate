package mapping

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// PackReader is the slice of the pack surface resolution needs.
// *componentsdk.Pack satisfies it.
type PackReader interface {
	Artifacts() []componentsdk.Artifact
	HasArtifact(path string) bool
	ReadArtifact(path string) ([]byte, error)
}

// documentInfo is one document's resolution data from a document index.
type documentInfo struct {
	FilePath string
	TextPath string
}

// documentIndex mirrors the slice of evidencepack/document-index@v1 that
// resolution reads. Unknown fields are ignored.
type documentIndex struct {
	Documents []struct {
		DocumentID string `json:"document_id"`
		File       *struct {
			Path string `json:"path"`
		} `json:"file"`
		Text *struct {
			Path string `json:"path"`
		} `json:"text"`
	} `json:"documents"`
}

// loadDocumentIndexes reads every document index artifact in the pack into a
// document_id lookup. A malformed index reads as indexing no documents; its
// entries then resolve as unresolved, which the warnings surface.
func loadDocumentIndexes(pack PackReader) map[string]documentInfo {
	docs := make(map[string]documentInfo)
	for _, artifact := range pack.Artifacts() {
		if artifact.Schema != DocumentIndexSchema {
			continue
		}
		data, err := pack.ReadArtifact(artifact.Path)
		if err != nil {
			continue
		}
		var index documentIndex
		if err := json.Unmarshal(data, &index); err != nil {
			continue
		}
		for _, doc := range index.Documents {
			if doc.DocumentID == "" {
				continue
			}
			info := documentInfo{}
			if doc.File != nil {
				info.FilePath = doc.File.Path
			}
			if doc.Text != nil {
				info.TextPath = doc.Text.Path
			}
			docs[doc.DocumentID] = info
		}
	}
	return docs
}

// resolution is the outcome of resolving one entry's evidence reference.
type resolution struct {
	State  string
	Value  any    // Cited value when a pointer resolved to a scalar
	Detail string // Why the reference did not resolve (empty when it did)
}

// resolveEvidence resolves an entry's evidence reference against the pack.
// Resolution is best-effort and display-oriented; it never affects
// verification or validation outcomes.
func resolveEvidence(ev *Evidence, pack PackReader, docs map[string]documentInfo) resolution {
	if ev.Artifact != "" {
		return resolveArtifact(ev, pack)
	}
	return resolveDocument(ev, pack, docs)
}

func resolveArtifact(ev *Evidence, pack PackReader) resolution {
	if !pack.HasArtifact(ev.Artifact) {
		return resolution{State: ResolutionUnresolved, Detail: "cites artifact " + ev.Artifact + " not present in the pack"}
	}
	if ev.Pointer == "" {
		return resolution{State: ResolutionResolved}
	}

	data, err := pack.ReadArtifact(ev.Artifact)
	if err != nil {
		return resolution{State: ResolutionUnresolved, Detail: "artifact " + ev.Artifact + " could not be read"}
	}
	var body any
	if err := json.Unmarshal(data, &body); err != nil {
		return resolution{State: ResolutionUnresolved, Detail: "pointer " + ev.Pointer + " cannot resolve: " + ev.Artifact + " is not JSON"}
	}
	value, found := resolvePointer(body, ev.Pointer)
	if !found {
		return resolution{State: ResolutionUnresolved, Detail: "pointer " + ev.Pointer + " not found in " + ev.Artifact}
	}
	return resolution{State: ResolutionResolved, Value: scalarValue(value)}
}

func resolveDocument(ev *Evidence, pack PackReader, docs map[string]documentInfo) resolution {
	info, ok := docs[ev.DocumentID]
	if !ok {
		return resolution{State: ResolutionUnresolved, Detail: "cites document " + ev.DocumentID + " not indexed in the pack"}
	}

	switch {
	case ev.Quote != nil:
		if info.TextPath == "" || !pack.HasArtifact(info.TextPath) {
			return resolution{State: ResolutionDocumentOnly}
		}
		text, err := pack.ReadArtifact(info.TextPath)
		if err != nil {
			return resolution{State: ResolutionDocumentOnly}
		}
		if quoteFound(text, ev.Quote, ev.TextPosition) {
			return resolution{State: ResolutionResolved}
		}
		return resolution{State: ResolutionUnresolved, Detail: "quote not found in the text of document " + ev.DocumentID}
	case ev.Table != nil:
		// No tabular extraction format ships in packs yet, so table anchors
		// always resolve at document level.
		return resolution{State: ResolutionDocumentOnly}
	default:
		return resolution{State: ResolutionResolved}
	}
}

// quoteFound locates a quoted passage in a document's extracted text. The
// contextualized search comes first, then the bare passage, then the byte
// offsets recorded for this sealed version.
func quoteFound(text []byte, quote *Quote, pos *TextPosition) bool {
	s := string(text)
	if quote.Prefix != "" || quote.Suffix != "" {
		if strings.Contains(s, quote.Prefix+quote.Exact+quote.Suffix) {
			return true
		}
	}
	if strings.Contains(s, quote.Exact) {
		return true
	}
	if pos != nil && pos.Start >= 0 && pos.End <= len(text) && pos.Start <= pos.End {
		return s[pos.Start:pos.End] == quote.Exact
	}
	return false
}

// resolvePointer walks an RFC 6901 JSON Pointer through decoded JSON.
func resolvePointer(body any, pointer string) (any, bool) {
	if pointer == "" {
		return body, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}

	current := body
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node := current.(type) {
		case map[string]any:
			value, ok := node[token]
			if !ok {
				return nil, false
			}
			current = value
		case []any:
			if len(token) > 1 && token[0] == '0' {
				return nil, false
			}
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

// scalarValue returns the value when it is a scalar worth echoing as the
// cited value, nil otherwise. Objects and arrays are cited by pointer, not
// duplicated into the report.
func scalarValue(value any) any {
	switch value.(type) {
	case string, bool, float64:
		return value
	default:
		return nil
	}
}
