// Package evidenceschema resolves profile JSONPaths against the JSON Schemas
// of the artifacts they test.
//
// The bundled schemas are the normalized schemas the epack collector SDK
// checks collector output against. They are read from the SDK with
// componentsdk.NormalizedSchemaJSON, so lint sees a change to one only after
// go.mod requires an epack release that has it.
package evidenceschema

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/locktivity/epack/componentsdk"
)

var bundledTypes = []string{
	"evidencepack/idp-posture@v1",
	"evidencepack/cloud-posture@v1",
	"evidencepack/vcs-posture@v1",
	"evidencepack/email-dns@v1",
	"evidencepack/tls@v1",
}

// SourceBundled marks a schema that ships inside this tool.
const SourceBundled = "bundled"

// Schema is one artifact type's JSON Schema.
type Schema struct {
	Type   string
	Source string
	root   map[string]any
}

// Registry maps artifact types to their schemas.
type Registry struct {
	schemas map[string]*Schema
}

// Bundled returns a registry holding the schemas that ship with this tool.
func Bundled() (*Registry, error) {
	r := &Registry{schemas: map[string]*Schema{}}
	for _, typ := range bundledTypes {
		data := componentsdk.NormalizedSchemaJSON(typ)
		if data == nil {
			return nil, fmt.Errorf("epack has no normalized schema for %s", typ)
		}
		if err := r.Add(typ, data, SourceBundled); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Add registers a schema, replacing any schema already held for the type.
func (r *Registry) Add(typ string, data []byte, source string) error {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parsing schema for %s from %s: %w", typ, source, err)
	}
	r.schemas[typ] = &Schema{Type: typ, Source: source, root: root}
	return nil
}

// Lookup returns the schema for an artifact type, or nil when none is known.
func (r *Registry) Lookup(typ string) *Schema {
	return r.schemas[typ]
}

// Types lists the artifact types the registry holds, sorted.
func (r *Registry) Types() []string {
	types := make([]string, 0, len(r.schemas))
	for typ := range r.schemas {
		types = append(types, typ)
	}
	sort.Strings(types)
	return types
}
