package evidenceschema

import (
	"strings"

	"github.com/ohler55/ojg/jp"
)

// Moved says where a deprecated field's value is now, from its schema's
// x-epack-replaced-by. A field with no reason of its own takes the nearest
// enclosing block's, and a field in a moved block with no annotation of its
// own takes the block's schema.
type Moved struct {
	Schema string // The schema ID that holds the value now
	Path   string // The field that holds it, or "" when no one field does
	Same   bool   // The new field holds the same value in the same collector's artifact
	Reason string // Why the field moved, for someone editing a profile
}

// MovedField returns where the value of the deprecated field at path in
// typ's schema is now. It reports false for a field the schema does not
// declare as deprecated, and for a path with filters, slices, or recursive
// descent. An index reads as every element.
func (r *Registry) MovedField(typ, path string) (Moved, bool) {
	s := r.Lookup(typ)
	if s == nil {
		return Moved{}, false
	}
	key, ok := canonicalPath(path)
	if !ok {
		return Moved{}, false
	}
	s.movedOnce.Do(func() {
		s.moved = map[string]Moved{}
		s.indexMoved(s.root, "$", Moved{}, 0)
	})
	moved, ok := s.moved[key]
	return moved, ok
}

// maxMovedDepth stops a schema whose $refs loop from recursing forever.
const maxMovedDepth = 32

// indexMoved records each deprecated field under node by its path. block is
// what the nearest enclosing deprecated block passes down: its schema and
// reason, never its path or same.
func (s *Schema) indexMoved(node map[string]any, path string, block Moved, depth int) {
	if depth > maxMovedDepth {
		return
	}
	node = s.deref(node)
	if node["deprecated"] == true {
		here := block
		replaced, _ := node["x-epack-replaced-by"].(map[string]any)
		if to, ok := replaced["schema"].(string); ok && to != "" {
			here = Moved{Schema: to, Reason: block.Reason}
			here.Path, _ = replaced["path"].(string)
			here.Same = replaced["same"] == true
		}
		if reason, ok := replaced["reason"].(string); ok && reason != "" {
			here.Reason = reason
		}
		if here.Schema != "" {
			s.moved[path] = here
		}
		block = Moved{Schema: here.Schema, Reason: here.Reason}
	}
	if props, ok := node["properties"].(map[string]any); ok {
		for name, raw := range props {
			if child, ok := raw.(map[string]any); ok {
				s.indexMoved(child, path+"."+name, block, depth+1)
			}
		}
	}
	if items, ok := node["items"].(map[string]any); ok {
		s.indexMoved(items, path+"[*]", block, depth+1)
	}
}

// deref returns the node a local $ref names, with the node's own keywords
// over it.
func (s *Schema) deref(node map[string]any) map[string]any {
	name, ok := strings.CutPrefix(stringValue(node["$ref"]), "#/$defs/")
	if !ok {
		return node
	}
	defs, _ := s.root["$defs"].(map[string]any)
	target, ok := defs[name].(map[string]any)
	if !ok {
		return node
	}
	merged := make(map[string]any, len(target)+len(node))
	for key, value := range target {
		merged[key] = value
	}
	for key, value := range node {
		if key != "$ref" {
			merged[key] = value
		}
	}
	return merged
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

// canonicalPath writes a JSONPath the way x-epack-replaced-by and the
// moved index write it, such as $.accounts[*].logging.audit_log_enabled.
func canonicalPath(path string) (string, bool) {
	expr, err := jp.ParseString(path)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	for _, frag := range expr {
		switch f := frag.(type) {
		case jp.Root:
			b.WriteString("$")
		case jp.Child:
			b.WriteString("." + string(f))
		case jp.Wildcard, jp.Nth:
			b.WriteString("[*]")
		case jp.Bracket:
		default:
			return "", false
		}
	}
	return b.String(), true
}
