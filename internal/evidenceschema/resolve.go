package evidenceschema

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ohler55/ojg/jp"
)

// Node describes the values a JSONPath can reach in a schema.
type Node struct {
	// Types lists the JSON types the value may take. Nil means the schema
	// does not constrain the type.
	Types []string
	// Enum lists the allowed values when every branch restricts them.
	Enum []any
	// Open is true when the path runs through a part of the schema that
	// accepts undeclared fields, so nothing past that point can be checked.
	Open bool
}

// Allows reports whether the node may hold a value of the given JSON type.
// Unconstrained nodes allow everything; "number" also admits "integer".
func (n *Node) Allows(jsonType string) bool {
	if n.Open || n.Types == nil {
		return true
	}
	for _, t := range n.Types {
		if t == jsonType || (jsonType == "integer" && t == "number") || (jsonType == "number" && t == "integer") {
			return true
		}
	}
	return false
}

// OnlyContainers reports whether the node can only be an object or an array.
func (n *Node) OnlyContainers() bool {
	if n.Open || n.Types == nil {
		return false
	}
	for _, t := range n.Types {
		if t != "object" && t != "array" && t != "null" {
			return false
		}
	}
	return true
}

// UnknownFieldError reports a path segment the schema does not declare.
type UnknownFieldError struct {
	Parent      string   // The part of the path that resolved, e.g. "$.user_security"
	Field       string   // The segment that did not
	Known       []string // Fields the schema declares at Parent
	Suggestions []string // Declared paths that look like what was meant
}

func (e *UnknownFieldError) Error() string {
	return fmt.Sprintf("%s has no field %q", e.Parent, e.Field)
}

// ShapeError reports a segment that does not fit the value's shape, such as
// an array index on an object.
type ShapeError struct {
	Parent  string
	Message string
}

func (e *ShapeError) Error() string {
	return fmt.Sprintf("%s %s", e.Parent, e.Message)
}

// UncheckedError reports path syntax that cannot be resolved statically.
type UncheckedError struct {
	Reason string
}

func (e *UncheckedError) Error() string {
	return e.Reason
}

// maxRefDepth bounds $ref and combinator expansion so a cyclic schema
// cannot recurse forever.
const maxRefDepth = 32

// Resolve walks a parsed JSONPath through the schema.
func (s *Schema) Resolve(expr jp.Expr) (*Node, error) {
	current := s.alternatives(s.root, 0)
	prefix := "$"

	for _, frag := range expr {
		switch f := frag.(type) {
		case jp.Root, jp.At, jp.Bracket:
			continue
		case jp.Child:
			name := string(f)
			next, open, known, objectLike := s.child(current, name)
			if open {
				return &Node{Open: true}, nil
			}
			if len(next) == 0 {
				if !objectLike {
					return nil, &ShapeError{Parent: prefix, Message: fmt.Sprintf("is not an object, so it has no field %q", name)}
				}
				return nil, &UnknownFieldError{
					Parent:      prefix,
					Field:       name,
					Known:       known,
					Suggestions: s.suggest(normalizedPath(expr)),
				}
			}
			current = next
			prefix += "." + name
		case jp.Wildcard:
			next, open := s.elements(current, true)
			if open {
				return &Node{Open: true}, nil
			}
			if len(next) == 0 {
				return nil, &ShapeError{Parent: prefix, Message: "is not an array or object, so [*] matches nothing"}
			}
			current = next
			prefix += "[*]"
		case jp.Nth, jp.Slice:
			next, open := s.elements(current, false)
			if open {
				return &Node{Open: true}, nil
			}
			if len(next) == 0 {
				return nil, &ShapeError{Parent: prefix, Message: "is not an array, so it cannot be indexed"}
			}
			current = next
			prefix += "[*]"
		case jp.Descent:
			return nil, &UncheckedError{Reason: "recursive descent (..) cannot be checked against the schema"}
		case jp.Filter, *jp.Filter:
			return nil, &UncheckedError{Reason: "filter expressions cannot be checked against the schema"}
		case jp.Union:
			return nil, &UncheckedError{Reason: "unions cannot be checked against the schema"}
		default:
			return nil, &UncheckedError{Reason: fmt.Sprintf("path segment %T cannot be checked against the schema", frag)}
		}
	}

	return describe(current), nil
}

// alternatives flattens $ref, oneOf, anyOf and allOf into the concrete
// schemas a value may match. allOf members are treated as alternatives: a
// field declared by any member is a declared field.
func (s *Schema) alternatives(node any, depth int) []map[string]any {
	if depth > maxRefDepth {
		return nil
	}
	switch n := node.(type) {
	case bool:
		if n {
			return []map[string]any{{}}
		}
		return nil
	case map[string]any:
		if ref, ok := n["$ref"].(string); ok {
			target, ok := s.pointer(ref)
			if !ok {
				return []map[string]any{{}}
			}
			return s.alternatives(target, depth+1)
		}
		var out []map[string]any
		combined := false
		for _, key := range []string{"oneOf", "anyOf", "allOf"} {
			members, ok := n[key].([]any)
			if !ok {
				continue
			}
			combined = true
			for _, m := range members {
				out = append(out, s.alternatives(m, depth+1)...)
			}
		}
		if !combined || hasShape(n) {
			out = append(out, n)
		}
		return out
	default:
		return nil
	}
}

func hasShape(n map[string]any) bool {
	for _, key := range []string{"type", "properties", "items", "additionalProperties", "enum", "const"} {
		if _, ok := n[key]; ok {
			return true
		}
	}
	return false
}

// pointer resolves a local JSON pointer such as "#/$defs/Summary".
func (s *Schema) pointer(ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#") {
		return nil, false
	}
	var cur any = s.root
	for _, part := range strings.Split(strings.TrimPrefix(strings.TrimPrefix(ref, "#"), "/"), "/") {
		if part == "" {
			continue
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// child looks a field up across alternatives. open is true when some branch
// accepts undeclared fields; objectLike is false when no branch is an object.
func (s *Schema) child(alts []map[string]any, name string) (next []map[string]any, open bool, known []string, objectLike bool) {
	seen := map[string]bool{}
	for _, alt := range alts {
		if !isObjectLike(alt) {
			continue
		}
		objectLike = true
		props, hasProps := alt["properties"].(map[string]any)
		for key := range props {
			if !seen[key] {
				seen[key] = true
				known = append(known, key)
			}
		}
		if p, ok := props[name]; ok {
			next = append(next, s.alternatives(p, 0)...)
			continue
		}
		if _, ok := alt["patternProperties"]; ok {
			open = true
			continue
		}
		switch ap := alt["additionalProperties"].(type) {
		case map[string]any:
			next = append(next, s.alternatives(ap, 0)...)
		case bool:
			if ap {
				open = true
			}
		case nil:
			if !hasProps {
				open = true
			}
		}
	}
	sort.Strings(known)
	return next, open, known, objectLike
}

// elements returns the schemas of an array's items, and with objectValues
// also the values of an object, which is what [*] reaches.
func (s *Schema) elements(alts []map[string]any, objectValues bool) (next []map[string]any, open bool) {
	for _, alt := range alts {
		if isArrayLike(alt) {
			items, ok := alt["items"]
			if !ok {
				open = true
				continue
			}
			next = append(next, s.alternatives(items, 0)...)
			continue
		}
		if !objectValues || !isObjectLike(alt) {
			continue
		}
		if props, ok := alt["properties"].(map[string]any); ok {
			for _, p := range props {
				next = append(next, s.alternatives(p, 0)...)
			}
		}
		switch ap := alt["additionalProperties"].(type) {
		case map[string]any:
			next = append(next, s.alternatives(ap, 0)...)
		case bool:
			if ap {
				open = true
			}
		}
	}
	return next, open
}

func isObjectLike(n map[string]any) bool {
	if len(n) == 0 {
		return true
	}
	if _, ok := n["properties"]; ok {
		return true
	}
	if _, ok := n["additionalProperties"]; ok {
		return true
	}
	return hasType(n, "object")
}

func isArrayLike(n map[string]any) bool {
	if _, ok := n["items"]; ok {
		return true
	}
	return hasType(n, "array")
}

func hasType(n map[string]any, want string) bool {
	for _, t := range typesOf(n) {
		if t == want {
			return true
		}
	}
	return false
}

func typesOf(n map[string]any) []string {
	switch t := n["type"].(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, v := range t {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func describe(alts []map[string]any) *Node {
	node := &Node{}
	typeSet := map[string]bool{}
	unconstrained := len(alts) == 0
	enumComplete := true
	var enum []any

	for _, alt := range alts {
		types := typesOf(alt)
		if c, ok := alt["const"]; ok {
			enum = append(enum, c)
			if len(types) == 0 {
				types = []string{JSONType(c)}
			}
		} else if values, ok := alt["enum"].([]any); ok {
			enum = append(enum, values...)
			if len(types) == 0 {
				for _, v := range values {
					types = append(types, JSONType(v))
				}
			}
		} else if len(types) != 1 || types[0] != "null" {
			enumComplete = false
		}
		if len(types) == 0 {
			unconstrained = true
		}
		for _, t := range types {
			typeSet[t] = true
		}
	}

	if !unconstrained {
		for t := range typeSet {
			node.Types = append(node.Types, t)
		}
		sort.Strings(node.Types)
	}
	if enumComplete && len(enum) > 0 {
		node.Enum = enum
	}
	return node
}

// JSONType names the JSON type of a value decoded from YAML or JSON.
func JSONType(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "integer"
	case float32:
		if float32(int64(val)) == val {
			return "integer"
		}
		return "number"
	case float64:
		if float64(int64(val)) == val {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func normalizedPath(expr jp.Expr) string {
	var b strings.Builder
	b.WriteString("$")
	for _, frag := range expr {
		switch f := frag.(type) {
		case jp.Child:
			b.WriteString(".")
			b.WriteString(string(f))
		case jp.Wildcard, jp.Nth, jp.Slice:
			b.WriteString("[*]")
		}
	}
	return b.String()
}
