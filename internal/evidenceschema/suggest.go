package evidenceschema

import (
	"sort"
	"strings"
)

const (
	maxSuggestions   = 3
	suggestionSpread = 2
	maxPathDepth     = 12
)

// Paths lists every path the schema declares, with arrays written as [*].
func (s *Schema) Paths() []string {
	seen := map[string]bool{}
	var out []string
	var walk func(alts []map[string]any, prefix string, depth int)
	walk = func(alts []map[string]any, prefix string, depth int) {
		if depth > maxPathDepth {
			return
		}
		for _, alt := range alts {
			if props, ok := alt["properties"].(map[string]any); ok {
				for name, p := range props {
					path := prefix + "." + name
					if !seen[path] {
						seen[path] = true
						out = append(out, path)
					}
					walk(s.alternatives(p, 0), path, depth+1)
				}
			}
			if items, ok := alt["items"]; ok {
				walk(s.alternatives(items, 0), prefix+"[*]", depth+1)
			}
		}
	}
	walk(s.alternatives(s.root, 0), "$", 0)
	sort.Strings(out)
	return out
}

// suggest ranks declared paths by how close they are to the one written.
// A declared path ending in the same field name ranks first, since the
// usual mistake is the right field at the wrong nesting.
func (s *Schema) suggest(written string) []string {
	lastField := written[strings.LastIndexAny(written, ".]")+1:]
	type candidate struct {
		path     string
		distance int
	}
	var candidates []candidate
	limit := len(written)/3 + 2
	for _, path := range s.Paths() {
		d := levenshtein(written, path)
		sameLeaf := lastField != "" && strings.HasSuffix(path, "."+lastField)
		if sameLeaf {
			d = 0
		}
		if d <= limit {
			candidates = append(candidates, candidate{path, d})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].distance != candidates[j].distance {
			return candidates[i].distance < candidates[j].distance
		}
		return candidates[i].path < candidates[j].path
	})
	var out []string
	for i := 0; i < len(candidates) && i < maxSuggestions; i++ {
		if candidates[i].distance > candidates[0].distance+suggestionSpread {
			break
		}
		out = append(out, candidates[i].path)
	}
	return out
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
