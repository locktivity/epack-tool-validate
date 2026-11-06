package validator

import (
	"sync"

	"github.com/ohler55/ojg/jp"

	"github.com/locktivity/epack-tool-validate/internal/condition"
	"github.com/locktivity/epack-tool-validate/internal/evidenceschema"
	"github.com/locktivity/epack-tool-validate/internal/profile/compiled"
)

// movedSchemas holds the bundled schemas, whose x-epack-replaced-by says
// where each deprecated field's value is now. It is nil when they don't
// load, and conditions then read only the fields they name.
var movedSchemas = sync.OnceValue(func() *evidenceschema.Registry {
	registry, err := evidenceschema.Bundled()
	if err != nil {
		return nil
	}
	return registry
})

// movedPaths caches movedPath by schema, path, and cardinality.
var movedPaths sync.Map

type movedKey struct {
	schema, path string
	cardinality  compiled.Cardinality
}

// movedField is where a field's value is now: the schema, and the path
// parsed the way a condition with the same cardinality parses it.
type movedField struct {
	schema   string
	path     string
	expr     jp.Expr
	baseExpr jp.Expr
	isMulti  bool
}

// movedRead returns the condition to read instead of cond, and the body to
// read it in, when artifact has no value at cond's path and the schemas mark
// that field deprecated with a field that holds the same value. A field
// renamed in its own schema is read in the same artifact. A field moved to
// another schema is read in the artifact of that schema the same collector
// run wrote, so a check never takes another system's value. It returns nil
// otherwise, and cond reads artifact as the profile wrote it. The condition
// keeps cond's operator, value, and cardinality.
func movedRead(ctx *Context, schema string, artifact IndexedArtifact, cond *compiled.CompiledCondition) (*compiled.CompiledCondition, any) {
	if len(cond.Expr.Get(artifact.Body)) > 0 {
		return nil, nil
	}
	to := movedPath(schema, cond)
	if to == nil {
		return nil, nil
	}
	body := artifact.Body
	if to.schema != schema {
		sibling, ok := ctx.pack.Sibling(artifact, to.schema)
		if !ok {
			return nil, nil
		}
		body = sibling.Body
	}
	rewritten := *cond
	rewritten.Path, rewritten.Expr, rewritten.BaseExpr, rewritten.IsMulti = to.path, to.expr, to.baseExpr, to.isMulti
	return &rewritten, body
}

// movedPath returns where cond's field holds its value now, or nil when the
// schemas name no field that holds the same value.
func movedPath(schema string, cond *compiled.CompiledCondition) *movedField {
	key := movedKey{schema: schema, path: cond.Path, cardinality: cond.Cardinality}
	if cached, ok := movedPaths.Load(key); ok {
		return cached.(*movedField)
	}
	to := buildMovedPath(schema, cond.Path, cond.Cardinality)
	movedPaths.Store(key, to)
	return to
}

func buildMovedPath(schema, path string, cardinality compiled.Cardinality) *movedField {
	registry := movedSchemas()
	if registry == nil {
		return nil
	}
	moved, ok := registry.MovedField(schema, path)
	if !ok || !moved.Same || moved.Path == "" {
		return nil
	}
	to := &movedField{schema: moved.Schema, path: moved.Path}
	if cardinality == compiled.CardinalitySingle {
		expr, err := condition.ParseJSONPath(moved.Path)
		if err != nil {
			return nil
		}
		to.expr = expr
		return to
	}
	expr, isMulti, err := condition.ParseJSONPathMulti(moved.Path)
	if err != nil {
		return nil
	}
	to.expr, to.isMulti, to.baseExpr = expr, isMulti, condition.ExtractBasePath(expr)
	return to
}
