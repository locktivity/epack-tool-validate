package validator

import (
	"sync"

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

// movedConditions caches movedCondition by schema, path, and cardinality.
var movedConditions sync.Map

type movedKey struct {
	schema, path string
	cardinality  compiled.Cardinality
}

// movedTo is a condition rewritten onto the field that holds the same value
// now, and the schema of the artifact that field sits in.
type movedTo struct {
	schema    string
	condition compiled.CompiledCondition
}

// movedRead returns the condition to read instead of cond, and the body to
// read it in, when artifact has no value at cond's path and the schemas mark
// that field deprecated with a field that holds the same value. A field
// renamed in its own schema is read in the same artifact. A field moved to
// another schema is read in the artifact of that schema the same collector
// run wrote, so a check never takes another system's value. It returns nil
// otherwise, and cond reads artifact as the profile wrote it.
func movedRead(ctx *Context, schema string, artifact IndexedArtifact, cond *compiled.CompiledCondition) (*compiled.CompiledCondition, any) {
	if len(cond.Expr.Get(artifact.Body)) > 0 {
		return nil, nil
	}
	to := movedCondition(schema, cond)
	if to == nil {
		return nil, nil
	}
	if to.schema == schema {
		return &to.condition, artifact.Body
	}
	sibling, ok := ctx.pack.Sibling(artifact, to.schema)
	if !ok {
		return nil, nil
	}
	return &to.condition, sibling.Body
}

// movedCondition returns cond rewritten onto the field that holds its
// field's value now, or nil when the schemas name no such field.
func movedCondition(schema string, cond *compiled.CompiledCondition) *movedTo {
	key := movedKey{schema: schema, path: cond.Path, cardinality: cond.Cardinality}
	if cached, ok := movedConditions.Load(key); ok {
		return cached.(*movedTo)
	}
	to := buildMovedCondition(schema, cond)
	movedConditions.Store(key, to)
	return to
}

func buildMovedCondition(schema string, cond *compiled.CompiledCondition) *movedTo {
	registry := movedSchemas()
	if registry == nil {
		return nil
	}
	moved, ok := registry.MovedField(schema, cond.Path)
	if !ok || !moved.Same || moved.Path == "" {
		return nil
	}
	rewritten := *cond
	rewritten.Path = moved.Path
	if cond.Cardinality == compiled.CardinalitySingle {
		expr, err := condition.ParseJSONPath(moved.Path)
		if err != nil {
			return nil
		}
		rewritten.Expr = expr
	} else {
		expr, isMulti, err := condition.ParseJSONPathMulti(moved.Path)
		if err != nil {
			return nil
		}
		rewritten.Expr, rewritten.IsMulti, rewritten.BaseExpr = expr, isMulti, condition.ExtractBasePath(expr)
	}
	return &movedTo{schema: moved.Schema, condition: rewritten}
}
