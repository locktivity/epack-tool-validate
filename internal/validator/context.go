// Package validator provides the core validation logic.
package validator

import "time"

// Context provides dependencies for validation execution.
type Context struct {
	Now func() time.Time // Clock for freshness checks

	pack *PackIndex // The pack under validation, for reading a run's other artifacts
}

// withPack returns a copy of the context that reads pack's artifacts.
func (c *Context) withPack(pack *PackIndex) *Context {
	scoped := *c
	scoped.pack = pack
	return &scoped
}

// DefaultContext returns a context using real time.
func DefaultContext() *Context {
	return &Context{
		Now: time.Now,
	}
}

// TestContext returns a context with a fixed time for deterministic tests.
func TestContext(fixedTime time.Time) *Context {
	return &Context{
		Now: func() time.Time { return fixedTime },
	}
}
