// Package validator provides the core validation logic.
package validator

import "time"

// Context provides dependencies for validation execution.
type Context struct {
	Now func() time.Time // Clock for freshness checks
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
