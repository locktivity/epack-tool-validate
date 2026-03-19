package validator

import (
	"testing"
	"time"
)

func TestDefaultContext(t *testing.T) {
	ctx := DefaultContext()
	if ctx == nil {
		t.Fatal("DefaultContext() returned nil")
	}
	if ctx.Now == nil {
		t.Fatal("Now function should not be nil")
	}

	// Verify it returns approximately current time
	before := time.Now()
	now := ctx.Now()
	after := time.Now()

	if now.Before(before) || now.After(after) {
		t.Errorf("Now() returned time outside expected range: got %v, expected between %v and %v", now, before, after)
	}
}

func TestTestContext(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	ctx := TestContext(fixedTime)

	if ctx == nil {
		t.Fatal("TestContext() returned nil")
	}
	if ctx.Now == nil {
		t.Fatal("Now function should not be nil")
	}

	// Verify it returns the fixed time
	got := ctx.Now()
	if !got.Equal(fixedTime) {
		t.Errorf("Now() = %v, want %v", got, fixedTime)
	}

	// Call again to ensure it's consistent
	got2 := ctx.Now()
	if !got2.Equal(fixedTime) {
		t.Errorf("Now() second call = %v, want %v", got2, fixedTime)
	}
}

func TestTestContext_Deterministic(t *testing.T) {
	// Test that TestContext provides deterministic time for tests
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx := TestContext(fixedTime)

	// Multiple calls should always return the same time
	times := make([]time.Time, 100)
	for i := range times {
		times[i] = ctx.Now()
	}

	for i, tm := range times {
		if !tm.Equal(fixedTime) {
			t.Errorf("times[%d] = %v, want %v", i, tm, fixedTime)
		}
	}
}
