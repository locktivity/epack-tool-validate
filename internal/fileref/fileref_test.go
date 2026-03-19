//go:build !windows

package fileref

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/limits"
)

func TestLoad(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		subDir := filepath.Join(tmpDir, "profiles")
		testFile := filepath.Join(subDir, "test.yaml")
		content := []byte("id: test\nname: Test Profile")

		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		ref, err := Load(tmpDir, "profiles/test.yaml", limits.ProfileFile)
		if err != nil {
			t.Errorf("Load() unexpected error: %v", err)
		}

		// Check Path (original)
		if ref.Path != "profiles/test.yaml" {
			t.Errorf("Path = %q, want %q", ref.Path, "profiles/test.yaml")
		}

		// Check Resolved (absolute)
		if ref.Resolved != testFile {
			t.Errorf("Resolved = %q, want %q", ref.Resolved, testFile)
		}

		// Check Data
		if string(ref.Data) != string(content) {
			t.Errorf("Data = %q, want %q", ref.Data, content)
		}

		// Check Digest
		expectedHash := sha256.Sum256(content)
		expectedDigest := "sha256:" + hex.EncodeToString(expectedHash[:])
		if ref.Digest != expectedDigest {
			t.Errorf("Digest = %q, want %q", ref.Digest, expectedDigest)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := Load(tmpDir, "../../../etc/passwd", limits.ProfileFile)
		if err == nil {
			t.Error("Load() should reject path traversal")
		}
		if !strings.Contains(err.Error(), "path validation") {
			t.Errorf("error should mention 'path validation', got: %v", err)
		}
	})

	t.Run("absolute path rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := Load(tmpDir, "/etc/passwd", limits.ProfileFile)
		if err == nil {
			t.Error("Load() should reject absolute paths")
		}
		if !strings.Contains(err.Error(), "path validation") {
			t.Errorf("error should mention 'path validation', got: %v", err)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := Load(tmpDir, "nonexistent.yaml", limits.ProfileFile)
		if err == nil {
			t.Error("Load() should reject non-existent files")
		}
		if !strings.Contains(err.Error(), "file validation") && !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error should mention file issue, got: %v", err)
		}
	})

	t.Run("symlink rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		realFile := filepath.Join(tmpDir, "real.yaml")
		linkFile := filepath.Join(tmpDir, "link.yaml")

		if err := os.WriteFile(realFile, []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		if err := os.Symlink(realFile, linkFile); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		_, err := Load(tmpDir, "link.yaml", limits.ProfileFile)
		if err == nil {
			t.Error("Load() should reject symlinks")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error should mention 'symlink', got: %v", err)
		}
	})

	t.Run("file exceeds size limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "large.yaml")
		content := make([]byte, 1000)

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		_, err := Load(tmpDir, "large.yaml", limits.SizeLimit(500))
		if err == nil {
			t.Error("Load() should reject files exceeding size limit")
		}
		if !strings.Contains(err.Error(), "reading file") && !strings.Contains(err.Error(), "size") {
			t.Errorf("error should mention size issue, got: %v", err)
		}
	})

	t.Run("symlink in directory path rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		realDir := filepath.Join(tmpDir, "real")
		linkDir := filepath.Join(tmpDir, "profiles")

		if err := os.MkdirAll(realDir, 0755); err != nil {
			t.Fatalf("failed to create real dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "test.yaml"), []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		_, err := Load(tmpDir, "profiles/test.yaml", limits.ProfileFile)
		if err == nil {
			t.Error("Load() should reject symlink in directory path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error should mention 'symlink', got: %v", err)
		}
	})

	t.Run("digest consistency", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.yaml")
		content := []byte("test content for digest verification")

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		// Load twice and verify digest is consistent
		ref1, err := Load(tmpDir, "test.yaml", limits.ProfileFile)
		if err != nil {
			t.Fatalf("first Load() failed: %v", err)
		}

		ref2, err := Load(tmpDir, "test.yaml", limits.ProfileFile)
		if err != nil {
			t.Fatalf("second Load() failed: %v", err)
		}

		if ref1.Digest != ref2.Digest {
			t.Errorf("digest mismatch: %q != %q", ref1.Digest, ref2.Digest)
		}

		// Verify digest format
		if !strings.HasPrefix(ref1.Digest, "sha256:") {
			t.Errorf("digest should start with 'sha256:', got: %q", ref1.Digest)
		}

		// Verify hex part is 64 characters (256 bits / 4 bits per hex char)
		hexPart := strings.TrimPrefix(ref1.Digest, "sha256:")
		if len(hexPart) != 64 {
			t.Errorf("digest hex part should be 64 chars, got %d", len(hexPart))
		}
	})
}

func TestLocalFileRef_Fields(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.yaml")
	content := []byte("test")

	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	ref, err := Load(tmpDir, "test.yaml", limits.ProfileFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify all fields are populated
	if ref.Path == "" {
		t.Error("Path should be non-empty")
	}
	if ref.Resolved == "" {
		t.Error("Resolved should be non-empty")
	}
	if ref.Data == nil {
		t.Error("Data should be non-nil")
	}
	if ref.Digest == "" {
		t.Error("Digest should be non-empty")
	}
}
