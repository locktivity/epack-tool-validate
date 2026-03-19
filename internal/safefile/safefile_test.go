//go:build !windows

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack-tool-validate/internal/limits"
)

func TestValidatePath(t *testing.T) {
	baseDir := t.TempDir()

	t.Run("valid relative path", func(t *testing.T) {
		result, err := ValidatePath(baseDir, "profiles/test.yaml")
		if err != nil {
			t.Errorf("ValidatePath() unexpected error: %v", err)
		}
		if !strings.HasPrefix(result, baseDir) {
			t.Errorf("ValidatePath() result %q should be under %q", result, baseDir)
		}
	})

	t.Run("absolute path rejected", func(t *testing.T) {
		_, err := ValidatePath(baseDir, "/etc/passwd")
		if err == nil {
			t.Error("ValidatePath() should reject absolute paths")
		}
		if !strings.Contains(err.Error(), "absolute paths not allowed") {
			t.Errorf("error should mention 'absolute paths not allowed', got: %v", err)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		_, err := ValidatePath(baseDir, "../../../etc/passwd")
		if err == nil {
			t.Error("ValidatePath() should reject path traversal")
		}
		if !strings.Contains(err.Error(), "traversal") {
			t.Errorf("error should mention 'traversal', got: %v", err)
		}
	})

	t.Run("path that resolves outside base rejected", func(t *testing.T) {
		_, err := ValidatePath(baseDir, "profiles/../../..")
		if err == nil {
			t.Error("ValidatePath() should reject paths escaping base")
		}
	})

	t.Run("single dot path", func(t *testing.T) {
		result, err := ValidatePath(baseDir, ".")
		if err != nil {
			t.Errorf("ValidatePath() unexpected error for '.': %v", err)
		}
		absBase, _ := filepath.Abs(baseDir)
		if result != absBase {
			t.Errorf("ValidatePath(.) = %q, want %q", result, absBase)
		}
	})

	t.Run("nested path with dots", func(t *testing.T) {
		result, err := ValidatePath(baseDir, "profiles/./test.yaml")
		if err != nil {
			t.Errorf("ValidatePath() unexpected error: %v", err)
		}
		if !strings.HasSuffix(result, filepath.Join("profiles", "test.yaml")) {
			t.Errorf("ValidatePath() = %q, doesn't end with profiles/test.yaml", result)
		}
	})
}

func TestReadFile(t *testing.T) {
	t.Run("read small file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("hello world")
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := ReadFile(testFile, limits.ProfileFile)
		if err != nil {
			t.Errorf("ReadFile() unexpected error: %v", err)
		}
		if string(data) != string(content) {
			t.Errorf("ReadFile() = %q, want %q", data, content)
		}
	})

	t.Run("file exceeds limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "large.txt")
		content := make([]byte, 1000)
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		_, err := ReadFile(testFile, limits.SizeLimit(500))
		if err == nil {
			t.Error("ReadFile() should reject file exceeding size limit")
		}
		if !strings.Contains(err.Error(), "exceeds maximum size") {
			t.Errorf("error should mention 'exceeds maximum size', got: %v", err)
		}
	})

	t.Run("refuse symlink", func(t *testing.T) {
		tmpDir := t.TempDir()
		realFile := filepath.Join(tmpDir, "real.txt")
		linkFile := filepath.Join(tmpDir, "link.txt")

		if err := os.WriteFile(realFile, []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		if err := os.Symlink(realFile, linkFile); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		_, err := ReadFile(linkFile, limits.ProfileFile)
		if err == nil {
			t.Error("ReadFile() should refuse to read symlinks")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error should mention 'symlink', got: %v", err)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ReadFile("/nonexistent/path.txt", limits.ProfileFile)
		if err == nil {
			t.Error("ReadFile() should return error for non-existent file")
		}
	})

	t.Run("exactly at limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "exact.txt")
		content := make([]byte, 100)
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := ReadFile(testFile, limits.SizeLimit(100))
		if err != nil {
			t.Errorf("ReadFile() should allow file at exact limit: %v", err)
		}
		if len(data) != 100 {
			t.Errorf("ReadFile() returned %d bytes, want 100", len(data))
		}
	})
}

func TestContainsSymlinkFrom(t *testing.T) {
	t.Run("no symlinks", func(t *testing.T) {
		tmpDir := t.TempDir()
		subDir := filepath.Join(tmpDir, "subdir")
		testFile := filepath.Join(subDir, "test.txt")

		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		hasSymlink, err := ContainsSymlinkFrom(testFile, tmpDir)
		if err != nil {
			t.Errorf("ContainsSymlinkFrom() unexpected error: %v", err)
		}
		if hasSymlink {
			t.Error("ContainsSymlinkFrom() should return false for path without symlinks")
		}
	})

	t.Run("symlink in path", func(t *testing.T) {
		tmpDir := t.TempDir()
		realDir := filepath.Join(tmpDir, "real")
		linkDir := filepath.Join(tmpDir, "link")
		testFile := filepath.Join(linkDir, "test.txt")

		if err := os.MkdirAll(realDir, 0755); err != nil {
			t.Fatalf("failed to create real dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realDir, "test.txt"), []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		hasSymlink, err := ContainsSymlinkFrom(testFile, tmpDir)
		if err != nil {
			t.Errorf("ContainsSymlinkFrom() unexpected error: %v", err)
		}
		if !hasSymlink {
			t.Error("ContainsSymlinkFrom() should detect symlink in path")
		}
	})

	t.Run("symlink at leaf", func(t *testing.T) {
		tmpDir := t.TempDir()
		realFile := filepath.Join(tmpDir, "real.txt")
		linkFile := filepath.Join(tmpDir, "link.txt")

		if err := os.WriteFile(realFile, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		if err := os.Symlink(realFile, linkFile); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		hasSymlink, err := ContainsSymlinkFrom(linkFile, tmpDir)
		if err != nil {
			t.Errorf("ContainsSymlinkFrom() unexpected error: %v", err)
		}
		if !hasSymlink {
			t.Error("ContainsSymlinkFrom() should detect symlink at leaf")
		}
	})
}

func TestValidateRegularFile(t *testing.T) {
	t.Run("valid regular file", func(t *testing.T) {
		tmpDir := t.TempDir()
		subDir := filepath.Join(tmpDir, "profiles")
		testFile := filepath.Join(subDir, "test.yaml")

		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		result, err := ValidateRegularFile(tmpDir, "profiles/test.yaml")
		if err != nil {
			t.Errorf("ValidateRegularFile() unexpected error: %v", err)
		}
		if result != testFile {
			t.Errorf("ValidateRegularFile() = %q, want %q", result, testFile)
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

		_, err := ValidateRegularFile(tmpDir, "link.yaml")
		if err == nil {
			t.Error("ValidateRegularFile() should reject symlinks")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error should mention 'symlink', got: %v", err)
		}
	})

	t.Run("directory rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		subDir := filepath.Join(tmpDir, "profiles")
		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		_, err := ValidateRegularFile(tmpDir, "profiles")
		if err == nil {
			t.Error("ValidateRegularFile() should reject directories")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("error should mention 'not a regular file', got: %v", err)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := ValidateRegularFile(tmpDir, "nonexistent.yaml")
		if err == nil {
			t.Error("ValidateRegularFile() should reject non-existent files")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error should mention 'does not exist', got: %v", err)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := ValidateRegularFile(tmpDir, "../../../etc/passwd")
		if err == nil {
			t.Error("ValidateRegularFile() should reject path traversal")
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

		_, err := ValidateRegularFile(tmpDir, "profiles/test.yaml")
		if err == nil {
			t.Error("ValidateRegularFile() should reject symlink in directory path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error should mention 'symlink', got: %v", err)
		}
	})
}
