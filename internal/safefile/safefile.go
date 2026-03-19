//go:build !windows

// Package safefile provides secure file operations with symlink protection.
package safefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack-tool-validate/internal/limits"
	"golang.org/x/sys/unix"
)

// ReadFile reads a file with size limit enforcement and symlink protection.
func ReadFile(path string, limit limits.SizeLimit) ([]byte, error) {
	maxSize := limit.Bytes()

	// Open with O_NOFOLLOW to refuse symlinks atomically
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("refusing to read symlink: %s", path)
		}
		return nil, err
	}

	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()

	// Check file size via fstat on open fd (race-free)
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file %s exceeds maximum size (%d bytes > %d bytes)",
			filepath.Base(path), info.Size(), maxSize)
	}

	// Use LimitReader as defense-in-depth
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file %s exceeded maximum size during read (%d bytes)",
			filepath.Base(path), maxSize)
	}

	return data, nil
}

// ValidatePath validates that relPath stays within baseDir.
// Returns the absolute path if valid.
func ValidatePath(baseDir, relPath string) (string, error) {
	// Reject absolute paths
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("absolute paths not allowed: %s", relPath)
	}

	// Clean and check for traversal
	cleaned := filepath.Clean(relPath)
	if strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path traversal not allowed: %s", relPath)
	}

	// Join and get absolute path
	joined := filepath.Join(baseDir, cleaned)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	// Verify result is under baseDir
	baseDirWithSep := absBaseDir
	if !strings.HasSuffix(baseDirWithSep, string(filepath.Separator)) {
		baseDirWithSep += string(filepath.Separator)
	}

	if !strings.HasPrefix(absJoined+string(filepath.Separator), baseDirWithSep) &&
		absJoined != absBaseDir {
		return "", fmt.Errorf("path escapes base directory: %s", relPath)
	}

	return absJoined, nil
}

// ContainsSymlinkFrom checks if any component in the path from root is a symlink.
func ContainsSymlinkFrom(path, root string) (bool, error) {
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false, err
	}

	startPath, err := resolveSymlinkStartPath(absPath, root)
	if err != nil {
		return false, err
	}

	rel, err := filepath.Rel(startPath, absPath)
	if err != nil {
		return false, err
	}

	if rel == "." {
		return isSymlinkIfExists(startPath)
	}

	components := strings.Split(rel, string(filepath.Separator))
	current := startPath
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}

		current = filepath.Join(current, component)

		fi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, err
		}

		if fi.Mode()&os.ModeSymlink != 0 {
			return true, nil
		}
	}

	return false, nil
}

// ValidateRegularFile validates that relPath is a regular file within root.
func ValidateRegularFile(root, relPath string) (string, error) {
	abs, err := ValidatePath(root, relPath)
	if err != nil {
		return "", err
	}

	hasSymlink, err := ContainsSymlinkFrom(abs, root)
	if err != nil {
		return "", err
	}
	if hasSymlink {
		return "", fmt.Errorf("symlink in path: %s", relPath)
	}

	info, err := os.Lstat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %s", relPath)
		}
		return "", fmt.Errorf("cannot stat file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("path is a symlink: %s", relPath)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s (mode: %s)", relPath, info.Mode())
	}

	return abs, nil
}

func resolveSymlinkStartPath(absPath, root string) (string, error) {
	if root == "" {
		return "/", nil
	}
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	rootWithSep := absRoot
	if !strings.HasSuffix(rootWithSep, string(filepath.Separator)) {
		rootWithSep += string(filepath.Separator)
	}
	if strings.HasPrefix(absPath, rootWithSep) || absPath == absRoot {
		return absRoot, nil
	}
	return "/", nil
}

func isSymlinkIfExists(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return fi.Mode()&os.ModeSymlink != 0, nil
}
