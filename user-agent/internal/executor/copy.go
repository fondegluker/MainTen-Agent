package executor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CopyToStorage copies a file from a network path to the local storage directory.
// It validates the source path, file extension, and size before copying.
func CopyToStorage(networkPath, storageDir string, maxFileSizeMB int, allowedExts []string) (string, error) {
	// Validate network path starts with \\
	networkPath = strings.TrimSpace(networkPath)
	if !strings.HasPrefix(networkPath, "\\\\") {
		return "", fmt.Errorf("source must be a UNC path (\\\\server\\share\\file)")
	}

	// Extract filename and clean it to prevent path traversal
	filename := filepath.Base(networkPath)
	if filename == "." || filename == "" {
		return "", fmt.Errorf("invalid filename in path")
	}

	// Additional path traversal check
	if strings.Contains(filename, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}

	// Validate extension
	ext := strings.ToLower(filepath.Ext(filename))
	allowed := false
	for _, allowedExt := range allowedExts {
		if ext == strings.ToLower(allowedExt) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("file extension %s not allowed, allowed: %v", ext, allowedExts)
	}

	// Check file size before copying
	srcFile, err := os.Open(networkPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat source file: %w", err)
	}

	maxSize := int64(maxFileSizeMB) * 1024 * 1024
	if srcInfo.Size() > maxSize {
		return "", fmt.Errorf("file size %dMB exceeds maximum %dMB", srcInfo.Size()/1024/1024, maxFileSizeMB)
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Destination path
	destPath := filepath.Join(storageDir, filename)

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Copy file
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		os.Remove(destPath) // Clean up on error
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	return destPath, nil
}