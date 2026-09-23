package executor

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunLocal runs an executable from the local storage.
// It handles .exe, .bat, .cmd, and .msi files appropriately.
func RunLocal(exePath string, args []string) error {
	ext := strings.ToLower(filepath.Ext(exePath))

	var cmd *exec.Cmd

	switch ext {
	case ".msi":
		// Use msiexec for MSI files
		msiArgs := []string{"/i", exePath}
		if len(args) > 0 {
			msiArgs = append(msiArgs, args...)
		} else {
			msiArgs = append(msiArgs, "/quiet", "/norestart")
		}
		cmd = exec.Command("msiexec", msiArgs...)
	case ".bat", ".cmd":
		// Use cmd.exe /c for batch files
		batchArgs := append([]string{"/c", exePath}, args...)
		cmd = exec.Command("cmd.exe", batchArgs...)
	default:
		// Regular executable
		cmd = exec.Command(exePath, args...)
	}

	// Set working directory to the executable's directory
	cmd.Dir = filepath.Dir(exePath)

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	// Don't wait for the process - let it run independently
	// The process will be reaped automatically when it terminates
	go func() {
		cmd.Wait()
	}()

	return nil
}