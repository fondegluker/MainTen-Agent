package executor

import (
	"fmt"
	"path/filepath"

	"github.com/maintent-agent/user-agent/internal/winapi"
)

// RunWithCredentials runs an executable with the specified credentials.
// It uses CreateProcessWithLogonW to start the process under a different user.
func RunWithCredentials(exePath string, args []string, username, domain, password string) error {
	// Build command line
	var cmdLine string
	if len(args) > 0 {
		cmdLine = exePath + " " + args[0]
	}

	// Set working directory to the executable's directory
	workDir := filepath.Dir(exePath)

	// For Entra ID (Azure AD) accounts:
	// - If domain is empty or "AzureAD", use UPN format (user@domain.com)
	// - Otherwise use domain\username format
	var user, dom string
	if domain == "" || domain == "AzureAD" {
		// Treat username as UPN
		user = username
		dom = ""
	} else {
		user = username
		dom = domain
	}

	if err := winapi.CreateProcessWithLogon(user, dom, password, exePath, cmdLine, workDir); err != nil {
		return fmt.Errorf("failed to create process with logon: %w", err)
	}

	return nil
}