package gui

import (
	"os/exec"
)

// OpenBrowser opens a URL in the default web browser.
// Uses Windows-specific command via rundll32.
func OpenBrowser(url string) error {
	// Use rundll32 url.dll,FileProtocolHandler to open URL
	// This is more reliable than exec.LookPath for browsers
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	return cmd.Start()
}