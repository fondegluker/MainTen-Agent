package gui

import (
	"os/exec"
	"strings"
)

// ShowMessage displays a simple message box using Windows utilities.
// This is a minimal implementation for the prototype.
func ShowMessage(title, body string, links []Link, buttons []Button, fontFamily string, fontSize int) {
	// For now, just log the message since GUI is complex
	// In production, you would use proper Windows GUI libraries
	
	// Build message text
	var sb strings.Builder
	sb.WriteString("Title: ")
	sb.WriteString(title)
	sb.WriteString("\n")
	sb.WriteString("Message: ")
	sb.WriteString(body)
	sb.WriteString("\n")
	
	if len(links) > 0 {
		sb.WriteString("Links:\n")
		for _, link := range links {
			sb.WriteString("  ")
			sb.WriteString(link.Text)
			sb.WriteString(": ")
			sb.WriteString(link.URL)
			sb.WriteString("\n")
		}
	}
	
	if len(buttons) > 0 {
		sb.WriteString("Buttons: ")
		for i, btn := range buttons {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(btn.Text)
		}
		sb.WriteString("\n")
	}
}