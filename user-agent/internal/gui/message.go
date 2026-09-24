package gui

import (
	"log"
)

// Link represents a clickable link in the message.
type Link struct {
	Text string
	URL  string
}

// Button represents a button with optional callback.
type Button struct {
	Text     string
	Callback string
}

// ShowMessage displays a simple message (placeholder implementation).
// For a production implementation, use proper Windows GUI libraries.
func ShowMessage(title, body string, links []Link, buttons []Button, fontFamily string, fontSize int) {
	log.Printf("[GUI] Message dialog would show:")
	log.Printf("[GUI]   Title: %s", title)
	log.Printf("[GUI]   Body: %s", body)
	
	for _, link := range links {
		log.Printf("[GUI]   Link: %s -> %s", link.Text, link.URL)
	}
	
	for _, button := range buttons {
		log.Printf("[GUI]   Button: %s", button.Text)
		if button.Callback != "" {
			log.Printf("[GUI]     Callback: %s", button.Callback)
		}
	}
}