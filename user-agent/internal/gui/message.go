package gui

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
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

// ShowMessage displays a modal message window with links and buttons.
// This runs in a separate goroutine to not block the HTTP server.
func ShowMessage(title, body string, links []Link, buttons []Button, fontFamily string, fontSize int) {
	// Use walk.ThreadRun for proper GUI initialization in goroutine
	walk.ThreadRun(func() {
		// Create a simple dialog window
		mw, err := declarative.MainWindow{
			Title:   title,
			MinSize: Size{400, 200},
			Layout:  VBox{},
		}.Create()
		if err != nil {
			fmt.Printf("Error creating window: %v\n", err)
			return
		}

		// Create container with padding
		container, err := declarative.GroupBox{
			Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
		}.Create(mw)
		if err != nil {
			fmt.Printf("Error creating container: %v\n", err)
			mw.Dispose()
			return
		}

		// Message body
		bodyLabel, err := declarative.Label{
			Text:      body,
			TextColor: 0x000000,
			Font:      Font{Family: fontFamily, PointSize: fontSize},
		}.Create(container)
		if err != nil {
			fmt.Printf("Error creating label: %v\n", err)
		}
		bodyLabel.SetParent(container)

		// Links - only if we have any
		if len(links) > 0 {
			var linkText strings.Builder
			for _, link := range links {
				linkText.WriteString(fmt.Sprintf(`<a href="%s">%s</a>`, link.URL, link.Text))
			}
			
			linkLabel, err := declarative.LinkLabel{
				Text:      linkText.String(),
				TextColor: 0x0000FF,
				Font:      Font{Family: fontFamily, PointSize: fontSize},
			}.Create(container)
			if err == nil {
				linkLabel.SetParent(container)
				linkLabel.LinkActivated().Attach(func(link *walk.LinkActionEventArgs) {
					OpenBrowser(link.URL())
				})
			}
		}

		// Spacer
		spacer := new(VSpacer)
		spacer.Create(container)
		spacer.SetParent(container)

		// Buttons in HBox
		buttonContainer, err := declarative.HBox{Spacing: 10}.Create(container)
		if err != nil {
			fmt.Printf("Error creating button container: %v\n", err)
		}
		buttonContainer.SetParent(container)

		// Add buttons
		for _, btn := range buttons {
			btn := btn // Capture for closure
			button, err := declarative.Button{
				Text: btn.Text,
			}.Create(buttonContainer)
			if err != nil {
				fmt.Printf("Error creating button: %v\n", err)
				continue
			}
			button.SetParent(buttonContainer)
			
			// Attach click handler
			button.Clicked().Attach(func() {
				// Send callback if present
				if btn.Callback != "" {
					go func() {
						http.Post(btn.Callback, "application/json", bytes.NewBufferString("{}"))
					}()
				}
				mw.Close()
			})
		}

		// Show and run
		mw.SetVisible(true)
		mw.Run()
	})
}