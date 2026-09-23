package gui

import (
	"fmt"
	"log"

	"github.com/lxn/walk"
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

// MessageDialog displays a simple message dialog with links and buttons.
type MessageDialog struct {
	Title   string
	Body    string
	Links   []Link
	Buttons []Button
}

// ShowMessage displays a modal message window with links and buttons.
func ShowMessage(title, body string, links []Link, buttons []Button, fontFamily string, fontSize int) {
	// Run in the GUI thread
	walk.Synchronize(func() {
		dlg := &walk.Dialog{
			Title:  title,
			Layout: walk.NewVBoxLayout(),
		}

		if _, err := walk.NewDialog(dlg); err != nil {
			log.Printf("Error creating dialog: %v", err)
			return
		}

		// Add body text
		label, err := walk.NewLabel(dlg)
		if err != nil {
			log.Printf("Error creating label: %v", err)
			return
		}
		label.SetText(body)

		// Add links if present
		if len(links) > 0 {
			for _, link := range links {
				linkLabel, err := walk.NewLinkLabel(dlg)
				if err != nil {
					continue
				}
				linkLabel.SetText(fmt.Sprintf(`<a href="%s">%s</a>`, link.URL, link.Text))
				linkLabel.LinkActivated().Attach(func(link *walk.LinkActionEventArgs) {
					OpenBrowser(link.URL())
				})
			}
		}

		// Add buttons
		if len(buttons) > 0 {
			buttonContainer, err := walk.NewHBoxLayout()
			if err != nil {
				log.Printf("Error creating button container: %v", err)
			} else {
				dlg.SetLayout(buttonContainer)
				for _, btn := range buttons {
					button, err := walk.NewPushButton(dlg)
					if err != nil {
						continue
					}
					button.SetText(btn.Text)
					button.Clicked().Attach(func() {
						// TODO: Handle callback if needed
						dlg.Accept()
					})
				}
			}
		}

		// Show dialog
		dlg.Run()
	})
}