package gui

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/lxn/walk"
	declarative "github.com/lxn/walk/declarative"
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

// ShowMessage displays a modeless message window with links and buttons.
//
// The window is created on the shared GUI thread via the manager, so this
// function is safe to call from any goroutine (e.g. an HTTP handler) and does
// not block the caller. The window owns itself: it stays open until the user
// clicks a button or closes it.
func ShowMessage(title, body string, links []Link, buttons []Button, fontFamily string, fontSize int) {
	onGUIThread(func() {
		if err := buildWindow(title, body, links, buttons, fontFamily, fontSize); err != nil {
			log.Printf("[GUI] failed to show message window: %v", err)
		}
	})
}

// buildWindow constructs and shows the dialog. It must run on the GUI thread.
func buildWindow(title, body string, links []Link, buttons []Button, fontFamily string, fontSize int) error {
	var mw *walk.MainWindow

	// Build LinkLabel markup. LinkLabel renders <a href="...">text</a> anchors
	// and reports the href back via the LinkActivated event.
	var linkText strings.Builder
	for i, link := range links {
		if i > 0 {
			linkText.WriteString("   ")
		}
		linkText.WriteString(fmt.Sprintf(`<a id="%d" href="%s">%s</a>`, i, link.URL, link.Text))
	}

	font := declarative.Font{Family: fontFamily, PointSize: fontSize}

	children := []declarative.Widget{
		declarative.Label{Text: body, Font: font},
	}

	if linkText.Len() > 0 {
		children = append(children, declarative.LinkLabel{
			Text: linkText.String(),
			Font: font,
			OnLinkActivated: func(link *walk.LinkLabelLink) {
				if err := OpenBrowser(link.URL()); err != nil {
					log.Printf("[GUI] failed to open browser for %s: %v", link.URL(), err)
				}
			},
		})
	}

	// Right-aligned button row.
	buttonWidgets := []declarative.Widget{declarative.HSpacer{}}
	for _, btn := range buttons {
		btn := btn
		buttonWidgets = append(buttonWidgets, declarative.PushButton{
			Text: btn.Text,
			OnClicked: func() {
				if btn.Callback != "" {
					go sendCallback(btn.Callback)
				}
				if mw != nil {
					_ = mw.Close()
				}
			},
		})
	}
	if len(buttons) == 0 {
		buttonWidgets = append(buttonWidgets, declarative.PushButton{
			Text: "OK",
			OnClicked: func() {
				if mw != nil {
					_ = mw.Close()
				}
			},
		})
	}

	children = append(children,
		declarative.VSpacer{},
		declarative.Composite{
			Layout:   declarative.HBox{MarginsZero: true},
			Children: buttonWidgets,
		},
	)

	// Create (do not Run) the window so it shares the manager”s message loop
	// instead of nesting a second one.
	if err := (declarative.MainWindow{
		AssignTo: &mw,
		Title:    title,
		MinSize:  declarative.Size{Width: 400, Height: 180},
		Layout: declarative.VBox{
			Margins: declarative.Margins{Left: 12, Top: 12, Right: 12, Bottom: 12},
		},
		Children: children,
	}).Create(); err != nil {
		return err
	}

	// Dispose the window when it closes so its resources are freed.
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// Defer disposal until after the close completes.
		go func() {
			mw.Synchronize(func() { mw.Dispose() })
		}()
	})

	mw.SetVisible(true)
	mw.Activate()
	return nil
}

// sendCallback posts an empty JSON body to the callback URL. Failures are
// logged but do not affect the dialog.
func sendCallback(url string) {
	resp, err := http.Post(url, "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		log.Printf("[GUI] callback POST to %s failed: %v", url, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[GUI] callback POST to %s returned %s", url, resp.Status)
}
