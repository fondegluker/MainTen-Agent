package gui

import (
	"log"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// manager owns the single persistent GUI thread and root window through which
// all dialogs are created. walk requires that every window and widget be
// created and driven from one OS thread that runs the message loop, and that
// the ComCtl32 common controls be initialized on that thread. We satisfy this
// by keeping a hidden root MainWindow alive for the process lifetime and
// marshaling all dialog creation onto it via Synchronize.
type manager struct {
	root  *walk.MainWindow
	ready chan struct{}
}

var mgr = &manager{ready: make(chan struct{})}

// initCommonControls registers the ComCtl32 control classes that walk relies
// on (tooltips, tabs, links, standard controls). Without this, building any
// widget fails with "TTM_ADDTOOL failed" because the tooltip class is not
// registered. This is normally done via an application manifest requesting
// ComCtl32 v6; calling InitCommonControlsEx explicitly achieves the same for a
// manifest-less GUI binary.
func initCommonControls() {
	var icc win.INITCOMMONCONTROLSEX
	icc.DwSize = uint32(unsafe.Sizeof(icc))
	icc.DwICC = win.ICC_STANDARD_CLASSES |
		win.ICC_BAR_CLASSES |
		win.ICC_TAB_CLASSES |
		win.ICC_LISTVIEW_CLASSES |
		win.ICC_TREEVIEW_CLASSES |
		win.ICC_PROGRESS_CLASS |
		win.ICC_UPDOWN_CLASS |
		win.ICC_LINK_CLASS
	if !win.InitCommonControlsEx(&icc) {
		log.Printf("[GUI] warning: InitCommonControlsEx failed; some controls may not render")
	}
}

// Run initializes the GUI subsystem and runs the walk message loop. It MUST be
// called from the process main goroutine (which is locked to the main OS
// thread) and it blocks until Shutdown is called.
func Run() error {
	initCommonControls()

	root, err := walk.NewMainWindow()
	if err != nil {
		return err
	}
	// Keep the root window hidden; it exists only to own the message loop.
	root.SetVisible(false)
	mgr.root = root

	// Signal that the GUI thread is ready to accept Synchronize calls.
	close(mgr.ready)

	// Run pumps the message loop until the root window is closed.
	root.Run()
	return nil
}

// Shutdown closes the root window, which causes Run to return and the message
// loop to exit. Safe to call from any goroutine.
func Shutdown() {
	if mgr.root == nil {
		return
	}
	mgr.root.Synchronize(func() {
		_ = mgr.root.Close()
	})
}

// onGUIThread runs f on the GUI thread once the subsystem is ready. If the GUI
// subsystem never started it logs and drops the work rather than blocking
// forever.
func onGUIThread(f func()) {
	<-mgr.ready
	if mgr.root == nil {
		log.Printf("[GUI] GUI subsystem not initialized; dropping dialog request")
		return
	}
	mgr.root.Synchronize(f)
}
