package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// ANSI colors for console output.
const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cGreen  = "\x1b[92m"
	cRed    = "\x1b[91m"
	cYellow = "\x1b[93m"
	cCyan   = "\x1b[96m"
	cGray   = "\x1b[90m"
)

var useColor bool

// initConsole enables ANSI processing on the Windows console and decides
// whether color may be used.
func initConsole() {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return // not a console
	}
	const enableVT = 0x0004
	if mode&enableVT == 0 {
		if err := windows.SetConsoleMode(h, mode|enableVT); err != nil {
			return
		}
	}
	useColor = true
}

func colorize(code, s string) string {
	if useColor {
		return code + s + cReset
	}
	return s
}

// step prints a numbered step header.
func step(n int, title string) {
	fmt.Printf("\n%s %s\n", colorize(cCyan+cBold, fmt.Sprintf("[%d]", n)), colorize(cBold, title))
}

func ok(msg string)      { fmt.Printf("    %s %s\n", colorize(cGreen, "OK"), msg) }
func warn(msg string)    { fmt.Printf("    %s %s\n", colorize(cYellow, "WARN"), msg) }
func failMsg(msg string) { fmt.Printf("    %s %s\n", colorize(cRed, "FAIL"), msg) }
func info(msg string)    { fmt.Printf("    %s\n", colorize(cGray, msg)) }

// banner prints the installer title.
func banner(title string) {
	fmt.Printf("\n%s\n", colorize(cCyan+cBold, "=== "+title+" ==="))
}

// hideConsoleWindow hides the console window associated with this process.
// Used in -silent mode so the installer runs invisibly. If there is no console
// (already detached), this is a no-op.
func hideConsoleWindow() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	showWindow := user32.NewProc("ShowWindow")
	const swHide = 0
	showWindow.Call(hwnd, swHide)
}
