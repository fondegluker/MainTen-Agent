package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ANSI escape sequence processing for the given
// console handle (stdout). Windows 10 1511+ supports this via the
// ENABLE_VIRTUAL_TERMINAL_PROCESSING console mode flag; without it, ANSI color
// codes are printed literally instead of being interpreted.
//
// Returns true if the console now interprets ANSI sequences.
func enableVirtualTerminal() bool {
	handle := windows.Handle(os.Stdout.Fd())

	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		// Not a console (e.g. output redirected to a file/pipe).
		return false
	}

	const enableVirtualTerminalProcessing = 0x0004
	if mode&enableVirtualTerminalProcessing != 0 {
		return true // already enabled
	}

	if err := windows.SetConsoleMode(handle, mode|enableVirtualTerminalProcessing); err != nil {
		return false
	}
	return true
}

// stdoutIsConsole reports whether stdout is attached to a real console (as
// opposed to a file or pipe). Used to decide whether to emit ANSI colors.
func stdoutIsConsole() bool {
	var mode uint32
	err := windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode)
	return err == nil
}
