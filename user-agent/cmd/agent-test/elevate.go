package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// isElevated reports whether the current process runs with an elevated
// (administrator) token. Creating SMB shares, local users and editing ACLs all
// require this.
func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var elevation struct{ TokenIsElevated uint32 }
	var outLen uint32
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&outLen,
	)
	if err != nil {
		return false
	}
	return elevation.TokenIsElevated != 0
}

// relaunchElevated re-launches the current executable with the same arguments
// through the UAC "runas" verb, requesting administrative privileges. It
// returns true if a relaunch was initiated (the caller should then exit).
func relaunchElevated() (bool, error) {
	exePath, err := os.Executable()
	if err != nil {
		return false, err
	}
	exePath, _ = filepath.Abs(exePath)

	// Rebuild the argument string (skip argv[0]). Quote args containing spaces.
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		args = append(args, a)
	}
	params := strings.Join(args, " ")

	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exePath)
	var paramPtr *uint16
	if params != "" {
		paramPtr, _ = syscall.UTF16PtrFromString(params)
	}
	// Show the console window so the user sees test output.
	const swShowNormal = 1

	err = windows.ShellExecute(0, verb, file, paramPtr, nil, swShowNormal)
	if err != nil {
		return false, fmt.Errorf("ShellExecute runas failed: %w", err)
	}
	return true, nil
}
