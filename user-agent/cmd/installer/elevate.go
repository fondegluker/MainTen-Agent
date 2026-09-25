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
// (administrator) token. The firewall rule step requires this.
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

// relaunchElevated re-launches this executable with the same arguments through
// the UAC "runas" verb. Returns true if a relaunch was initiated (caller should
// then exit). An extra marker argument is appended so the elevated instance can
// detect it was spawned for elevation.
func relaunchElevated(extraArg string) (bool, error) {
	exePath, err := os.Executable()
	if err != nil {
		return false, err
	}
	exePath, _ = filepath.Abs(exePath)

	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		args = append(args, a)
	}
	if extraArg != "" {
		args = append(args, extraArg)
	}
	params := strings.Join(args, " ")

	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exePath)
	var paramPtr *uint16
	if params != "" {
		paramPtr, _ = syscall.UTF16PtrFromString(params)
	}
	const swShowNormal = 1

	if err := windows.ShellExecute(0, verb, file, paramPtr, nil, swShowNormal); err != nil {
		return false, fmt.Errorf("ShellExecute runas failed: %w", err)
	}
	return true, nil
}

// shellExecuteAndWait runs ShellExecuteEx with the given verb/file/params,
// waits for the spawned process to exit, and returns an error if it failed to
// launch or exited non-zero. Used to run an elevated child and block on it.
func shellExecuteAndWait(verb, file, params *uint16) error {
	const (
		seeMaskNoCloseProcess = 0x00000040
		swHide                = 0
	)
	type shellExecuteInfo struct {
		cbSize         uint32
		fMask          uint32
		hwnd           windows.Handle
		lpVerb         *uint16
		lpFile         *uint16
		lpParameters   *uint16
		lpDirectory    *uint16
		nShow          int32
		hInstApp       windows.Handle
		lpIDList       uintptr
		lpClass        *uint16
		hkeyClass      windows.Handle
		dwHotKey       uint32
		hIconOrMonitor windows.Handle
		hProcess       windows.Handle
	}

	shell32 := windows.NewLazySystemDLL("shell32.dll")
	proc := shell32.NewProc("ShellExecuteExW")

	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        swHide,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))

	ret, _, err := proc.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return fmt.Errorf("ShellExecuteEx failed: %v", err)
	}
	if info.hProcess == 0 {
		return fmt.Errorf("no process handle returned")
	}
	defer windows.CloseHandle(info.hProcess)

	// Wait for the elevated child to finish.
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return fmt.Errorf("wait failed: %w", err)
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &exitCode); err != nil {
		return fmt.Errorf("get exit code: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("elevated step exited with code %d", exitCode)
	}
	return nil
}
