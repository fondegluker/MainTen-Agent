package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LogonWithProfile causes the system to load the user profile.
const LogonWithProfile uint32 = 0x00000001

// CreateProcessWithLogonW starts a new process with the specified credentials.
// It uses CreateProcessWithLogonW from advapi32.dll.
func CreateProcessWithLogon(username, domain, password, exePath, args, workDir string) error {
	// Convert strings to UTF-16 pointers
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return fmt.Errorf("failed to convert username: %w", err)
	}

	domainPtr, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return fmt.Errorf("failed to convert domain: %w", err)
	}

	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("failed to convert password: %w", err)
	}

	exePtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return fmt.Errorf("failed to convert exe path: %w", err)
	}

	var cmdLine *uint16
	var cmdLineArg uintptr
	if args != "" {
		cmdLine, err = windows.UTF16PtrFromString(args)
		if err != nil {
			return fmt.Errorf("failed to convert args: %w", err)
		}
		cmdLineArg = uintptr(unsafe.Pointer(cmdLine))
	}

	var workDirPtr *uint16
	var workDirArg uintptr
	if workDir != "" {
		workDirPtr, err = windows.UTF16PtrFromString(workDir)
		if err != nil {
			return fmt.Errorf("failed to convert work dir: %w", err)
		}
		workDirArg = uintptr(unsafe.Pointer(workDirPtr))
	}

	// Initialize STARTUPINFO
	si := windows.StartupInfo{
		Cb:      uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:   windows.STARTF_USESTDHANDLES,
		ShowWindow: windows.SW_HIDE,
	}

	// Initialize PROCESS_INFORMATION
	var pi windows.ProcessInformation

	// Call CreateProcessWithLogonW
	// BOOL CreateProcessWithLogonW(
	//   LPCWSTR lpUsername,
	//   LPCWSTR lpDomain,
	//   LPCWSTR lpPassword,
	//   DWORD dwLogonFlags,
	//   LPCWSTR lpApplicationName,
	//   LPWSTR lpCommandLine,
	//   DWORD dwCreationFlags,
	//   LPVOID lpEnvironment,
	//   LPCWSTR lpCurrentDirectory,
	//   LPSTARTUPINFOW lpStartupInfo,
	//   LPPROCESS_INFORMATION lpProcessInformation
	// );
	advapi32 := windows.MustLoadDLL("advapi32.dll")

	createProcessWithLogonW, err := advapi32.FindProc("CreateProcessWithLogonW")
	if err != nil {
		return fmt.Errorf("failed to find CreateProcessWithLogonW: %w", err)
	}

	ret, _, _ := createProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(LogonWithProfile),
		uintptr(unsafe.Pointer(exePtr)),
		cmdLineArg,
		uintptr(windows.CREATE_UNICODE_ENVIRONMENT),
		0,
		workDirArg,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return fmt.Errorf("CreateProcessWithLogonW failed")
	}

	// Close handles to avoid leaks
	if pi.Thread != 0 {
		windows.CloseHandle(windows.Handle(pi.Thread))
	}
	if pi.Process != 0 {
		windows.CloseHandle(windows.Handle(pi.Process))
	}

	return nil
}