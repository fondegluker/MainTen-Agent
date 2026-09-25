package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// testEnv holds the paths and share information created for the test run.
type testEnv struct {
	root      string // local filesystem root that backs the share
	shareName string // SMB share name
	uncBase   string // \\HOST\shareName
	host      string // host used in UNC paths (defaults to 127.0.0.1)

	exeName string
	batName string
	cmdName string
	msiName string

	createdShare bool
}

// uncPath returns the UNC path for a file in the share.
func (e *testEnv) uncPath(name string) string {
	return fmt.Sprintf(`\\%s\%s\%s`, e.host, e.shareName, name)
}

// resolveEveryoneName resolves the well-known Everyone SID (S-1-1-0) to its
// localized account name (e.g. "Everyone" on English Windows, "Все" on
// Russian). net share /grant requires a name rather than a SID.
func resolveEveryoneName() string {
	sid, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return "Everyone"
	}
	account, _, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return "Everyone"
	}
	return account
}

// setupTestEnv creates a backing directory, populates it with test artifacts
// for every allowed extension, and publishes it as an SMB share.
//
// The .exe is a copy of the system timeout.exe (a small, self-terminating
// console program). The .bat/.cmd write a marker file so a successful launch is
// observable. The .msi is a placeholder used to exercise copy + extension
// validation; msiexec rejects it quickly, which is enough to prove routing.
func setupTestEnv(host, shareName string) (*testEnv, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	root, err := os.MkdirTemp("", "agent-test-share-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	env := &testEnv{
		root:      root,
		shareName: shareName,
		host:      host,
		uncBase:   fmt.Sprintf(`\\%s\%s`, host, shareName),
		exeName:   "agent_test_tool.exe",
		batName:   "agent_test_script.bat",
		cmdName:   "agent_test_script.cmd",
		msiName:   "agent_test_package.msi",
	}

	// .exe: copy system timeout.exe, falling back to cmd.exe.
	sysExe := filepath.Join(os.Getenv("WINDIR"), "System32", "timeout.exe")
	if err := copyFile(sysExe, filepath.Join(root, env.exeName)); err != nil {
		sysExe = filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")
		if err2 := copyFile(sysExe, filepath.Join(root, env.exeName)); err2 != nil {
			return nil, fmt.Errorf("copy system exe: %v / %v", err, err2)
		}
	}

	// .bat and .cmd: drop a marker into %TEMP% so a launch is visible.
	batchBody := "@echo off\r\n" +
		"echo agent-test launched %~nx0 %DATE% %TIME% > \"%TEMP%\\agent_test_%~n0.marker\"\r\n" +
		"exit /b 0\r\n"
	if err := os.WriteFile(filepath.Join(root, env.batName), []byte(batchBody), 0644); err != nil {
		return nil, fmt.Errorf("write bat: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, env.cmdName), []byte(batchBody), 0644); err != nil {
		return nil, fmt.Errorf("write cmd: %w", err)
	}

	// .msi: placeholder content (not a real installer database).
	if err := os.WriteFile(filepath.Join(root, env.msiName), []byte("MSI-PLACEHOLDER"), 0644); err != nil {
		return nil, fmt.Errorf("write msi: %w", err)
	}

	if err := env.createShare(); err != nil {
		return env, fmt.Errorf("create share: %w", err)
	}
	return env, nil
}

// createShare publishes root as an SMB share via net share.
func (e *testEnv) createShare() error {
	_ = exec.Command("net", "share", e.shareName, "/delete", "/y").Run()

	everyone := resolveEveryoneName()
	out, err := exec.Command("net", "share",
		fmt.Sprintf("%s=%s", e.shareName, e.root),
		fmt.Sprintf("/grant:%s,READ", everyone),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	e.createdShare = true

	// Grant NTFS read to Everyone via SID (locale-independent).
	_ = exec.Command("icacls", e.root, "/grant", "*S-1-1-0:(OI)(CI)R", "/T", "/C").Run()
	return nil
}

// cleanup removes the share and temp directory.
func (e *testEnv) cleanup() {
	if e == nil {
		return
	}
	if e.createdShare {
		_ = exec.Command("net", "share", e.shareName, "/delete", "/y").Run()
	}
	if e.root != "" {
		_ = os.RemoveAll(e.root)
	}
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
