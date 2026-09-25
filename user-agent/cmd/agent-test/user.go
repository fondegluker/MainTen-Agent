package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// localUser represents a temporary local account created for run-as testing.
type localUser struct {
	name     string
	password string
	created  bool
}

// ensureLocalUser creates a temporary local user with a known password so the
// positive /api/run-as test has valid credentials to log on with. The account
// is added to the default Users group. Requires administrative privileges.
//
// The password must be <= 14 characters to avoid the interactive "longer than
// 14 characters" confirmation prompt that net.exe emits; we also pipe "Y" to
// stdin as a safety net in case any prompt still appears.
func ensureLocalUser(name, password string) (*localUser, error) {
	u := &localUser{name: name, password: password}

	// Delete any stale account first (ignore errors).
	_ = exec.Command("net", "user", name, "/delete").Run()

	cmd := exec.Command("net", "user", name, password, "/add",
		"/expires:never", "/passwordchg:no")
	cmd.Stdin = strings.NewReader("Y\r\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return u, fmt.Errorf("net user add: %v: %s", err, decodeOEM(out))
	}
	u.created = true
	return u, nil
}

// cleanup removes the temporary local user.
func (u *localUser) cleanup() {
	if u == nil || !u.created {
		return
	}
	_ = exec.Command("net", "user", u.name, "/delete").Run()
}

// decodeOEM trims console output for error messages. Console tools emit OEM
// codepage bytes; we keep it simple and just trim whitespace for logging.
func decodeOEM(b []byte) string {
	return strings.TrimSpace(string(b))
}
