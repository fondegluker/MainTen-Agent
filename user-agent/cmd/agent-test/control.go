package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// agentControl manages the agent process and its config for the test run.
type agentControl struct {
	exePath      string
	configPath   string
	cmd          *exec.Cmd
	startedByUs  bool
	origConfig   []byte // original agent.toml contents, for restore
	configEdited bool
}

// randomToken returns a cryptographically random hex token.
func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var runAsTokenRe = regexp.MustCompile(`(?m)^\s*run_as_token\s*=\s*".*"\s*$`)

// ensureRunAsToken makes sure agent.toml has a non-empty run_as_token. If it is
// empty, a random token is generated and written, and the original config is
// remembered for restore. Returns the effective token and whether the config
// was modified.
func (a *agentControl) ensureRunAsToken() (token string, edited bool, err error) {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return "", false, fmt.Errorf("read config: %w", err)
	}
	a.origConfig = append([]byte(nil), data...)

	// Extract current value.
	current := extractTokenValue(string(data))
	if current != "" {
		return current, false, nil
	}

	// Generate a new token and substitute it.
	newTok, err := randomToken(24)
	if err != nil {
		return "", false, err
	}
	replacement := fmt.Sprintf(`run_as_token = "%s"`, newTok)

	var updated string
	if runAsTokenRe.MatchString(string(data)) {
		updated = runAsTokenRe.ReplaceAllString(string(data), replacement)
	} else {
		// No key present; the config always has one, but be defensive.
		updated = string(data) + "\r\n" + replacement + "\r\n"
	}

	if err := os.WriteFile(a.configPath, []byte(updated), 0644); err != nil {
		return "", false, fmt.Errorf("write config: %w", err)
	}
	a.configEdited = true
	return newTok, true, nil
}

// extractTokenValue returns the run_as_token value from a config string.
func extractTokenValue(cfg string) string {
	m := regexp.MustCompile(`(?m)^\s*run_as_token\s*=\s*"([^"]*)"`).FindStringSubmatch(cfg)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// restoreConfig writes back the original agent.toml if we changed it.
func (a *agentControl) restoreConfig() {
	if a.configEdited && a.origConfig != nil {
		_ = os.WriteFile(a.configPath, a.origConfig, 0644)
	}
}

// stopExisting terminates any already-running agent so we can start a fresh one
// that picks up the (possibly updated) config.
func stopExistingAgents(port int) {
	_ = exec.Command("taskkill", "/IM", "agent.exe", "/F").Run()
	waitPortFree(port, 8*time.Second)
}

// waitPortFree blocks until nothing accepts TCP on 127.0.0.1:port or timeout.
func waitPortFree(port int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(300 * time.Millisecond)
	}
}

// start launches the agent process from exePath.
func (a *agentControl) start() error {
	cmd := exec.Command(a.exePath, "-config", a.configPath)
	cmd.Dir = dirOf(a.exePath)
	// Inherit stdio so the agent''s early fatal errors are visible if any.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	a.cmd = cmd
	a.startedByUs = true
	return nil
}

// stop terminates the agent process we started.
func (a *agentControl) stop() {
	if a.startedByUs && a.cmd != nil && a.cmd.Process != nil {
		_ = a.cmd.Process.Kill()
		_, _ = a.cmd.Process.Wait()
	}
}

// waitReady polls GET /api/health until it succeeds or the timeout elapses.
func waitReady(c *agentClient, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res, err := c.health()
		if err == nil && res.status == 200 {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("agent did not become ready within %s", timeout)
}

func dirOf(path string) string {
	return filepath.Dir(path)
}
