package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const firewallRuleName = "MainTen User Agent"

// addFirewallRule creates an inbound allow rule for the agent TCP port using
// netsh advfirewall. Requires administrative privileges. Any pre-existing rule
// with the same name is removed first so the port stays in sync with config.
func addFirewallRule(port int, profile string) error {
	if profile == "" {
		profile = "private"
	}
	// Remove stale rule (ignore errors: it may not exist).
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+firewallRuleName).Run()

	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+firewallRuleName,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		"localport="+strconv.Itoa(port),
		"profile="+profile,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add rule: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeFirewallRule deletes the inbound rule (used by -uninstall).
func removeFirewallRule() error {
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+firewallRuleName).Run()
	return nil
}

// startAgent launches the installed agent detached from the installer so it
// keeps running after the installer exits.
func startAgent(destDir string) error {
	exe := destDir + `\agent.exe`
	cfg := destDir + `\agent.toml`
	cmd := exec.Command(exe, "-config", cfg)
	cmd.Dir = destDir
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	// Detach: do not wait. The agent runs its own message loop.
	_ = cmd.Process.Release()
	return nil
}

// healthCheck polls the agent”s /api/health endpoint until success or timeout.
// When caFile is provided and the URL is HTTPS, the agent certificate is
// validated against that CA; otherwise a plain client is used.
func healthCheck(baseURL, caFile string, timeout time.Duration) error {
	client, err := buildHealthClient(baseURL, caFile)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(400 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return fmt.Errorf("agent did not become healthy: %w", lastErr)
}

// buildHealthClient returns an HTTP client that trusts caFile for HTTPS URLs.
func buildHealthClient(baseURL, caFile string) (*http.Client, error) {
	transport := &http.Transport{}
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") && caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certs parsed from CA %s", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: transport}, nil
}

// checkNetworkReachable verifies the agent port is reachable on a non-loopback
// address, confirming firewall/binding allow inbound connections. It uses the
// health endpoint against the machine hostname. A failure here is reported as a
// warning rather than a hard error, because a host may intentionally restrict
// access via the agent”s own IP allowlist.
func checkNetworkReachable(port int, https bool, caFile string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "", fmt.Errorf("cannot resolve hostname")
	}
	scheme := "http"
	if https {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, hostname, port)

	// For HTTPS the cert SANs include the hostname, so CA validation works.
	if err := healthCheck(url, caFile, 4*time.Second); err != nil {
		return url, err
	}
	return url, nil
}
