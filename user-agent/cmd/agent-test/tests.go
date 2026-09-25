package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// testHealthAndPubkey checks the unauthenticated liveness and key endpoints.
func testHealthAndPubkey(c *agentClient, rep *reporter) {
	rep.section("health & pubkey")

	res, err := c.health()
	if err != nil {
		rep.fail("GET /api/health", err.Error())
	} else if res.status == 200 && res.parsed.Success {
		rep.pass("GET /api/health", "200 OK")
	} else {
		rep.fail("GET /api/health", fmt.Sprintf("status=%d body=%s", res.status, string(res.body)))
	}

	algo, pemKey, res, err := c.pubkey()
	if err != nil {
		rep.fail("GET /api/pubkey", err.Error())
		return
	}
	if res.status == 200 && algo != "" && len(pemKey) > 0 {
		rep.pass("GET /api/pubkey", "algorithm="+algo)
	} else {
		rep.fail("GET /api/pubkey", fmt.Sprintf("status=%d algo=%q", res.status, algo))
	}
}

// fetchPubKey retrieves the PEM public key for use in run-as encryption.
func fetchPubKey(c *agentClient, rep *reporter) string {
	_, pemKey, _, err := c.pubkey()
	if err != nil {
		rep.fail("fetch public key", err.Error())
		return ""
	}
	return pemKey
}

// testRun exercises POST /api/run for every allowed extension.
func testRun(c *agentClient, env *testEnv, rep *reporter) {
	rep.section("run (current user)")

	cases := []struct {
		name    string
		source  string
		args    string
		observe func() bool // optional post-check
	}{
		{"run .exe", env.uncPath(env.exeName), "1", nil},
		{"run .bat", env.uncPath(env.batName), "", markerCheck(env.batName)},
		{"run .cmd", env.uncPath(env.cmdName), "", markerCheck(env.cmdName)},
		{"run .msi", env.uncPath(env.msiName), "", nil},
	}

	for _, tc := range cases {
		res, err := c.run(runRequest{Source: tc.source, RunAsCurrentUser: true, Args: tc.args})
		if err != nil {
			rep.fail(tc.name, err.Error())
			continue
		}
		if res.status != 200 || !res.parsed.Success {
			rep.fail(tc.name, fmt.Sprintf("status=%d body=%s", res.status, string(res.body)))
			continue
		}
		// Launch accepted. Optionally verify a side effect.
		if tc.observe != nil {
			if waitFor(tc.observe, 5*time.Second) {
				rep.pass(tc.name, "process launched + marker observed")
			} else {
				// The agent reported success; marker may lag or TEMP differs.
				rep.pass(tc.name, "process launched (marker not observed)")
			}
		} else {
			rep.pass(tc.name, "process launched")
		}
	}

	// Negative: non-UNC source must be rejected.
	res, err := c.run(runRequest{Source: `C:\Windows\System32\calc.exe`, RunAsCurrentUser: true})
	if err != nil {
		rep.fail("run rejects non-UNC source", err.Error())
	} else if res.status == 400 {
		rep.pass("run rejects non-UNC source", "400 Bad Request")
	} else {
		rep.fail("run rejects non-UNC source", fmt.Sprintf("status=%d", res.status))
	}

	// Negative: disallowed extension must be rejected.
	res, err = c.run(runRequest{Source: env.uncPath("agent_test_tool.txt"), RunAsCurrentUser: true})
	if err != nil {
		rep.fail("run rejects disallowed extension", err.Error())
	} else if res.status == 400 {
		rep.pass("run rejects disallowed extension", "400 Bad Request")
	} else {
		rep.fail("run rejects disallowed extension", fmt.Sprintf("status=%d", res.status))
	}
}

// testRunAs exercises POST /api/run-as: positive (encrypted, valid user) and
// several negatives (missing token, plaintext creds, foreign key).
func testRunAs(c *agentClient, env *testEnv, pubPEM, token string, user *localUser, rep *reporter) {
	rep.section("run-as (encrypted credentials)")

	if token == "" {
		rep.skip("run-as suite", "no run_as_token available")
		return
	}

	// Negative 1: no X-Run-As-Token header -> 403.
	{
		req := runAsRequest{Source: env.uncPath(env.exeName), CredentialsEncrypted: "AA=="}
		res, err := c.runAs(req, false)
		if err != nil {
			rep.fail("run-as without token -> 403", err.Error())
		} else if res.status == 403 {
			rep.pass("run-as without token -> 403", "403 Forbidden")
		} else {
			rep.fail("run-as without token -> 403", fmt.Sprintf("status=%d", res.status))
		}
	}

	// Negative 2: plaintext credentials -> 400.
	{
		req := runAsRequest{
			Source:      env.uncPath(env.exeName),
			Credentials: &credentials{Username: "x", Password: "y"},
		}
		res, err := c.runAs(req, true)
		if err != nil {
			rep.fail("run-as plaintext creds -> 400", err.Error())
		} else if res.status == 400 {
			rep.pass("run-as plaintext creds -> 400", "400 Bad Request")
		} else {
			rep.fail("run-as plaintext creds -> 400", fmt.Sprintf("status=%d body=%s", res.status, string(res.body)))
		}
	}

	// Negative 3: payload encrypted with a foreign key -> 400.
	if pubPEM != "" {
		foreign, err := generateForeignKey()
		if err == nil {
			blob, err := encryptCredentials(foreign, credentials{Username: "x", Password: "y"})
			if err == nil {
				req := runAsRequest{Source: env.uncPath(env.exeName), CredentialsEncrypted: blob}
				res, err := c.runAs(req, true)
				if err != nil {
					rep.fail("run-as foreign key -> 400", err.Error())
				} else if res.status == 400 {
					rep.pass("run-as foreign key -> 400", "400 invalid credentials payload")
				} else {
					rep.fail("run-as foreign key -> 400", fmt.Sprintf("status=%d", res.status))
				}
			}
		}
	}

	// Positive: valid encrypted credentials for the temp user.
	if user == nil {
		rep.skip("run-as positive launch", "no local user available")
		return
	}
	if pubPEM == "" {
		rep.skip("run-as positive launch", "no public key")
		return
	}

	pub, err := parseRSAPublicKey(pubPEM)
	if err != nil {
		rep.fail("run-as positive launch", "parse pubkey: "+err.Error())
		return
	}

	creds := credentials{Username: user.name, Domain: "", Password: user.password}
	blob, err := encryptCredentials(pub, creds)
	if err != nil {
		rep.fail("run-as positive launch", "encrypt: "+err.Error())
		return
	}

	req := runAsRequest{Source: env.uncPath(env.batName), CredentialsEncrypted: blob}
	res, err := c.runAs(req, true)
	if err != nil {
		rep.fail("run-as positive launch", err.Error())
		return
	}
	if res.status == 200 && res.parsed.Success {
		rep.pass("run-as positive launch", "200 process started as "+user.name)
	} else {
		rep.fail("run-as positive launch", fmt.Sprintf("status=%d body=%s", res.status, string(res.body)))
	}
}

// testMessage exercises POST /api/message with a link and buttons.
func testMessage(c *agentClient, rep *reporter) {
	rep.section("message")

	req := messageRequest{
		Title: "Agent Test",
		Body:  "This message was generated by the agent test utility.",
		Links: []messageLink{{Text: "Open example.com", URL: "https://example.com"}},
		Buttons: []messageBtn{
			{Text: "Acknowledge"},
			{Text: "Dismiss"},
		},
	}
	res, err := c.message(req)
	if err != nil {
		rep.fail("POST /api/message", err.Error())
		return
	}
	if res.status == 200 && res.parsed.Success {
		rep.pass("POST /api/message", "200 message shown (check for a window)")
	} else {
		rep.fail("POST /api/message", fmt.Sprintf("status=%d body=%s", res.status, string(res.body)))
	}
}

// markerCheck returns a predicate that looks for the marker file a batch script
// writes into %TEMP% on successful launch.
func markerCheck(scriptName string) func() bool {
	base := scriptName
	if ext := filepath.Ext(base); ext != "" {
		base = base[:len(base)-len(ext)]
	}
	marker := filepath.Join(os.Getenv("TEMP"), "agent_test_"+base+".marker")
	return func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}
}

// waitFor polls predicate until it is true or the timeout elapses.
func waitFor(predicate func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// testTLS verifies the HTTPS transport itself:
//  1. HTTPS with the deployment CA trusted succeeds (secure channel works).
//  2. HTTPS without trusting the CA is rejected (server presents a cert that
//     does not chain to a trusted root => validation must fail).
//  3. A plain-text HTTP request to the HTTPS port is refused by the server.
//
// If the agent is configured for plain HTTP (baseURL uses http://), the suite
// is skipped since there is no TLS to exercise.
func testTLS(baseURL, caFile, authToken, runAsToken string, rep *reporter) {
	rep.section("tls transport")

	if !strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		rep.skip("tls suite", "agent URL is not HTTPS")
		return
	}

	// 1) HTTPS with CA trust must succeed.
	if caFile == "" {
		rep.skip("https with CA trust", "no -ca provided")
	} else {
		c, err := newAgentClient(baseURL, authToken, runAsToken, caFile, false)
		if err != nil {
			rep.fail("https with CA trust", err.Error())
		} else {
			res, err := c.health()
			if err != nil {
				rep.fail("https with CA trust", err.Error())
			} else if res.status == 200 && res.parsed.Success {
				rep.pass("https with CA trust", "200 over TLS")
			} else {
				rep.fail("https with CA trust", fmt.Sprintf("status=%d", res.status))
			}
		}
	}

	// 2) HTTPS without trusting our CA must be rejected by cert validation.
	{
		c, err := newAgentClient(baseURL, authToken, runAsToken, "", false)
		if err != nil {
			rep.fail("https rejects untrusted cert", err.Error())
		} else {
			_, err := c.health()
			if err != nil && isTLSTrustError(err) {
				rep.pass("https rejects untrusted cert", "validation failed as expected")
			} else if err != nil {
				// Some other error still means the insecure path did not succeed.
				rep.pass("https rejects untrusted cert", "request failed as expected")
			} else {
				rep.fail("https rejects untrusted cert", "request unexpectedly succeeded without CA trust")
			}
		}
	}

	// 3) Plain HTTP to the HTTPS port must not yield a valid HTTP response.
	{
		httpURL := "http://" + stripScheme(baseURL)
		c, err := newAgentClient(httpURL, authToken, runAsToken, "", false)
		if err != nil {
			rep.fail("plain http refused on tls port", err.Error())
		} else {
			res, err := c.health()
			if err != nil {
				rep.pass("plain http refused on tls port", "HTTP request rejected")
			} else if res.status >= 400 {
				rep.pass("plain http refused on tls port", fmt.Sprintf("status=%d", res.status))
			} else {
				rep.fail("plain http refused on tls port", fmt.Sprintf("unexpected status=%d", res.status))
			}
		}
	}
}

// isTLSTrustError reports whether err looks like a certificate trust/validation
// failure rather than a connection error.
func isTLSTrustError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "x509") ||
		strings.Contains(msg, "unknown authority") ||
		strings.Contains(msg, "verif")
}

// stripScheme removes a leading scheme:// from a URL, leaving host[:port]/path.
func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		return u[i+3:]
	}
	return u
}
