package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// agentClient is a thin HTTP(S) client for the agent API.
type agentClient struct {
	baseURL    string
	authToken  string // X-Auth-Token (may be empty)
	runAsToken string // X-Run-As-Token (may be empty)
	http       *http.Client
}

// newAgentClient builds a client. When caFile is non-empty, TLS server
// verification is enabled against that CA (the agent”s HTTPS certificate must
// chain to it). When caFile is empty, a plain client is used (HTTP, or HTTPS
// with system trust). insecure disables verification entirely (for negative
// TLS tests only).
func newAgentClient(baseURL, authToken, runAsToken, caFile string, insecure bool) (*agentClient, error) {
	transport := &http.Transport{}

	switch {
	case insecure:
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - negative test only
	case caFile != "":
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from CA file %s", caFile)
		}
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	}

	return &agentClient{
		baseURL:    baseURL,
		authToken:  authToken,
		runAsToken: runAsToken,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}, nil
}

// apiResponse is the agent”s standard JSON envelope.
type apiResponse struct {
	Success bool              `json:"success"`
	Message string            `json:"message"`
	Error   string            `json:"error"`
	Data    map[string]string `json:"data"`
}

// httpResult captures everything a test needs to assert on.
type httpResult struct {
	status int
	body   []byte
	parsed apiResponse
}

// do issues a request. extraHeaders are applied last so callers can override
// or add headers (e.g. the run-as token) per request.
func (c *agentClient) do(method, path string, body any, extraHeaders map[string]string) (*httpResult, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.authToken != "" {
		req.Header.Set("X-Auth-Token", c.authToken)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	res := &httpResult{status: resp.StatusCode, body: raw}
	// Best-effort parse; some error responses are plain text (http.Error).
	_ = json.Unmarshal(raw, &res.parsed)
	return res, nil
}

// health calls GET /api/health.
func (c *agentClient) health() (*httpResult, error) {
	return c.do(http.MethodGet, "/api/health", nil, nil)
}

// pubkey calls GET /api/pubkey and returns the PEM public key and algorithm.
func (c *agentClient) pubkey() (algorithm, pemKey string, res *httpResult, err error) {
	res, err = c.do(http.MethodGet, "/api/pubkey", nil, nil)
	if err != nil {
		return "", "", res, err
	}
	var payload struct {
		Algorithm    string `json:"algorithm"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if e := json.Unmarshal(res.body, &payload); e != nil {
		return "", "", res, fmt.Errorf("parse pubkey response: %w", e)
	}
	return payload.Algorithm, payload.PublicKeyPEM, res, nil
}

// runRequest is the POST /api/run body.
type runRequest struct {
	Source           string `json:"source"`
	Args             string `json:"args,omitempty"`
	RunAsCurrentUser bool   `json:"run_as_current_user"`
}

func (c *agentClient) run(req runRequest) (*httpResult, error) {
	return c.do(http.MethodPost, "/api/run", req, nil)
}

// runAsRequest is the POST /api/run-as body. Only the encrypted field is used
// for positive tests; plaintextCreds is populated only for the negative test.
type runAsRequest struct {
	Source               string       `json:"source"`
	Args                 string       `json:"args,omitempty"`
	CredentialsEncrypted string       `json:"credentials_encrypted,omitempty"`
	Credentials          *credentials `json:"credentials,omitempty"`
}

// runAs posts to /api/run-as with the configured run-as token header.
func (c *agentClient) runAs(req runAsRequest, withToken bool) (*httpResult, error) {
	headers := map[string]string{}
	if withToken && c.runAsToken != "" {
		headers["X-Run-As-Token"] = c.runAsToken
	}
	return c.do(http.MethodPost, "/api/run-as", req, headers)
}

// messageRequest is the POST /api/message body.
type messageRequest struct {
	Title   string        `json:"title"`
	Body    string        `json:"body"`
	Links   []messageLink `json:"links,omitempty"`
	Buttons []messageBtn  `json:"buttons,omitempty"`
}

type messageLink struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

type messageBtn struct {
	Text     string `json:"text"`
	Callback string `json:"callback,omitempty"`
}

func (c *agentClient) message(req messageRequest) (*httpResult, error) {
	return c.do(http.MethodPost, "/api/message", req, nil)
}
