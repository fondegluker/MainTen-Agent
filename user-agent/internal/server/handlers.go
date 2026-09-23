package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/maintent-agent/user-agent/internal/executor"
	"github.com/maintent-agent/user-agent/internal/gui"

	"github.com/maintent-agent/user-agent/internal/crypto"
)

// MessageRequest represents the request body for POST /api/message.
type MessageRequest struct {
	Title   string        `json:"title"`
	Body    string        `json:"body"`
	Links   []Link        `json:"links"`
	Buttons []Button      `json:"buttons"`
}

// Link represents a clickable link.
type Link struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

// Button represents a button with optional callback.
type Button struct {
	Text     string `json:"text"`
	Callback string `json:"callback,omitempty"`
}

// RunRequest represents the request body for POST /api/run.
type RunRequest struct {
	Source           string `json:"source"`
	Args             string `json:"args"`
	RunAsCurrentUser bool   `json:"run_as_current_user"`
}

// RunAsRequestOld represents the old format (deprecated).
type RunAsRequestOld struct {
	Source      string           `json:"source"`
	Args        string           `json:"args"`
	Credentials CredentialsPlain `json:"credentials"`
}

// RunAsRequest represents the new request body for POST /api/run-as with encrypted credentials.
type RunAsRequest struct {
	Source               string `json:"source"`
	Args                 string `json:"args"`
	CredentialsEncrypted string `json:"credentials_encrypted"`
	// Deprecated: credentials in plaintext is no longer allowed
	CredentialsPlain CredentialsPlain `json:"credentials"`
}

// CredentialsPlain represents plaintext credentials (deprecated).
type CredentialsPlain struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

// Response represents a standard API response.
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Handlers holds dependencies for HTTP handlers.
type Handlers struct {
	storageDir    string
	maxFileSizeMB int
	allowedExts   []string
	defaultTitle  string
	fontFamily    string
	fontSize      int
	keyManager    *crypto.KeyManager
}

// NewHandlers creates new handlers instance.
func NewHandlers(storageDir string, maxFileSizeMB int, allowedExts []string, defaultTitle, fontFamily string, fontSize int, keyManager *crypto.KeyManager) *Handlers {
	return &Handlers{
		storageDir:    storageDir,
		maxFileSizeMB: maxFileSizeMB,
		allowedExts:   allowedExts,
		defaultTitle:  defaultTitle,
		fontFamily:    fontFamily,
		fontSize:      fontSize,
		keyManager:    keyManager,
	}
}

// HandleMessage handles POST /api/message.
func (h *Handlers) HandleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode message request: %v", err)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "Invalid request body"})
		return
	}

	title := req.Title
	if title == "" {
		title = h.defaultTitle
	}

	// Show message in a separate goroutine to not block HTTP
	go func() {
		gui.ShowMessage(title, req.Body, req.Links, req.Buttons, h.fontFamily, h.fontSize)
	}()

	log.Printf("[INFO] Message shown from %s: %s", r.RemoteAddr, title)
	respondJSON(w, http.StatusOK, Response{Success: true, Message: "Message shown"})
}

// HandleRun handles POST /api/run.
func (h *Handlers) HandleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode run request: %v", err)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "Invalid request body"})
		return
	}

	if req.Source == "" {
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "source is required"})
		return
	}

	// Copy file to storage
	localPath, err := executor.CopyToStorage(req.Source, h.storageDir, h.maxFileSizeMB, h.allowedExts)
	if err != nil {
		log.Printf("[ERROR] Failed to copy file: %v", err)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: err.Error()})
		return
	}

	// Parse args
	var args []string
	if req.Args != "" {
		args = []string{req.Args}
	}

	// Run the executable from current user
	err = executor.RunLocal(localPath, args)
	if err != nil {
		log.Printf("[ERROR] Failed to run executable: %v", err)
		respondJSON(w, http.StatusInternalServerError, Response{Success: false, Error: err.Error()})
		return
	}

	log.Printf("[INFO] Started process: %s %s from %s", localPath, req.Args, r.RemoteAddr)
	respondJSON(w, http.StatusOK, Response{Success: true, Message: "Process started", Data: map[string]string{"path": localPath}})
}

// HandleRunAs handles POST /api/run-as with encrypted credentials.
func (h *Handlers) HandleRunAs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RunAsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode run-as request: %v", err)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "Invalid request body"})
		return
	}

	if req.Source == "" {
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "source is required"})
		return
	}

	// Check for plaintext credentials - this is forbidden
	if req.CredentialsPlain.Username != "" || req.CredentialsPlain.Password != "" {
		log.Printf("[SECURITY] Attempted to use plaintext credentials from %s - rejected", r.RemoteAddr)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "Plaintext credentials not allowed. Use credentials_encrypted field."})
		return
	}

	// Check for encrypted credentials
	if req.CredentialsEncrypted == "" {
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "credentials_encrypted is required"})
		return
	}

	// Decrypt credentials
	creds, err := h.keyManager.DecryptCredentials(req.CredentialsEncrypted)
	if err != nil {
		log.Printf("[ERROR] Failed to decrypt credentials from %s: %v", r.RemoteAddr, err)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: "Invalid credentials payload"})
		return
	}

	// Copy values before wiping password
	username := creds.Username
	domain := creds.Domain

	// Log username and domain for audit (never log password)
	log.Printf("[INFO] Processing run-as request for user: %s\\%s from %s", domain, username, r.RemoteAddr)

	// Copy file to storage
	localPath, err := executor.CopyToStorage(req.Source, h.storageDir, h.maxFileSizeMB, h.allowedExts)
	if err != nil {
		log.Printf("[ERROR] Failed to copy file: %v", err)
		respondJSON(w, http.StatusBadRequest, Response{Success: false, Error: err.Error()})
		return
	}

	// Parse args
	var args []string
	if req.Args != "" {
		args = []string{req.Args}
	}

	// Run with credentials
	err = executor.RunWithCredentials(localPath, args, username, domain, creds.Password)
	if err != nil {
		log.Printf("[ERROR] Failed to run with credentials: %v", err)
		respondJSON(w, http.StatusInternalServerError, Response{Success: false, Error: err.Error()})
		return
	}

	// Securely wipe password from memory
	passwordBytes := []byte(creds.Password)
	for i := range passwordBytes {
		passwordBytes[i] = 0
	}

	log.Printf("[INFO] Started process as %s\\%s: %s %s", domain, username, localPath, req.Args)
	respondJSON(w, http.StatusOK, Response{Success: true, Message: "Process started as user", Data: map[string]string{"path": localPath}})
}

// HandlePubkey handles GET /api/pubkey.
func (h *Handlers) HandlePubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pem, err := h.keyManager.PublicKeyPEM()
	if err != nil {
		log.Printf("[ERROR] Failed to get public key: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Use a custom response to avoid the Data wrapper
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"algorithm":      h.keyManager.Algorithm(),
		"public_key_pem": pem,
	})
}

// HandleHealth handles GET /api/health.
func (h *Handlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, Response{Success: true, Message: "OK"})
}

func respondJSON(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}