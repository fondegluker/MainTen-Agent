package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/maintent-agent/user-agent/internal/crypto"
)

// Server represents the HTTP(S) server.
type Server struct {
	httpServer *http.Server
	keyManager *crypto.KeyManager
	runAsToken string

	// TLS settings; when tlsEnabled is true the server serves HTTPS using
	// certFile/keyFile.
	tlsEnabled bool
	certFile   string
	keyFile    string
}

// NewServer creates and configures the HTTP(S) server.
func NewServer(bind string, port int, ipFilter *IPFilter, tokenAuth *TokenAuthMiddleware, handlers *Handlers, runAsToken string) *Server {
	mux := http.NewServeMux()

	// Register handlers with custom routing
	mux.HandleFunc("/api/health", handlers.HandleHealth)
	mux.HandleFunc("/api/pubkey", handlers.HandlePubkey)
	mux.HandleFunc("/api/message", handlers.HandleMessage)
	mux.HandleFunc("/api/run", handlers.HandleRun)

	// Special handler for /api/run-as with token check
	mux.HandleFunc("/api/run-as", func(w http.ResponseWriter, r *http.Request) {
		if runAsToken == "" {
			log.Printf("[DENY] /api/run-as is disabled (no token configured) from %s", r.RemoteAddr)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		provided := r.Header.Get("X-Run-As-Token")
		if provided == "" {
			log.Printf("[DENY] Missing X-Run-As-Token from %s", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if subtle.ConstantTimeCompare([]byte(provided), []byte(runAsToken)) != 1 {
			log.Printf("[DENY] Invalid X-Run-As-Token from %s", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		handlers.HandleRunAs(w, r)
	})

	// Build middleware chain
	var handler http.Handler = mux

	// Apply IP filter first
	if ipFilter != nil {
		handler = ipFilter.Middleware(handler)
	}

	// Apply token auth (but not for /api/pubkey, /api/health)
	if tokenAuth != nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/pubkey" || r.URL.Path == "/api/health" {
				mux.ServeHTTP(w, r)
				return
			}
			tokenAuth.Middleware(http.HandlerFunc(mux.ServeHTTP)).ServeHTTP(w, r)
		})
	}

	httpServer := &http.Server{
		Addr:         bind + ":" + strconv.Itoa(port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{httpServer: httpServer}
}

// NewServerWithConfig creates a server with config, including TLS settings.
func NewServerWithConfig(bind string, port int, allowedIPs []string, authToken string, runAsToken string, tlsEnabled bool, certFile, keyFile string, handlers *Handlers) (*Server, error) {
	ipFilter, err := NewIPFilter(allowedIPs)
	if err != nil {
		return nil, err
	}

	tokenAuth := NewTokenAuthMiddleware(authToken)

	s := NewServer(bind, port, ipFilter, tokenAuth, handlers, runAsToken)
	s.tlsEnabled = tlsEnabled
	s.certFile = certFile
	s.keyFile = keyFile

	if tlsEnabled {
		// Modern, secure TLS baseline: TLS 1.2+ only.
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return s, nil
}

// Start starts the HTTP(S) server in a goroutine.
func (s *Server) Start() error {
	scheme := "HTTP"
	if s.tlsEnabled {
		scheme = "HTTPS"
	}
	log.Printf("[INFO] Starting %s server on %s", scheme, s.httpServer.Addr)

	go func() {
		var err error
		if s.tlsEnabled {
			// Cert/key are passed to ListenAndServeTLS; the http.Server loads and
			// watches them. TLSConfig.MinVersion is already set.
			err = s.httpServer.ListenAndServeTLS(s.certFile, s.keyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] %s server error: %v", scheme, err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	log.Println("[INFO] Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	log.Println("[INFO] Server stopped")
	return nil
}

// WaitForInterrupt waits for interrupt signal and shuts down gracefully.
func WaitForInterrupt() os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	return <-sigChan
}
