package server

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/maintent-agent/user-agent/internal/crypto"
)

// Server represents the HTTP server.
type Server struct {
	httpServer  *http.Server
	keyManager  *crypto.KeyManager
	runAsToken  string
}

// NewServer creates and configures the HTTP server.
func NewServer(bind string, port int, ipFilter *IPFilter, tokenAuth *TokenAuthMiddleware, handlers *Handlers, runAsToken string) *Server {
	mux := http.NewServeMux()

	// Register handlers with custom routing
	mux.HandleFunc("/api/health", handlers.HandleHealth)
	mux.HandleFunc("/api/pubkey", handlers.HandlePubkey)
	mux.HandleFunc("/api/message", handlers.HandleMessage)
	mux.HandleFunc("/api/run", handlers.HandleRun)

	// Special handler for /api/run-as with token check
	mux.HandleFunc("/api/run-as", func(w http.ResponseWriter, r *http.Request) {
		// Apply RunAsTokenMiddleware inline
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

		// Token valid, proceed to handler
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
			// Skip token auth for pubkey and health
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

// NewServerWithConfig creates a server with config.
func NewServerWithConfig(bind string, port int, allowedIPs []string, authToken string, runAsToken string, handlers *Handlers) (*Server, error) {
	ipFilter, err := NewIPFilter(allowedIPs)
	if err != nil {
		return nil, err
	}

	tokenAuth := NewTokenAuthMiddleware(authToken)

	return NewServer(bind, port, ipFilter, tokenAuth, handlers, runAsToken), nil
}

// Start starts the HTTP server in a goroutine.
func (s *Server) Start() error {
	log.Printf("[INFO] Starting HTTP server on %s", s.httpServer.Addr)

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTP server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	log.Println("[INFO] Shutting down HTTP server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	log.Println("[INFO] HTTP server stopped")
	return nil
}

// WaitForInterrupt waits for interrupt signal and shuts down gracefully.
func WaitForInterrupt() os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	return <-sigChan
}