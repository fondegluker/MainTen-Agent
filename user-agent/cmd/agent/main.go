package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/maintent-agent/user-agent/internal/config"
	"github.com/maintent-agent/user-agent/internal/crypto"
	"github.com/maintent-agent/user-agent/internal/gui"
	"github.com/maintent-agent/user-agent/internal/server"

	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// The GUI (walk) message loop must run on the main OS thread, and that same
	// thread must perform the one-time common-controls initialization. Lock the
	// main goroutine to its OS thread before anything else runs.
	runtime.LockOSThread()
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "agent.toml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		// Try loading from current directory
		cfg, err = config.Load("agent.toml")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
			os.Exit(1)
		}
	}

	// Initialize file logger with rotation
	initLogger(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.MaxSizeMB, cfg.Logging.MaxBackups)

	log.Println("[INFO] User Agent starting...")
	log.Printf("[INFO] Configuration loaded: server port=%d, bind=%s", cfg.Server.Port, cfg.Server.Bind)

	// Initialize key manager (load or generate key pair)
	keyManager, err := crypto.LoadOrGenerate(cfg.Crypto.PrivateKeyPath, cfg.Crypto.Algorithm)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize key manager: %v", err)
	}

	// Log key fingerprint (for audit)
	fingerprint, err := keyManager.PublicKeyFingerprint()
	if err != nil {
		log.Printf("[WARN] Failed to get key fingerprint: %v", err)
	} else {
		log.Printf("[INFO] Public key fingerprint: %s", fingerprint)
	}

	// Check if run_as_token is configured
	if cfg.Security.RunAsToken == "" {
		log.Println("[WARN] run_as_token is not configured - /api/run-as endpoint is disabled")
	}

	// Create handlers with key manager
	handlers := server.NewHandlers(
		cfg.Storage.Dir,
		cfg.Storage.MaxFileSizeMB,
		cfg.Storage.AllowedExtensions,
		cfg.GUI.DefaultTitle,
		cfg.GUI.FontFamily,
		cfg.GUI.FontSize,
		keyManager,
	)

	// Create and start server
	srv, err := server.NewServerWithConfig(
		cfg.Server.Bind,
		cfg.Server.Port,
		cfg.Security.AllowedIPs,
		cfg.Security.AuthToken,
		cfg.Security.RunAsToken,
		cfg.TLS.Enabled,
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
		handlers,
	)
	if err != nil {
		log.Fatalf("[FATAL] Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("[FATAL] Failed to start server: %v", err)
	}

	log.Printf("[INFO] User Agent started on %s:%d", cfg.Server.Bind, cfg.Server.Port)
	log.Printf("[INFO] Storage directory: %s", cfg.Storage.Dir)
	log.Printf("[INFO] Allowed IPs: %v", cfg.Security.AllowedIPs)
	log.Printf("[INFO] Crypto algorithm: %s", cfg.Crypto.Algorithm)
	log.Printf("[INFO] Run-as endpoint: %s", func() string {
		if cfg.Security.RunAsToken != "" {
			return "enabled"
		}
		return "disabled"
	}())

	// Handle shutdown signals in a background goroutine. On signal, stop the
	// HTTP server and close the GUI so the message loop (running on the main
	// thread below) returns.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("[INFO] Received shutdown signal")
		if err := srv.Stop(); err != nil {
			log.Printf("[ERROR] Error during shutdown: %v", err)
		}
		gui.Shutdown()
	}()

	// Run the GUI message loop on the main OS thread. This blocks until
	// gui.Shutdown is called. All dialogs are created on this thread via the
	// GUI manager. Common controls are initialized here once.
	log.Println("[INFO] Starting GUI message loop")
	if err := gui.Run(); err != nil {
		log.Fatalf("[FATAL] GUI subsystem failed: %v", err)
	}

	log.Println("[INFO] User Agent stopped")
}

func initLogger(logFile, level string, maxSizeMB, maxBackups int) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	if logFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(logFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create log directory: %v\n", err)
		}

		// Use lumberjack for log rotation
		log.SetOutput(&lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    maxSizeMB,
			MaxBackups: maxBackups,
			MaxAge:     30,
			Compress:   true,
		})
	}

	// Set log level (placeholder for level filtering)
	_ = level
}
