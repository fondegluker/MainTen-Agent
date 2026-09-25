package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/maintent-agent/user-agent/internal/config"
	"golang.org/x/sys/windows/registry"
)

// installLayout describes where the agent is installed and which source files
// are copied in.
type installLayout struct {
	// Source files (in the directory the installer is run from, or -src).
	srcDir string

	// Destination directory (user-writable, no admin needed).
	destDir string

	// Resolved config after copy, used for firewall/health steps.
	cfg *config.Config
}

// agentFiles are the artifacts copied into the install directory. Certificates
// are optional (a deployment may provision them separately).
var requiredFiles = []string{"agent.exe", "agent.toml"}
var optionalFiles = []string{
	filepath.Join("certs", "server.pem"),
	filepath.Join("certs", "server.key"),
	filepath.Join("certs", "ca.pem"),
	"agent.manifest",
}

// defaultDestDir returns %LOCALAPPDATA%\MainTenAgent, the per-user install root.
func defaultDestDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	return filepath.Join(base, "MainTenAgent")
}

// copyFiles copies required and optional artifacts from srcDir to destDir.
func (l *installLayout) copyFiles() error {
	if err := os.MkdirAll(l.destDir, 0755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(l.destDir, "certs"), 0755); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}

	for _, rel := range requiredFiles {
		if err := copyOne(filepath.Join(l.srcDir, rel), filepath.Join(l.destDir, rel)); err != nil {
			return fmt.Errorf("copy required %s: %w", rel, err)
		}
	}
	for _, rel := range optionalFiles {
		src := filepath.Join(l.srcDir, rel)
		if _, err := os.Stat(src); err != nil {
			continue // optional file absent; skip
		}
		if err := copyOne(src, filepath.Join(l.destDir, rel)); err != nil {
			return fmt.Errorf("copy optional %s: %w", rel, err)
		}
	}
	return nil
}

// copyOne copies a single file, creating parent directories as needed.
func copyOne(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

// rewriteConfigPaths loads the copied agent.toml, rewrites the TLS certificate
// paths to absolute locations inside destDir (so the agent finds them
// regardless of its working directory), writes it back, and stores the parsed
// config on the layout for later steps.
func (l *installLayout) rewriteConfigPaths() error {
	cfgPath := filepath.Join(l.destDir, "agent.toml")

	var cfg config.Config
	if _, err := toml.DecodeFile(cfgPath, &cfg); err != nil {
		return fmt.Errorf("parse agent.toml: %w", err)
	}

	// Make TLS paths absolute under destDir when they are relative.
	if cfg.TLS.Enabled {
		cfg.TLS.CertFile = absUnder(l.destDir, cfg.TLS.CertFile)
		cfg.TLS.KeyFile = absUnder(l.destDir, cfg.TLS.KeyFile)
	}

	f, err := os.OpenFile(cfgPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open agent.toml for write: %w", err)
	}
	defer f.Close()
	if err := toml.NewEncoder(f).Encode(cfg); err != nil {
		return fmt.Errorf("write agent.toml: %w", err)
	}

	l.cfg = &cfg
	return nil
}

// absUnder resolves p against base if p is relative; absolute p is returned
// unchanged.
func absUnder(base, p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "MainTenAgent"

// registerAutostart adds an HKCU\...\Run entry so the agent launches at user
// logon. This is per-user and requires no administrative rights, matching the
// agent”s "runs in the logged-in user session" design.
func (l *installLayout) registerAutostart() error {
	exe := filepath.Join(l.destDir, "agent.exe")
	cfg := filepath.Join(l.destDir, "agent.toml")
	cmd := fmt.Sprintf(`"%s" -config "%s"`, exe, cfg)

	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open Run key: %w", err)
	}
	defer key.Close()

	if err := key.SetStringValue(runValueName, cmd); err != nil {
		return fmt.Errorf("set Run value: %w", err)
	}
	return nil
}

// removeAutostart deletes the autostart entry (used by -uninstall).
func removeAutostart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return nil // key absent => nothing to remove
	}
	defer key.Close()
	_ = key.DeleteValue(runValueName)
	return nil
}
