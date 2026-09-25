// Package config provides configuration loading and validation for the User Agent.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the application configuration.
type Config struct {
	Server   ServerConfig   `toml:"server"`
	TLS      TLSConfig      `toml:"tls"`
	Security SecurityConfig `toml:"security"`
	Crypto   CryptoConfig   `toml:"crypto"`
	Storage  StorageConfig  `toml:"storage"`
	Logging  LoggingConfig  `toml:"logging"`
	GUI      GUIConfig      `toml:"gui"`
}

// ServerConfig contains HTTP server settings.
type ServerConfig struct {
	Port int    `toml:"port"`
	Bind string `toml:"bind"`
}

// TLSConfig controls HTTPS transport. When Enabled is true the agent serves
// HTTPS using CertFile/KeyFile (a server certificate signed by the deployment
// CA). When disabled the agent falls back to plain HTTP (development only).
type TLSConfig struct {
	Enabled  bool   `toml:"enabled"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// SecurityConfig contains security settings.
type SecurityConfig struct {
	AllowedIPs []string `toml:"allowed_ips"`
	AuthToken  string   `toml:"auth_token"`
	RunAsToken string   `toml:"run_as_token"`
}

// CryptoConfig contains cryptographic settings.
type CryptoConfig struct {
	PrivateKeyPath string `toml:"private_key_path"`
	Algorithm      string `toml:"algorithm"`
}

// StorageConfig contains file storage settings.
type StorageConfig struct {
	Dir               string   `toml:"dir"`
	MaxFileSizeMB     int      `toml:"max_file_size_mb"`
	AllowedExtensions []string `toml:"allowed_extensions"`
}

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	Level      string `toml:"level"`
	File       string `toml:"file"`
	MaxSizeMB  int    `toml:"max_size_mb"`
	MaxBackups int    `toml:"max_backups"`
}

// GUIConfig contains GUI settings.
type GUIConfig struct {
	DefaultTitle string `toml:"default_title"`
	FontFamily   string `toml:"font_family"`
	FontSize     int    `toml:"font_size"`
}

// Default returns a Config with default values.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 8080,
			Bind: "0.0.0.0",
		},
		TLS: TLSConfig{
			Enabled:  true,
			CertFile: "C:\\ProgramData\\UserAgent\\server.pem",
			KeyFile:  "C:\\ProgramData\\UserAgent\\server.key",
		},
		Security: SecurityConfig{
			AllowedIPs: []string{},
			AuthToken:  "",
			RunAsToken: "",
		},
		Crypto: CryptoConfig{
			PrivateKeyPath: "C:\\ProgramData\\UserAgent\\agent_key.pem",
			Algorithm:      "rsa-3072",
		},
		Storage: StorageConfig{
			Dir:               "C:\\ProgramData\\UserAgent\\Storage",
			MaxFileSizeMB:     500,
			AllowedExtensions: []string{".exe", ".bat", ".cmd", ".msi"},
		},
		Logging: LoggingConfig{
			Level:      "info",
			File:       "C:\\ProgramData\\UserAgent\\agent.log",
			MaxSizeMB:  10,
			MaxBackups: 5,
		},
		GUI: GUIConfig{
			DefaultTitle: "Сообщение",
			FontFamily:   "Segoe UI",
			FontSize:     12,
		},
	}
}

// Load reads configuration from a TOML file.
func Load(path string) (*Config, error) {
	cfg := Default()

	_, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate checks configuration values.
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.Bind == "" {
		c.Server.Bind = "0.0.0.0"
	}

	// Validate TLS config when enabled.
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls enabled but cert_file/key_file not set")
		}
		if _, err := os.Stat(c.TLS.CertFile); err != nil {
			return fmt.Errorf("tls cert_file not accessible: %w", err)
		}
		if _, err := os.Stat(c.TLS.KeyFile); err != nil {
			return fmt.Errorf("tls key_file not accessible: %w", err)
		}
	}

	if c.Storage.MaxFileSizeMB < 1 {
		return fmt.Errorf("invalid max file size: %d", c.Storage.MaxFileSizeMB)
	}

	if len(c.Storage.AllowedExtensions) == 0 {
		c.Storage.AllowedExtensions = []string{".exe", ".bat", ".cmd", ".msi"}
	}

	if c.Logging.MaxSizeMB < 1 {
		return fmt.Errorf("invalid max log size: %d", c.Logging.MaxSizeMB)
	}

	if c.Logging.MaxBackups < 0 {
		return fmt.Errorf("invalid max backups: %d", c.Logging.MaxBackups)
	}

	if c.GUI.FontSize < 6 || c.GUI.FontSize > 72 {
		return fmt.Errorf("invalid font size: %d", c.GUI.FontSize)
	}

	if c.GUI.DefaultTitle == "" {
		c.GUI.DefaultTitle = "Сообщение"
	}

	if c.GUI.FontFamily == "" {
		c.GUI.FontFamily = "Segoe UI"
	}

	// Validate crypto config
	if c.Crypto.Algorithm == "" {
		c.Crypto.Algorithm = "ecdsa-p256"
	}
	if c.Crypto.Algorithm != "ecdsa-p256" && c.Crypto.Algorithm != "rsa-3072" {
		return fmt.Errorf("invalid crypto algorithm: %s (must be ecdsa-p256 or rsa-3072)", c.Crypto.Algorithm)
	}

	if c.Crypto.PrivateKeyPath == "" {
		return fmt.Errorf("private_key_path is required")
	}

	return nil
}
