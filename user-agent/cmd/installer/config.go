package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// installerConfig mirrors installer.toml.
type installerConfig struct {
	Firewall firewallConfig `toml:"firewall"`
	Install  installConfig  `toml:"install"`
}

type firewallConfig struct {
	Enabled  bool     `toml:"enabled"`
	Profiles []string `toml:"profiles"`
}

type installConfig struct {
	Dir string `toml:"dir"`
}

// defaultInstallerConfig returns the built-in defaults used when no config file
// is present: firewall enabled for the private profile only.
func defaultInstallerConfig() installerConfig {
	return installerConfig{
		Firewall: firewallConfig{
			Enabled:  true,
			Profiles: []string{"private"},
		},
	}
}

// loadInstallerConfig reads installer.toml from path. A missing file is not an
// error: defaults are returned. Unknown/partial files are merged over defaults.
func loadInstallerConfig(path string) (installerConfig, error) {
	cfg := defaultInstallerConfig()

	if _, err := os.Stat(path); err != nil {
		return cfg, nil // no file => defaults
	}

	// Decode into a fresh struct so we can detect whether profiles were given.
	var fileCfg installerConfig
	fileCfg.Firewall.Enabled = true // default true unless explicitly set false
	if _, err := toml.DecodeFile(path, &fileCfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}

	cfg.Firewall.Enabled = fileCfg.Firewall.Enabled
	if len(fileCfg.Firewall.Profiles) > 0 {
		cfg.Firewall.Profiles = fileCfg.Firewall.Profiles
	}
	if fileCfg.Install.Dir != "" {
		cfg.Install.Dir = fileCfg.Install.Dir
	}
	return cfg, nil
}

// validProfiles is the set of profile names netsh accepts.
var validProfiles = map[string]bool{"domain": true, "private": true, "public": true}

// netshProfileValue converts the configured profile list into a netsh
// "profile=" value (comma-separated). Invalid names are rejected. An empty
// result falls back to "private".
func netshProfileValue(profiles []string) (string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range profiles {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !validProfiles[p] {
			return "", fmt.Errorf("invalid firewall profile %q (allowed: domain, private, public)", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "private", nil
	}
	// netsh accepts domain, private, public, or "any"; a comma list is valid.
	return strings.Join(out, ","), nil
}
