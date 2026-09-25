package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type options struct {
	srcDir       string
	destDir      string
	configPath   string
	noFirewall   bool
	noStart      bool
	uninstall    bool
	silent       bool   // no pause, hidden console window
	noPause      bool   // disable the end-of-run pause without hiding the window
	firewallOnly bool   // internal: elevated child that only manages the firewall rule
	port         int    // internal: port for -firewall-only (0 => remove)
	profile      string // internal: netsh profile value for -firewall-only

	// Resolved installer configuration (from installer.toml).
	cfg installerConfig
}

func main() {
	opts := parseFlags()

	// In silent mode, hide the console window immediately so the installer runs
	// invisibly (e.g. from a deployment tool).
	if opts.silent {
		hideConsoleWindow()
	}

	initConsole()

	// Internal elevated child: only manage the firewall rule, then exit. This
	// keeps the user-space install (HKCU, %LOCALAPPDATA%) under the real user
	// while the admin-only firewall step runs in a separate elevated process.
	if opts.firewallOnly {
		if opts.port > 0 {
			if err := addFirewallRule(opts.port, opts.profile); err != nil {
				os.Exit(1)
			}
		} else {
			_ = removeFirewallRule()
		}
		os.Exit(0)
	}

	// Load installer configuration (firewall profiles, etc.).
	cfg, err := loadInstallerConfig(opts.configPath)
	if err != nil {
		// Non-fatal: fall back to defaults but report it.
		fmt.Fprintln(os.Stderr, "installer config:", err)
		cfg = defaultInstallerConfig()
	}
	opts.cfg = cfg

	if opts.uninstall {
		os.Exit(runUninstall(opts))
	}
	os.Exit(runInstall(opts))
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.srcDir, "src", "", "source directory containing agent.exe/agent.toml (default: installer dir)")
	flag.StringVar(&o.destDir, "dest", "", "install directory (default: installer.toml install.dir or %LOCALAPPDATA%\\MainTenAgent)")
	flag.StringVar(&o.configPath, "config", "installer.toml", "path to installer configuration")
	flag.BoolVar(&o.noFirewall, "no-firewall", false, "skip creating the firewall rule")
	flag.BoolVar(&o.noStart, "no-start", false, "skip starting the agent and health check")
	flag.BoolVar(&o.uninstall, "uninstall", false, "remove autostart, firewall rule and installed files")
	flag.BoolVar(&o.silent, "silent", false, "run without any prompts and hide the console window")
	flag.BoolVar(&o.noPause, "no-pause", false, "do not wait for Enter before exiting")
	flag.BoolVar(&o.firewallOnly, "firewall-only", false, "internal: manage firewall rule then exit (elevated child)")
	flag.IntVar(&o.port, "port", 0, "internal: port for -firewall-only")
	flag.StringVar(&o.profile, "profile", "", "internal: netsh profile value for -firewall-only")
	flag.Parse()

	if o.srcDir == "" {
		if exe, err := os.Executable(); err == nil {
			o.srcDir = filepath.Dir(exe)
		} else {
			o.srcDir = "."
		}
	}
	return o
}

// resolveDestDir picks the install directory: -dest flag > installer.toml
// install.dir > %LOCALAPPDATA%\MainTenAgent.
func resolveDestDir(opts options) string {
	if opts.destDir != "" {
		return opts.destDir
	}
	if opts.cfg.Install.Dir != "" {
		return opts.cfg.Install.Dir
	}
	return defaultDestDir()
}

func runInstall(opts options) int {
	banner("MainTen Agent Installer")

	destDir := resolveDestDir(opts)

	// Step 1: system requirements.
	step(1, "Checking system requirements")
	if err := checkSystem(); err != nil {
		failMsg(err.Error())
		return finish(opts, 1)
	}
	if v, err := getWindowsVersion(); err == nil {
		ok(fmt.Sprintf("%s (%s), x64", windowsProductName(v), v))
	} else {
		ok("Windows 10+ x64")
	}

	layout := &installLayout{srcDir: opts.srcDir, destDir: destDir}

	// Step 2: verify source artifacts exist.
	step(2, "Verifying source files")
	for _, rel := range requiredFiles {
		p := filepath.Join(opts.srcDir, rel)
		if _, err := os.Stat(p); err != nil {
			failMsg(fmt.Sprintf("missing required file: %s", p))
			return finish(opts, 1)
		}
		ok(rel)
	}

	// Step 3: copy files.
	step(3, "Installing files")
	if err := layout.copyFiles(); err != nil {
		failMsg(err.Error())
		return finish(opts, 1)
	}
	ok("copied to " + destDir)

	// Step 4: rewrite config paths (absolute cert paths).
	step(4, "Configuring agent")
	if err := layout.rewriteConfigPaths(); err != nil {
		failMsg(err.Error())
		return finish(opts, 1)
	}
	ok("agent.toml updated")
	port := layout.cfg.Server.Port
	https := layout.cfg.TLS.Enabled
	info(fmt.Sprintf("port=%d, tls=%v", port, https))

	if https {
		if _, err := os.Stat(layout.cfg.TLS.CertFile); err != nil {
			warn("TLS enabled but server certificate not found: " + layout.cfg.TLS.CertFile)
			info("Provision certs (e.g. via certgen) before starting the agent.")
		}
	}

	// Step 5: register autostart (HKCU Run) - no admin needed.
	step(5, "Registering autostart (current user)")
	if err := layout.registerAutostart(); err != nil {
		failMsg(err.Error())
		return finish(opts, 1)
	}
	ok("HKCU\\...\\Run\\" + runValueName)

	// Step 6: firewall rule (admin needed), scoped to configured profiles.
	step(6, "Configuring firewall")
	if opts.noFirewall || !opts.cfg.Firewall.Enabled {
		reason := "-no-firewall"
		if !opts.cfg.Firewall.Enabled {
			reason = "disabled in installer.toml"
		}
		info("skipped (" + reason + ")")
	} else {
		profile, perr := netshProfileValue(opts.cfg.Firewall.Profiles)
		if perr != nil {
			warn(perr.Error())
		} else if err := ensureFirewall(port, profile); err != nil {
			warn("could not add firewall rule: " + err.Error())
			info("Re-run the installer as administrator, or use -no-firewall.")
		} else {
			ok(fmt.Sprintf("inbound TCP %d allowed for profiles: %s", port, profile))
		}
	}

	// Step 7: start agent + health check.
	step(7, "Starting agent and verifying")
	if opts.noStart {
		info("skipped (-no-start)")
		return finish(opts, 0)
	}

	if https {
		if _, err := os.Stat(layout.cfg.TLS.CertFile); err != nil {
			warn("not starting: TLS certificate missing")
			return finish(opts, 0)
		}
	}

	if err := startAgent(destDir); err != nil {
		failMsg(err.Error())
		return finish(opts, 1)
	}
	ok("agent started")

	scheme := "http"
	if https {
		scheme = "https"
	}
	localURL := fmt.Sprintf("%s://127.0.0.1:%d", scheme, port)
	caFile := filepath.Join(destDir, "certs", "ca.pem")

	if err := healthCheck(localURL, caFile, 12*time.Second); err != nil {
		failMsg("local health check failed: " + err.Error())
		return finish(opts, 1)
	}
	ok("local health OK (" + localURL + "/api/health)")

	// Step 8: network reachability (best-effort).
	step(8, "Checking network reachability")
	url, err := checkNetworkReachable(port, https, caFile)
	if err != nil {
		warn(fmt.Sprintf("not reachable at %s: %v", url, err))
		info("This may be expected if the agent IP allowlist restricts access.")
	} else {
		ok("reachable at " + url + "/api/health")
	}

	fmt.Printf("\n%s\n", colorize(cGreen+cBold, "Installation complete."))
	return finish(opts, 0)
}

// ensureFirewall adds the firewall rule for the given netsh profile value,
// elevating via a child process if the current process lacks admin rights.
func ensureFirewall(port int, profile string) error {
	if isElevated() {
		return addFirewallRule(port, profile)
	}
	return elevatedFirewall(port, profile)
}

// elevatedFirewall spawns an elevated copy of this executable that only adds the
// firewall rule (-firewall-only -port N -profile P), waits for it, and reports
// the result. This isolates the admin step from the user-space install.
func elevatedFirewall(port int, profile string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	params := fmt.Sprintf("-firewall-only -port %d -profile %s", port, profile)

	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString(params)

	return shellExecuteAndWait(verb, file, args)
}

func runUninstall(opts options) int {
	banner("MainTen Agent Uninstaller")

	destDir := resolveDestDir(opts)

	step(1, "Removing autostart")
	if err := removeAutostart(); err != nil {
		warn(err.Error())
	} else {
		ok("autostart entry removed")
	}

	step(2, "Removing firewall rule")
	if isElevated() {
		_ = removeFirewallRule()
		ok("firewall rule removed")
	} else {
		if err := elevatedFirewallRemove(); err != nil {
			warn("could not remove firewall rule (needs admin): " + err.Error())
		} else {
			ok("firewall rule removed")
		}
	}

	step(3, "Stopping agent")
	_ = exec.Command("taskkill", "/IM", "agent.exe", "/F").Run()
	ok("agent stopped")

	step(4, "Removing files")
	if destDir != "" {
		if err := os.RemoveAll(destDir); err != nil {
			warn("could not remove " + destDir + ": " + err.Error())
		} else {
			ok("removed " + destDir)
		}
	}

	fmt.Printf("\n%s\n", colorize(cGreen+cBold, "Uninstall complete."))
	return finish(opts, 0)
}

// elevatedFirewallRemove spawns an elevated child to delete the firewall rule.
func elevatedFirewallRemove() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString("-firewall-only -port 0")
	return shellExecuteAndWait(verb, file, args)
}

// finish waits for Enter before returning unless the run is silent or the pause
// was explicitly disabled. Interactive runs pause by default so the user can
// read results before the window closes.
func finish(opts options, code int) int {
	if opts.silent || opts.noPause {
		return code
	}
	fmt.Print("\nPress Enter to close...")
	fmt.Scanln()
	return code
}
