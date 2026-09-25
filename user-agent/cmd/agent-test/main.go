package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// config holds command-line options for the test utility.
type options struct {
	baseURL   string
	caFile    string
	host      string // host used in UNC paths (must be reachable as \\host\share)
	shareName string
	agentExe  string
	agentConf string
	authToken string
	runAsUser string
	runAsPass string
	skipRunAs bool
	skipMsg   bool
	noElevate bool
	noPause   bool
}

func main() {
	opts := parseFlags()

	closer := initOutput()
	defer closer()

	banner()

	// Administrative privileges are required to create SMB shares, local users
	// and adjust ACLs. If we are not elevated, relaunch via UAC unless disabled.
	if !isElevated() {
		if opts.noElevate {
			warnf("not running elevated and -no-elevate set; share/user setup will likely fail")
		} else {
			infof("Not elevated. Requesting administrator privileges via UAC...")
			relaunched, err := relaunchElevated()
			if err != nil {
				fatalf("failed to elevate: %v", err)
				os.Exit(2)
			}
			if relaunched {
				// The elevated instance continues the work; this one exits.
				os.Exit(0)
			}
		}
	}

	rep := &reporter{}
	exitCode := run(opts, rep)
	os.Exit(exitCode)
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.baseURL, "url", "https://127.0.0.1:50513", "agent base URL")
	flag.StringVar(&o.caFile, "ca", "certs/ca.pem", "CA certificate (PEM) to trust for HTTPS; empty to disable TLS verification")
	flag.StringVar(&o.host, "host", "127.0.0.1", "host for UNC share paths (\\\\host\\share)")
	flag.StringVar(&o.shareName, "share", "AgentTestShare", "SMB share name to create")
	flag.StringVar(&o.agentExe, "agent", "", "path to agent.exe (default: alongside this utility)")
	flag.StringVar(&o.agentConf, "config", "", "path to agent.toml (default: alongside agent.exe)")
	flag.StringVar(&o.authToken, "auth-token", "", "X-Auth-Token value if the agent requires one")
	flag.StringVar(&o.runAsUser, "runas-user", "agenttestuser", "temporary local user for run-as test")
	flag.StringVar(&o.runAsPass, "runas-pass", "Ag3nt!Test#9", "password for the temporary user")
	flag.BoolVar(&o.skipRunAs, "skip-runas", false, "skip /api/run-as tests")
	flag.BoolVar(&o.skipMsg, "skip-message", false, "skip /api/message test")
	flag.BoolVar(&o.noElevate, "no-elevate", false, "do not attempt UAC elevation")
	flag.BoolVar(&o.noPause, "no-pause", false, "do not wait for Enter before exiting")
	flag.Parse()

	// Resolve default agent paths.
	if o.agentExe == "" {
		if exe, err := os.Executable(); err == nil {
			o.agentExe = filepath.Join(filepath.Dir(exe), "agent.exe")
			if _, statErr := os.Stat(o.agentExe); statErr != nil {
				// Fall back to current working directory.
				o.agentExe = "agent.exe"
			}
		}
	}
	if o.agentConf == "" {
		o.agentConf = filepath.Join(filepath.Dir(o.agentExe), "agent.toml")
	}
	return o
}

// run performs the full test flow and returns a process exit code.
func run(opts options, rep *reporter) int {
	// --- Prepare agent control (config + process) ---
	ctrl := &agentControl{
		exePath:    opts.agentExe,
		configPath: opts.agentConf,
	}

	// Ensure a run-as token exists; generate one if the config leaves it empty.
	runAsToken := ""
	if !opts.skipRunAs {
		tok, edited, err := ctrl.ensureRunAsToken()
		if err != nil {
			warnf("could not ensure run_as_token: %v (run-as tests limited)", err)
		} else {
			runAsToken = tok
			if edited {
				infof("Generated temporary run_as_token and updated %s", opts.agentConf)
			} else {
				infof("Using existing run_as_token from config")
			}
		}
	}
	defer ctrl.restoreConfig()

	// Restart the agent so it loads the (possibly updated) config.
	stopExistingAgents(portFromURL(opts.baseURL))
	if err := ctrl.start(); err != nil {
		fatalf("%v", err)
		ctrl.restoreConfig()
		return 2
	}
	defer ctrl.stop()

	client, err := newAgentClient(opts.baseURL, opts.authToken, runAsToken, opts.caFile, false)
	if err != nil {
		fatalf("failed to build HTTPS client: %v", err)
		return 2
	}

	if err := waitReady(client, 15*time.Second); err != nil {
		fatalf("%v", err)
		return 2
	}

	// --- Set up the share and test files ---
	env, err := setupTestEnv(opts.host, opts.shareName)
	if err != nil {
		fatalf("environment setup: %v", err)
		if env != nil {
			env.cleanup()
		}
		return 2
	}
	defer env.cleanup()
	infof("Share published: %s (backing dir: %s)", env.uncBase, env.root)

	// --- Optionally create the temporary local user for run-as ---
	var user *localUser
	if !opts.skipRunAs && runAsToken != "" {
		user, err = ensureLocalUser(opts.runAsUser, opts.runAsPass)
		if err != nil {
			warnf("could not create local user: %v (positive run-as skipped)", err)
			user = nil
		} else {
			infof("Created temporary local user: %s", user.name)
		}
		defer user.cleanup()
	}

	// --- Run the test suites ---
	testTLS(opts.baseURL, opts.caFile, opts.authToken, runAsToken, rep)
	testHealthAndPubkey(client, rep)
	pubPEM := fetchPubKey(client, rep)

	testRun(client, env, rep)

	if !opts.skipRunAs {
		testRunAs(client, env, pubPEM, runAsToken, user, rep)
	} else {
		rep.section("run-as")
		rep.skip("run-as suite", "disabled via -skip-runas")
	}

	if !opts.skipMsg {
		testMessage(client, rep)
	} else {
		rep.section("message")
		rep.skip("message", "disabled via -skip-message")
	}

	code := rep.summary()

	infof("\nResults also written to: %s", logFilePath())

	if !opts.noPause {
		fmt.Print("\nPress Enter to close...")
		fmt.Scanln()
	}
	return code
}

// portFromURL extracts the TCP port from a base URL like http://host:port.
// Falls back to 50513 if it cannot be parsed.
func portFromURL(raw string) int {
	u, err := url.Parse(raw)
	if err == nil {
		if p := u.Port(); p != "" {
			if n, e := strconv.Atoi(p); e == nil {
				return n
			}
		}
	}
	return 50513
}
