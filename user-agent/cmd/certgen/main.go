// Command certgen generates the TLS key material used to secure the HTTP API
// between the control server and the agent.
//
// It produces a small PKI:
//
// ca.pem      - self-signed CA certificate (trust anchor), valid 10 years
// ca.key      - CA private key (keep secret; only needed to sign more certs)
// server.pem  - agent server certificate, signed by the CA, valid 825 days
// server.key  - agent server private key (installed on the agent host)
//
// The agent listens on HTTPS using server.pem/server.key. Any client (the
// control server, or the agent-test utility) trusts ca.pem to validate the
// agent. This scales to many agents: each agent gets its own server cert signed
// by the same CA, and clients only need the single CA to trust all of them.
//
// This tool is intended for development and testing. In production the signing
// role moves to the control server side.
//
// Usage:
//
// certgen -out ./certs [-san IP:10.0.0.5] [-san DNS:agent.corp.local] ...
// certgen -out ./certs -force            # overwrite existing files
// certgen -out ./certs -ca-only          # only (re)create the CA
// certgen -out ./certs -reuse-ca         # sign a new server cert with an existing CA
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sanFlag collects repeated -san values (e.g. -san IP:1.2.3.4 -san DNS:host).
type sanFlag []string

func (s *sanFlag) String() string { return strings.Join(*s, ",") }
func (s *sanFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	outDir := flag.String("out", "certs", "output directory for the generated key material")
	commonName := flag.String("cn", "MainTen User Agent", "server certificate common name")
	caCN := flag.String("ca-cn", "MainTen Agent Dev CA", "CA certificate common name")
	force := flag.Bool("force", false, "overwrite existing files")
	caOnly := flag.Bool("ca-only", false, "only generate the CA (ca.pem/ca.key)")
	reuseCA := flag.Bool("reuse-ca", false, "reuse an existing CA in -out to sign the server cert")
	var sans sanFlag
	flag.Var(&sans, "san", "additional SAN entry, prefixed IP: or DNS: (repeatable)")
	flag.Parse()

	if err := run(*outDir, *caCN, *commonName, sans, *force, *caOnly, *reuseCA); err != nil {
		fmt.Fprintf(os.Stderr, "certgen: %v\n", err)
		os.Exit(1)
	}
}

func run(outDir, caCN, serverCN string, sans sanFlag, force, caOnly, reuseCA bool) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	caCertPath := filepath.Join(outDir, "ca.pem")
	caKeyPath := filepath.Join(outDir, "ca.key")
	srvCertPath := filepath.Join(outDir, "server.pem")
	srvKeyPath := filepath.Join(outDir, "server.key")

	var ca *certKeyPair
	var err error

	if reuseCA {
		ca, err = loadCA(caCertPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("load existing CA (needed for -reuse-ca): %w", err)
		}
		fmt.Printf("Reusing existing CA: %s\n", caCertPath)
	} else {
		if !force {
			if fileExists(caCertPath) || fileExists(caKeyPath) {
				return fmt.Errorf("CA files already exist in %s (use -force to overwrite or -reuse-ca to keep)", outDir)
			}
		}
		ca, err = generateCA(caCN)
		if err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
		if err := ca.save(caCertPath, caKeyPath); err != nil {
			return fmt.Errorf("save CA: %w", err)
		}
		fmt.Printf("Generated CA:\n  %s\n  %s\n", caCertPath, caKeyPath)
	}

	if caOnly {
		return nil
	}

	if !force && !reuseCA {
		if fileExists(srvCertPath) || fileExists(srvKeyPath) {
			return fmt.Errorf("server cert files already exist in %s (use -force to overwrite)", outDir)
		}
	}

	server, err := generateServerCert(ca, serverCN, sans)
	if err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}
	if err := server.save(srvCertPath, srvKeyPath); err != nil {
		return fmt.Errorf("save server cert: %w", err)
	}
	fmt.Printf("Generated server certificate:\n  %s\n  %s\n", srvCertPath, srvKeyPath)

	fp, _ := server.fingerprintSHA256()
	fmt.Printf("Server cert SHA-256: %s\n", fp)
	fmt.Printf("SANs: %s\n", strings.Join(server.sanDescriptions(), ", "))
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
