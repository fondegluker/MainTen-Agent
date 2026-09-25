package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour // ~10 years
	serverValidity = 825 * 24 * time.Hour      // 825 days (browser/CA max for leaf certs)
)

// certKeyPair bundles a parsed certificate with its private key and the raw DER.
type certKeyPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certDER []byte
}

// newSerial returns a random 128-bit certificate serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// generateCA creates a self-signed CA certificate and key (ECDSA P-256).
func generateCA(commonName string) (*certKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"MainTen"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // this CA only signs leaf certs
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &certKeyPair{cert: cert, key: key, certDER: der}, nil
}

// defaultSANs returns the SAN set every agent server cert should carry:
// loopback IP, localhost, and the machine hostname.
func defaultSANs() (ips []net.IP, dns []string) {
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	dns = []string{"localhost"}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		dns = append(dns, hn)
	}
	return ips, dns
}

// parseSANFlags splits user-provided -san entries into IP and DNS lists.
// Each entry is "IP:1.2.3.4" or "DNS:name". A bare value is treated as DNS if it
// does not parse as an IP.
func parseSANFlags(sans []string) (ips []net.IP, dns []string, err error) {
	for _, s := range sans {
		switch {
		case len(s) > 3 && (s[:3] == "IP:" || s[:3] == "ip:"):
			ip := net.ParseIP(s[3:])
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid IP SAN: %q", s)
			}
			ips = append(ips, ip)
		case len(s) > 4 && (s[:4] == "DNS:" || s[:4] == "dns:"):
			dns = append(dns, s[4:])
		default:
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			} else {
				dns = append(dns, s)
			}
		}
	}
	return ips, dns, nil
}

// generateServerCert creates an agent server certificate signed by the CA.
func generateServerCert(ca *certKeyPair, commonName string, extraSANs sanFlag) (*certKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	ips, dns := defaultSANs()
	extraIPs, extraDNS, err := parseSANFlags(extraSANs)
	if err != nil {
		return nil, err
	}
	ips = append(ips, extraIPs...)
	dns = append(dns, extraDNS...)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"MainTen"},
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(serverValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ips,
		DNSNames:    dns,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &certKeyPair{cert: cert, key: key, certDER: der}, nil
}

// save writes the certificate (PEM) and private key (PKCS#8 PEM) to disk. The
// key file is created with 0600 permissions.
func (p *certKeyPair) save(certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(keyPEM); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// loadCA loads an existing CA certificate and key from disk.
func loadCA(certPath, keyPath string) (*certKeyPair, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not ECDSA")
	}

	return &certKeyPair{cert: cert, key: key, certDER: certBlock.Bytes}, nil
}

// fingerprintSHA256 returns the hex SHA-256 fingerprint of the certificate DER.
func (p *certKeyPair) fingerprintSHA256() (string, error) {
	sum := sha256.Sum256(p.certDER)
	return fmt.Sprintf("%x", sum), nil
}

// sanDescriptions returns a human-readable list of the cert”s SANs.
func (p *certKeyPair) sanDescriptions() []string {
	var out []string
	for _, ip := range p.cert.IPAddresses {
		out = append(out, "IP:"+ip.String())
	}
	for _, d := range p.cert.DNSNames {
		out = append(out, "DNS:"+d)
	}
	return out
}
