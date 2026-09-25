package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
)

// credentials mirrors the agent-side credential payload.
type credentials struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

// parseRSAPublicKey parses a PEM-encoded PKIX RSA public key, as returned by
// the agent”s GET /api/pubkey (public_key_pem field).
func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA (got %T)", pub)
	}
	return rsaPub, nil
}

// encryptCredentials reproduces the agent”s hybrid scheme so that
// internal/crypto.decryptRSA can reverse it:
//
// base64( RSA-OAEP(SHA-256, AES key) || 12-byte nonce || AES-256-GCM(plaintext) )
func encryptCredentials(pub *rsa.PublicKey, creds credentials) (string, error) {
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return "", fmt.Errorf("marshal credentials: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("RSA-OAEP encrypt: %w", err)
	}

	blob := make([]byte, 0, len(encKey)+len(nonce)+len(ciphertext))
	blob = append(blob, encKey...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// generateForeignKey builds an unrelated RSA-3072 key pair, used to produce a
// payload the agent must reject (negative test for /api/run-as).
func generateForeignKey() (*rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	return &priv.PublicKey, nil
}
