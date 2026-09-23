package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ecies/go/v2"
)

// KeyManager manages the cryptographic keys for the agent.
type KeyManager struct {
	privateKey any
	publicKey  any
	algorithm  string
	path       string
	eciesPriv  *ecies.PrivateKey
}

// NewKeyManager creates a new KeyManager instance.
func NewKeyManager(privKey any, pubKey any, algorithm string, path string) *KeyManager {
	km := &KeyManager{
		privateKey: privKey,
		publicKey:  pubKey,
		algorithm:  algorithm,
		path:       path,
	}

	// Initialize ECIES key if using ECDSA
	if algorithm == "ecdsa-p256" {
		if ecdsaKey, ok := privKey.(*ecdsa.PrivateKey); ok {
			km.eciesPriv = ecies.NewPrivateKeyFromECDSA(ecdsaKey)
		}
	}

	return km
}

// LoadOrGenerate loads an existing key pair or generates a new one.
func LoadOrGenerate(path, algorithm string) (*KeyManager, error) {
	var privKey any
	var pubKey any
	var err error

	// Try to load existing key
	if _, statErr := os.Stat(path); statErr == nil {
		privKey, pubKey, err = loadKeyPair(path, algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to load existing key: %w", err)
		}
	} else {
		// Generate new key pair
		privKey, pubKey, err = generateKeyPair(algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}

		// Save to disk with secure permissions
		if err := saveKeyPair(path, privKey, pubKey, algorithm); err != nil {
			return nil, fmt.Errorf("failed to save key: %w", err)
		}
	}

	return NewKeyManager(privKey, pubKey, algorithm, path), nil
}

// generateKeyPair generates a new ECDSA or RSA key pair.
func generateKeyPair(algorithm string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch algorithm {
	case "ecdsa-p256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case "rsa-3072":
		priv, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.Public, nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// loadKeyPair loads an existing key pair from disk.
func loadKeyPair(path, algorithm string) (crypto.PrivateKey, crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid private key format")
	}

	var privKey any
	switch algorithm {
	case "ecdsa-p256":
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		privKey = priv.(*ecdsa.PrivateKey)
	case "rsa-3072":
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		privKey = priv.(*rsa.PrivateKey)
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Derive public key
	var pubKey crypto.PublicKey
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case *rsa.PrivateKey:
		pubKey = &k.Public
	}

	return privKey, pubKey, nil
}

// saveKeyPair saves the key pair to disk with secure permissions.
func saveKeyPair(path string, privKey crypto.PrivateKey, pubKey crypto.PublicKey, algorithm string) error {
	// Serialize private key in PKCS#8 format
	var privBytes []byte
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		var err error
		privBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}
	case *rsa.PrivateKey:
		var err error
		privBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key type")
	}

	// Write private key with restrictive permissions
	privFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	if err := pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Write public key
	pubPath := path + ".pub"
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	return nil
}

// PublicKeyPEM returns the public key in PEM format.
func (km *KeyManager) PublicKeyPEM() (string, error) {
	var pubBytes []byte
	var err error

	switch k := km.publicKey.(type) {
	case *ecdsa.PublicKey:
		pubBytes, err = x509.MarshalPKIXPublicKey(k)
	case *rsa.PublicKey:
		pubBytes, err = x509.MarshalPKIXPublicKey(k)
	default:
		return "", fmt.Errorf("unsupported public key type")
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})), nil
}

// Algorithm returns the key algorithm.
func (km *KeyManager) Algorithm() string {
	return km.algorithm
}

// PublicKeyFingerprint returns SHA-256 fingerprint of the public key (hex).
func (km *KeyManager) PublicKeyFingerprint() (string, error) {
	pemStr, err := km.PublicKeyPEM()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(pemStr))
	return fmt.Sprintf("%x", hash), nil
}

// GetPrivateKey returns the private key (for internal use only).
func (km *KeyManager) GetPrivateKey() any {
	return km.privateKey
}

// GetECIESPrivateKey returns the ECIES private key.
func (km *KeyManager) GetECIESPrivateKey() *ecies.PrivateKey {
	return km.eciesPriv
}