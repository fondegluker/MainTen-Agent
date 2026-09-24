package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// Credentials represents decrypted user credentials.
type Credentials struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

// DecryptCredentials decrypts base64-encoded credentials using the private key.
// Пока поддерживаем только RSA.
func (km *KeyManager) DecryptCredentials(encoded string) (*Credentials, error) {
	// Проверяем алгоритм
	if km.algorithm != "rsa-3072" {
		return nil, fmt.Errorf("unsupported algorithm: %s (only rsa-3072 supported)", km.algorithm)
	}

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding")
	}

	plaintext, err := km.decryptRSA(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	// Parse JSON
	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("invalid credentials format")
	}

	// Validate required fields
	if creds.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if creds.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	return &creds, nil
}

// decryptRSA decrypts using hybrid RSA-OAEP + AES-GCM scheme.
// Format: [32 bytes encrypted AES key][12 bytes nonce][ciphertext with auth tag]
func (km *KeyManager) decryptRSA(ciphertext []byte) ([]byte, error) {
	privKey, ok := km.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}

	// Minimum size: 32 (encrypted key) + 12 (nonce) + 16 (tag) + 1 (minimum plaintext)
	minLen := 32 + 12 + 16 + 1
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract encrypted AES key (32 bytes for RSA-3072)
	encryptedKey := ciphertext[:32]
	nonce := ciphertext[32:44]
	encryptedData := ciphertext[44:]

	// Decrypt AES key with RSA-OAEP
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed")
	}

	// Decrypt payload with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed")
	}

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed")
	}

	// Securely wipe the AES key from memory
	for i := range aesKey {
		aesKey[i] = 0
	}

	return plaintext, nil
}

// SecureWipe securely wipes a byte slice.
func SecureWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncryptCredentialsForTest encrypts credentials using RSA public key.
// This is for testing only - in production, the control server does the encryption.
func (km *KeyManager) EncryptCredentialsForTest(creds *Credentials) (string, error) {
	jsonData, err := json.Marshal(creds)
	if err != nil {
		return "", err
	}

	if km.algorithm != "rsa-3072" {
		return "", fmt.Errorf("unsupported algorithm")
	}

	ciphertext, err := km.encryptRSAHybrid(jsonData)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// encryptRSAHybrid encrypts using hybrid RSA-OAEP + AES-GCM.
func (km *KeyManager) encryptRSAHybrid(plaintext []byte) ([]byte, error) {
	pubKey, ok := km.publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA public key")
	}

	// Generate random AES-256 key
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, err
	}
	defer SecureWipe(aesKey)

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Encrypt AES key with RSA-OAEP
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return nil, err
	}

	// Combine: encryptedKey + nonce + ciphertext
	result := make([]byte, 0, len(encryptedKey)+len(nonce)+len(ciphertext))
	result = append(result, encryptedKey...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}