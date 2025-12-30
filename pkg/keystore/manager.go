package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// DefaultManager is the default implementation of Manager.
type DefaultManager struct {
	mu            sync.RWMutex
	locked        bool
	encryptedData []byte
	container     *WalletStateContainer
	privateKeys   map[string]*ecdsa.PrivateKey
}

// NewManager creates a new keystore manager.
func NewManager() *DefaultManager {
	return &DefaultManager{
		locked:      true,
		privateKeys: make(map[string]*ecdsa.PrivateKey),
	}
}

// IsLocked returns true if the keystore is locked.
func (m *DefaultManager) IsLocked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.locked
}

// Unlock decrypts the keystore using a PRF-derived key.
// credentialID identifies which PRF key to use
// prfOutput is the raw PRF output from WebAuthn assertion
// encryptedData is the JSON-encoded EncryptedContainer
func (m *DefaultManager) Unlock(ctx context.Context, credentialID, prfOutput, encryptedData []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Parse the EncryptedContainer
	container, err := ParseEncryptedContainer(encryptedData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}

	// 2. Find the matching PRF key info based on credential ID
	prfKeyInfo := container.FindPRFKeyByCredentialID(credentialID)
	if prfKeyInfo == nil {
		return ErrNoPRFKeyMatch
	}

	// 3. Derive the base wrapping key using HKDF from PRF output
	baseWrappingKey, err := derivePrfKey(prfOutput, prfKeyInfo)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err)
	}

	// 4. Unwrap the main key using ECDH-ES+A256KW
	mainKey, err := decapsulateMainKey(baseWrappingKey, container.MainKey, prfKeyInfo)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// 5. Decrypt the JWE content
	walletContainer, err := decryptJWE(container.JWE, mainKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// 6. Parse private keys from wallet state
	privateKeys, err := extractPrivateKeys(walletContainer)
	if err != nil {
		return fmt.Errorf("failed to extract private keys: %w", err)
	}

	m.encryptedData = encryptedData
	m.container = walletContainer
	m.privateKeys = privateKeys
	m.locked = false

	return nil
}

// UnlockWithPassword decrypts the keystore using a password.
func (m *DefaultManager) UnlockWithPassword(ctx context.Context, password string, encryptedData []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Parse the EncryptedContainer
	container, err := ParseEncryptedContainer(encryptedData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}

	if container.PasswordKey == nil {
		return fmt.Errorf("no password key configured")
	}

	// 2. Derive password key using PBKDF2
	baseWrappingKey, err := derivePasswordKey(password, container.PasswordKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err)
	}

	// 3. Unwrap the main key
	mainKey, err := decapsulateMainKeyFromPassword(baseWrappingKey, container.MainKey, container.PasswordKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// 4. Decrypt the JWE content
	walletContainer, err := decryptJWE(container.JWE, mainKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// 5. Parse private keys
	privateKeys, err := extractPrivateKeys(walletContainer)
	if err != nil {
		return fmt.Errorf("failed to extract private keys: %w", err)
	}

	m.encryptedData = encryptedData
	m.container = walletContainer
	m.privateKeys = privateKeys
	m.locked = false

	return nil
}

// Lock clears the decrypted keys from memory.
func (m *DefaultManager) Lock() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear all private keys from memory
	for k := range m.privateKeys {
		delete(m.privateKeys, k)
	}
	m.container = nil
	m.locked = true

	return nil
}

// GetPrivateKey retrieves a private key by DID or key ID.
func (m *DefaultManager) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.locked {
		return nil, ErrKeystoreLocked
	}

	key, ok := m.privateKeys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return key, nil
}

// ListKeys returns all available key IDs.
func (m *DefaultManager) ListKeys() ([]KeyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.locked {
		return nil, ErrKeystoreLocked
	}

	if m.container == nil {
		return []KeyInfo{}, nil
	}

	keys := make([]KeyInfo, len(m.container.S.Keypairs))
	for i, kp := range m.container.S.Keypairs {
		keys[i] = KeyInfo{
			KeyID:     kp.KID,
			DID:       kp.Keypair.DID,
			Algorithm: kp.Keypair.Algorithm,
			PublicKey: kp.Keypair.PublicKey,
		}
	}

	return keys, nil
}

// Sign creates a signature using the specified key.
func (m *DefaultManager) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.locked {
		return nil, ErrKeystoreLocked
	}

	key, ok := m.privateKeys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Hash the data and sign
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Return signature in IEEE P1363 format (r || s)
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	r.FillBytes(sig[:byteLen])
	s.FillBytes(sig[byteLen:])

	return sig, nil
}

// SignJWT creates a signed JWT using the specified key.
func (m *DefaultManager) SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.locked {
		return "", ErrKeystoreLocked
	}

	key, ok := m.privateKeys[keyID]
	if !ok {
		return "", ErrKeyNotFound
	}

	// Find the algorithm for this key
	var alg string
	for _, kp := range m.container.S.Keypairs {
		if kp.KID == keyID {
			alg = kp.Keypair.Algorithm
			break
		}
	}
	if alg == "" {
		alg = "ES256" // Default to ES256
	}

	// Create signer
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Add standard claims if not present
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}

	// Encode claims
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Sign
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return jws.CompactSerialize()
}

// GetEncryptedData returns the encrypted keystore data for storage.
func (m *DefaultManager) GetEncryptedData() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.encryptedData == nil {
		return nil, fmt.Errorf("no encrypted data available")
	}

	return m.encryptedData, nil
}

// GetPRFKeyInfos returns the PRF key infos for WebAuthn authentication.
func (m *DefaultManager) GetPRFKeyInfos(encryptedData []byte) ([]PRFKeyInfo, error) {
	container, err := ParseEncryptedContainer(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}
	return container.GetPRFKeyInfos(), nil
}

// Ensure DefaultManager implements Manager
var _ Manager = (*DefaultManager)(nil)

// --- Helper functions for key derivation and decryption ---

// derivePrfKey derives the base wrapping key from PRF output using HKDF.
func derivePrfKey(prfOutput []byte, keyInfo *WebauthnPrfEncryptionKeyInfo) ([]byte, error) {
	// HKDF with SHA-256
	hkdf := hkdf.New(sha256.New, prfOutput, []byte(keyInfo.HKDFSalt), []byte(keyInfo.HKDFInfo))

	// Default to AES-256 (32 bytes)
	keyLen := 32
	if keyInfo.Algorithm != nil && keyInfo.Algorithm.Length > 0 {
		keyLen = keyInfo.Algorithm.Length / 8
	}

	key := make([]byte, keyLen)
	if _, err := hkdf.Read(key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}

	return key, nil
}

// derivePasswordKey derives the base wrapping key from password using PBKDF2.
func derivePasswordKey(password string, keyInfo *AsymmetricPasswordKeyInfo) ([]byte, error) {
	// Default to AES-256 (32 bytes) with AES-GCM
	keyLen := 32
	if keyInfo.Algorithm != nil && keyInfo.Algorithm.Length > 0 {
		keyLen = keyInfo.Algorithm.Length / 8
	}

	// PBKDF2 with SHA-256
	salt := []byte(keyInfo.Pbkdf2Params.Salt)
	iterations := keyInfo.Pbkdf2Params.Iterations
	if iterations == 0 {
		iterations = 600000 // Default from wallet-frontend
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)
	return key, nil
}

// decapsulateMainKey unwraps the main key using ECDH key agreement.
// This implements the decapsulateKey function from wallet-frontend.
func decapsulateMainKey(baseWrappingKey []byte, ephemeralInfo *EphemeralEncapsulationInfo, staticInfo *WebauthnPrfEncryptionKeyInfo) ([]byte, error) {
	// 1. Unwrap the encapsulation private key using AES-GCM
	encapPrivateKey, err := unwrapEncapsulationPrivateKey(baseWrappingKey, &staticInfo.Keypair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap encapsulation private key: %w", err)
	}

	// 2. Import the ephemeral public key
	ephemeralPublicKey, err := importECDHPublicKey([]byte(ephemeralInfo.PublicKey.ImportKey.KeyData))
	if err != nil {
		return nil, fmt.Errorf("failed to import ephemeral public key: %w", err)
	}

	// 3. Perform ECDH to derive the wrapping key
	wrappingKey, err := ecdhDeriveKey(encapPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key derivation failed: %w", err)
	}

	// 4. Unwrap the main key using AES-KW
	mainKey, err := aesKeyUnwrap(wrappingKey, []byte(staticInfo.UnwrapKey.WrappedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap main key: %w", err)
	}

	return mainKey, nil
}

// decapsulateMainKeyFromPassword unwraps the main key using password-derived key.
func decapsulateMainKeyFromPassword(baseWrappingKey []byte, ephemeralInfo *EphemeralEncapsulationInfo, staticInfo *AsymmetricPasswordKeyInfo) ([]byte, error) {
	// 1. Unwrap the encapsulation private key using AES-GCM
	encapPrivateKey, err := unwrapEncapsulationPrivateKey(baseWrappingKey, &staticInfo.Keypair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap encapsulation private key: %w", err)
	}

	// 2. Import the ephemeral public key
	ephemeralPublicKey, err := importECDHPublicKey([]byte(ephemeralInfo.PublicKey.ImportKey.KeyData))
	if err != nil {
		return nil, fmt.Errorf("failed to import ephemeral public key: %w", err)
	}

	// 3. Perform ECDH to derive the wrapping key
	wrappingKey, err := ecdhDeriveKey(encapPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key derivation failed: %w", err)
	}

	// 4. Unwrap the main key using AES-KW
	mainKey, err := aesKeyUnwrap(wrappingKey, []byte(staticInfo.UnwrapKey.WrappedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap main key: %w", err)
	}

	return mainKey, nil
}

// unwrapEncapsulationPrivateKey unwraps the encapsulation private key using AES-GCM.
func unwrapEncapsulationPrivateKey(baseWrappingKey []byte, info *EncapsulationPrivateKeyInfo) (*ecdh.PrivateKey, error) {
	// Create AES-GCM cipher
	block, err := aes.NewCipher(baseWrappingKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt the wrapped key
	iv := []byte(info.UnwrapKey.UnwrapAlgo.IV)
	wrappedKey := []byte(info.UnwrapKey.WrappedKey)

	plaintext, err := gcm.Open(nil, iv, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	// Parse JWK from plaintext
	var jwk map[string]interface{}
	if err := json.Unmarshal(plaintext, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	// Extract d parameter (private key scalar)
	dStr, ok := jwk["d"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'd' parameter in JWK")
	}

	d, err := base64.RawURLEncoding.DecodeString(dStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'd' parameter: %w", err)
	}

	// Import as ECDH P-256 private key
	return ecdh.P256().NewPrivateKey(d)
}

// importECDHPublicKey imports a raw ECDH public key (uncompressed point format).
func importECDHPublicKey(rawKey []byte) (*ecdh.PublicKey, error) {
	return ecdh.P256().NewPublicKey(rawKey)
}

// ecdhDeriveKey performs ECDH and derives an AES-KW key.
func ecdhDeriveKey(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	// Perform ECDH
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}

	// For AES-KW, we use the raw shared secret as the key
	// (wallet-frontend uses SubtleCrypto.deriveKey with name="ECDH" which does this)
	// The shared secret is already 32 bytes for P-256
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("shared secret too short: %d bytes", len(sharedSecret))
	}

	// Use first 32 bytes for AES-256-KW
	return sharedSecret[:32], nil
}

// aesKeyUnwrap implements AES Key Unwrap (RFC 3394).
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) / 8) - 1
	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:(i+2)*8])
	}

	// 6 rounds
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// A ^ t
			t := uint64(n*j + i + 1)
			for k := 0; k < 8; k++ {
				a[7-k] ^= byte(t >> (8 * k))
			}

			// B = AES-1(K, (A ^ t) | R[i])
			b := make([]byte, 16)
			copy(b[:8], a)
			copy(b[8:], r[i])
			block.Decrypt(b, b)

			copy(a, b[:8])
			copy(r[i], b[8:])
		}
	}

	// Check IV (A should be 0xA6A6A6A6A6A6A6A6)
	expectedIV := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	for i := 0; i < 8; i++ {
		if a[i] != expectedIV[i] {
			return nil, fmt.Errorf("AES-KW integrity check failed")
		}
	}

	// Concatenate R blocks
	plaintext := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		plaintext = append(plaintext, r[i]...)
	}

	return plaintext, nil
}

// decryptJWE decrypts a JWE using the main key.
func decryptJWE(jweString string, mainKey []byte) (*WalletStateContainer, error) {
	// Parse the JWE
	jwe, err := jose.ParseEncrypted(jweString, []jose.KeyAlgorithm{jose.A256GCMKW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	// Decrypt
	plaintext, err := jwe.Decrypt(mainKey)
	if err != nil {
		return nil, fmt.Errorf("JWE decryption failed: %w", err)
	}

	// Parse the wallet state container (with tagged binary support)
	var container WalletStateContainer
	if err := json.Unmarshal(plaintext, &container); err != nil {
		return nil, fmt.Errorf("failed to parse wallet state: %w", err)
	}

	return &container, nil
}

// extractPrivateKeys extracts ECDSA private keys from the wallet state.
func extractPrivateKeys(container *WalletStateContainer) (map[string]*ecdsa.PrivateKey, error) {
	keys := make(map[string]*ecdsa.PrivateKey)

	for _, kp := range container.S.Keypairs {
		privateKey, err := jwkToECDSAPrivateKey(kp.Keypair.PrivateKey)
		if err != nil {
			// Log but continue - some keys might not be ECDSA
			continue
		}
		keys[kp.KID] = privateKey
		// Also store by DID
		if kp.Keypair.DID != "" && kp.Keypair.DID != kp.KID {
			keys[kp.Keypair.DID] = privateKey
		}
	}

	return keys, nil
}

// jwkToECDSAPrivateKey converts a JWK to an ECDSA private key.
func jwkToECDSAPrivateKey(jwk map[string]interface{}) (*ecdsa.PrivateKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	crv, _ := jwk["crv"].(string)
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	// Decode x, y, d
	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)
	dStr, _ := jwk["d"].(string)

	x, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}
	d, err := base64.RawURLEncoding.DecodeString(dStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode d: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}, nil
}
