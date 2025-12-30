// Package keystore handles encrypted wallet key storage.
package keystore

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Common errors
var (
	ErrKeystoreLocked      = errors.New("keystore is locked")
	ErrKeyNotFound         = errors.New("key not found")
	ErrInvalidContainer    = errors.New("invalid encrypted container")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrKeyDerivationFailed = errors.New("key derivation failed")
	ErrNoPRFKeyMatch       = errors.New("no matching PRF key found for credential")
)

// Manager handles encrypted keystore operations.
// It is compatible with the wallet-frontend's EncryptedContainer format.
type Manager interface {
	// IsLocked returns true if the keystore is locked.
	IsLocked() bool

	// Unlock decrypts the keystore using a PRF-derived key.
	// credentialID identifies which PRF key to use
	// prfOutput is the raw PRF output from WebAuthn assertion
	// encryptedData is the JSON-encoded EncryptedContainer
	Unlock(ctx context.Context, credentialID, prfOutput, encryptedData []byte) error

	// UnlockWithPassword decrypts the keystore using a password.
	UnlockWithPassword(ctx context.Context, password string, encryptedData []byte) error

	// Lock clears the decrypted keys from memory.
	Lock() error

	// GetPrivateKey retrieves a private key by DID or key ID.
	GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error)

	// ListKeys returns all available key IDs.
	ListKeys() ([]KeyInfo, error)

	// Sign creates a signature using the specified key.
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)

	// SignJWT creates a signed JWT using the specified key.
	SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error)

	// GetEncryptedData returns the encrypted keystore data for storage.
	GetEncryptedData() ([]byte, error)

	// GetPRFKeyInfos returns the PRF key infos for WebAuthn authentication.
	GetPRFKeyInfos(encryptedData []byte) ([]PRFKeyInfo, error)
}

// KeyInfo contains information about a stored key.
type KeyInfo struct {
	// KeyID is the key identifier (usually DID#fragment)
	KeyID string

	// DID is the decentralized identifier
	DID string

	// Algorithm is the signing algorithm (e.g., "ES256")
	Algorithm string

	// PublicKey is the JWK representation of the public key
	PublicKey map[string]interface{}
}

// PRFKeyInfo contains info needed for WebAuthn PRF authentication.
type PRFKeyInfo struct {
	CredentialID []byte
	Transports   []string
	PRFSalt      []byte
}

// EncryptedContainer represents the wallet-frontend compatible format.
// This matches the AsymmetricEncryptedContainer type from keystore.ts
type EncryptedContainer struct {
	// JWE is the encrypted wallet state
	JWE string `json:"jwe"`

	// MainKey contains the ephemeral encapsulation info
	MainKey *EphemeralEncapsulationInfo `json:"mainKey,omitempty"`

	// PasswordKey contains password-derived key info (optional)
	PasswordKey *AsymmetricPasswordKeyInfo `json:"passwordKey,omitempty"`

	// PRFKeys contains WebAuthn PRF key info
	PRFKeys []WebauthnPrfEncryptionKeyInfo `json:"prfKeys"`
}

// EphemeralEncapsulationInfo contains key encapsulation info for the main key.
type EphemeralEncapsulationInfo struct {
	PublicKey EncapsulationPublicKeyInfo `json:"publicKey"`
	UnwrapKey EphemeralUnwrapKeyInfo     `json:"unwrapKey"`
}

// EncapsulationPublicKeyInfo contains the public key for encapsulation.
type EncapsulationPublicKeyInfo struct {
	ImportKey ImportKeyInfo `json:"importKey"`
}

// ImportKeyInfo contains key import parameters.
type ImportKeyInfo struct {
	Format    string         `json:"format"`
	KeyData   TaggedBinary   `json:"keyData"`
	Algorithm EcKeyAlgorithm `json:"algorithm"`
}

// EcKeyAlgorithm represents EC key algorithm parameters.
type EcKeyAlgorithm struct {
	Name       string `json:"name"`
	NamedCurve string `json:"namedCurve"`
}

// EphemeralUnwrapKeyInfo contains key unwrapping parameters for the main key.
type EphemeralUnwrapKeyInfo struct {
	Format           string                 `json:"format"`
	UnwrapAlgo       string                 `json:"unwrapAlgo"`
	UnwrappedKeyAlgo map[string]interface{} `json:"unwrappedKeyAlgo"`
}

// AsymmetricPasswordKeyInfo contains password-derived key info.
type AsymmetricPasswordKeyInfo struct {
	Pbkdf2Params Pbkdf2Params             `json:"pbkdf2Params"`
	Algorithm    *AesKeyGenParams         `json:"algorithm,omitempty"`
	Keypair      EncapsulationKeypairInfo `json:"keypair"`
	UnwrapKey    StaticUnwrapKeyInfo      `json:"unwrapKey"`
}

// Pbkdf2Params contains PBKDF2 parameters.
type Pbkdf2Params struct {
	Name       string       `json:"name"`
	Salt       TaggedBinary `json:"salt"`
	Iterations int          `json:"iterations"`
	Hash       string       `json:"hash"`
}

// AesKeyGenParams contains AES key generation parameters.
type AesKeyGenParams struct {
	Name   string `json:"name"`
	Length int    `json:"length"`
}

// WebauthnPrfEncryptionKeyInfo contains PRF-derived key info (V2 format).
type WebauthnPrfEncryptionKeyInfo struct {
	CredentialID TaggedBinary             `json:"credentialId"`
	Transports   []string                 `json:"transports,omitempty"`
	PRFSalt      TaggedBinary             `json:"prfSalt"`
	HKDFSalt     TaggedBinary             `json:"hkdfSalt"`
	HKDFInfo     TaggedBinary             `json:"hkdfInfo"`
	Algorithm    *AesKeyGenParams         `json:"algorithm,omitempty"`
	Keypair      EncapsulationKeypairInfo `json:"keypair"`
	UnwrapKey    StaticUnwrapKeyInfo      `json:"unwrapKey"`
}

// EncapsulationKeypairInfo contains a keypair for key encapsulation.
type EncapsulationKeypairInfo struct {
	PublicKey  EncapsulationPublicKeyInfo  `json:"publicKey"`
	PrivateKey EncapsulationPrivateKeyInfo `json:"privateKey"`
}

// EncapsulationPrivateKeyInfo contains the wrapped private key.
type EncapsulationPrivateKeyInfo struct {
	UnwrapKey PrivateKeyUnwrapInfo `json:"unwrapKey"`
}

// PrivateKeyUnwrapInfo contains parameters for unwrapping the private key.
type PrivateKeyUnwrapInfo struct {
	Format           string         `json:"format"`
	WrappedKey       TaggedBinary   `json:"wrappedKey"`
	UnwrapAlgo       AesGcmParams   `json:"unwrapAlgo"`
	UnwrappedKeyAlgo EcKeyAlgorithm `json:"unwrappedKeyAlgo"`
}

// AesGcmParams contains AES-GCM parameters.
type AesGcmParams struct {
	Name string       `json:"name"`
	IV   TaggedBinary `json:"iv"`
}

// StaticUnwrapKeyInfo contains info for unwrapping the main key.
type StaticUnwrapKeyInfo struct {
	WrappedKey    TaggedBinary            `json:"wrappedKey"`
	UnwrappingKey EncapsulationUnwrapInfo `json:"unwrappingKey"`
}

// EncapsulationUnwrapInfo contains key derivation info.
type EncapsulationUnwrapInfo struct {
	DeriveKey DeriveKeyInfo `json:"deriveKey"`
}

// DeriveKeyInfo contains key derivation parameters.
type DeriveKeyInfo struct {
	Algorithm           DeriveKeyAlgorithm `json:"algorithm"`
	DerivedKeyAlgorithm AesKeyGenParams    `json:"derivedKeyAlgorithm"`
}

// DeriveKeyAlgorithm contains the algorithm name for key derivation.
type DeriveKeyAlgorithm struct {
	Name string `json:"name"`
}

// WalletStateContainer represents the decrypted wallet state container.
// This matches the WalletStateContainer from WalletStateSchema.ts
type WalletStateContainer struct {
	LastEventHash string            `json:"lastEventHash"`
	Events        []json.RawMessage `json:"events"`
	S             WalletState       `json:"S"`
}

// WalletState represents the wallet state.
type WalletState struct {
	SchemaVersion              int               `json:"schemaVersion"`
	Credentials                []json.RawMessage `json:"credentials"`
	Presentations              []json.RawMessage `json:"presentations"`
	Keypairs                   []StoredKeypair   `json:"keypairs"`
	CredentialIssuanceSessions []json.RawMessage `json:"credentialIssuanceSessions"`
	Settings                   json.RawMessage   `json:"settings"`
}

// StoredKeypair represents a stored key pair.
type StoredKeypair struct {
	KID     string      `json:"kid"`
	Keypair KeypairData `json:"keypair"`
}

// KeypairData contains the key data.
type KeypairData struct {
	KID        string                 `json:"kid"`
	DID        string                 `json:"did"`
	Algorithm  string                 `json:"alg"`
	PublicKey  map[string]interface{} `json:"publicKey"`
	PrivateKey map[string]interface{} `json:"privateKey"`
}

// TaggedBinary handles wallet-frontend's tagged binary format.
// Binary data is serialized as {"$b64u": "base64url-string"}.
type TaggedBinary []byte

// UnmarshalJSON implements json.Unmarshaler for TaggedBinary.
func (tb *TaggedBinary) UnmarshalJSON(data []byte) error {
	// Try tagged format first: {"$b64u": "..."}
	var tagged struct {
		B64U string `json:"$b64u"`
	}
	if err := json.Unmarshal(data, &tagged); err == nil && tagged.B64U != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(tagged.B64U)
		if err != nil {
			return err
		}
		*tb = decoded
		return nil
	}

	// Try plain base64url string (for backward compat)
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		decoded, err := base64.RawURLEncoding.DecodeString(str)
		if err != nil {
			// Try with padding
			decoded, err = base64.URLEncoding.DecodeString(str)
			if err != nil {
				return err
			}
		}
		*tb = decoded
		return nil
	}

	// Try raw bytes array
	var bytes []byte
	if err := json.Unmarshal(data, &bytes); err == nil {
		*tb = bytes
		return nil
	}

	return errors.New("invalid tagged binary format")
}

// MarshalJSON implements json.Marshaler for TaggedBinary.
func (tb TaggedBinary) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(tb)
	return json.Marshal(map[string]string{"$b64u": encoded})
}

// ToBase64URL returns the base64url encoded string.
func (tb TaggedBinary) ToBase64URL() string {
	return base64.RawURLEncoding.EncodeToString(tb)
}

// BytesEqual compares two byte slices for equality.
func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseEncryptedContainer parses JSON into an EncryptedContainer.
func ParseEncryptedContainer(data []byte) (*EncryptedContainer, error) {
	// The wallet-frontend uses jsonParseTaggedBinary which handles
	// {"$b64u": "..."} format for Uint8Array values.
	// Our TaggedBinary type handles this automatically.
	var container EncryptedContainer
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, err
	}
	return &container, nil
}

// FindPRFKeyByCredentialID finds a PRF key info by credential ID.
func (c *EncryptedContainer) FindPRFKeyByCredentialID(credentialID []byte) *WebauthnPrfEncryptionKeyInfo {
	// Also try base64url comparison for flexibility
	credIDStr := base64.RawURLEncoding.EncodeToString(credentialID)
	for i := range c.PRFKeys {
		if BytesEqual([]byte(c.PRFKeys[i].CredentialID), credentialID) {
			return &c.PRFKeys[i]
		}
		// Also compare base64url strings
		if c.PRFKeys[i].CredentialID.ToBase64URL() == credIDStr {
			return &c.PRFKeys[i]
		}
	}
	return nil
}

// GetPRFKeyInfos returns simplified PRF key info for WebAuthn authentication.
func (c *EncryptedContainer) GetPRFKeyInfos() []PRFKeyInfo {
	infos := make([]PRFKeyInfo, len(c.PRFKeys))
	for i, key := range c.PRFKeys {
		infos[i] = PRFKeyInfo{
			CredentialID: []byte(key.CredentialID),
			Transports:   key.Transports,
			PRFSalt:      []byte(key.PRFSalt),
		}
	}
	return infos
}

// GetCredentialIDs returns all credential IDs as base64url strings.
func (c *EncryptedContainer) GetCredentialIDs() []string {
	ids := make([]string, len(c.PRFKeys))
	for i, key := range c.PRFKeys {
		ids[i] = strings.TrimRight(base64.URLEncoding.EncodeToString(key.CredentialID), "=")
	}
	return ids
}
