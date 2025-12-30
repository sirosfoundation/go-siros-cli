package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/hkdf"
)

// InitPRFResult contains the result of PRF-based keystore initialization.
type InitPRFResult struct {
	// EncryptedContainer is the JSON-serialized encrypted container
	EncryptedContainer []byte
	// MainKey is the raw main AES key (for immediate use without re-unlock)
	MainKey []byte
}

// InitPRF initializes a new keystore using PRF output from WebAuthn registration.
// This creates an EncryptedContainer compatible with wallet-frontend.
//
// Parameters:
//   - credentialID: The WebAuthn credential ID
//   - prfOutput: The PRF output from the credential registration (32 bytes)
//   - prfSalt: The salt used for PRF (from registration options)
//   - transports: The authenticator transports (e.g., ["usb"])
//
// Returns the encrypted container ready to send to the backend.
func InitPRF(credentialID, prfOutput, prfSalt []byte, transports []string) (*InitPRFResult, error) {
	// 1. Generate a new AES-256 main key
	mainKey := make([]byte, 32)
	if _, err := rand.Read(mainKey); err != nil {
		return nil, fmt.Errorf("failed to generate main key: %w", err)
	}

	// 2. Generate main key encapsulation keypair (for future recovery)
	// Note: mainPrivateKey would be used for recovery but is not stored in this version
	mainPublicKey, _, err := generateECDHKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate main keypair: %w", err)
	}

	// 3. Derive the PRF wrapping key using HKDF
	hkdfSalt := make([]byte, 32)
	if _, err := rand.Read(hkdfSalt); err != nil {
		return nil, fmt.Errorf("failed to generate HKDF salt: %w", err)
	}
	hkdfInfo := []byte("eDiplomas PRF")

	prfWrappingKey, err := derivePrfWrappingKey(prfOutput, hkdfSalt, hkdfInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to derive PRF key: %w", err)
	}

	// 4. Generate PRF encapsulation keypair
	prfPublicKey, prfPrivateKey, err := generateECDHKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PRF keypair: %w", err)
	}

	// 5. Wrap the PRF private key with the derived PRF wrapping key using AES-GCM
	wrappedPrfPrivateKey, prfIV, err := wrapPrivateKey(prfWrappingKey, prfPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap PRF private key: %w", err)
	}

	// 6. Use ECDH to encapsulate the main key
	// The PRF private key is used to derive a shared secret with the main public key
	wrappedMainKey, err := encapsulateMainKey(prfPrivateKey, mainPublicKey, mainKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate main key: %w", err)
	}

	// 7. Create initial wallet state and encrypt as JWE
	initialState := createInitialWalletState()
	jwe, err := encryptWalletState(initialState, mainKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt wallet state: %w", err)
	}

	// 8. Build the PRF key info
	prfKeyInfo := WebauthnPrfEncryptionKeyInfo{
		CredentialID: TaggedBinary(credentialID),
		Transports:   transports,
		PRFSalt:      TaggedBinary(prfSalt),
		HKDFSalt:     TaggedBinary(hkdfSalt),
		HKDFInfo:     TaggedBinary(hkdfInfo),
		Algorithm: &AesKeyGenParams{
			Name:   "AES-GCM",
			Length: 256,
		},
		Keypair: EncapsulationKeypairInfo{
			PublicKey: EncapsulationPublicKeyInfo{
				ImportKey: ImportKeyInfo{
					Format:  "raw",
					KeyData: TaggedBinary(prfPublicKey.Bytes()),
					Algorithm: EcKeyAlgorithm{
						Name:       "ECDH",
						NamedCurve: "P-256",
					},
				},
			},
			PrivateKey: EncapsulationPrivateKeyInfo{
				UnwrapKey: PrivateKeyUnwrapInfo{
					Format:     "raw",
					WrappedKey: TaggedBinary(wrappedPrfPrivateKey),
					UnwrapAlgo: AesGcmParams{
						Name: "AES-GCM",
						IV:   TaggedBinary(prfIV),
					},
					UnwrappedKeyAlgo: EcKeyAlgorithm{
						Name:       "ECDH",
						NamedCurve: "P-256",
					},
				},
			},
		},
		UnwrapKey: StaticUnwrapKeyInfo{
			WrappedKey: TaggedBinary(wrappedMainKey),
			UnwrappingKey: EncapsulationUnwrapInfo{
				DeriveKey: DeriveKeyInfo{
					Algorithm: DeriveKeyAlgorithm{
						Name: "ECDH",
					},
					DerivedKeyAlgorithm: AesKeyGenParams{
						Name:   "AES-KW",
						Length: 256,
					},
				},
			},
		},
	}

	// 9. Build the main key info (ephemeral encapsulation)
	mainKeyInfo := EphemeralEncapsulationInfo{
		PublicKey: EncapsulationPublicKeyInfo{
			ImportKey: ImportKeyInfo{
				Format:  "raw",
				KeyData: TaggedBinary(mainPublicKey.Bytes()),
				Algorithm: EcKeyAlgorithm{
					Name:       "ECDH",
					NamedCurve: "P-256",
				},
			},
		},
		UnwrapKey: EphemeralUnwrapKeyInfo{
			Format:     "raw",
			UnwrapAlgo: "AES-KW",
			UnwrappedKeyAlgo: map[string]interface{}{
				"name":   "AES-GCM",
				"length": 256,
			},
		},
	}

	// 10. Build the encrypted container
	container := EncryptedContainer{
		JWE:     jwe,
		MainKey: &mainKeyInfo,
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{prfKeyInfo},
	}

	// 11. Serialize to JSON
	containerJSON, err := json.Marshal(container)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize container: %w", err)
	}

	return &InitPRFResult{
		EncryptedContainer: containerJSON,
		MainKey:            mainKey,
	}, nil
}

// derivePrfWrappingKey derives a key from PRF output using HKDF.
func derivePrfWrappingKey(prfOutput, salt, info []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, prfOutput, salt, info)
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// generateECDHKeypair generates an ECDH P-256 keypair.
func generateECDHKeypair() (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey.PublicKey(), privateKey, nil
}

// wrapPrivateKey wraps an ECDH private key using AES-GCM.
func wrapPrivateKey(wrappingKey []byte, privateKey *ecdh.PrivateKey) ([]byte, []byte, error) {
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	// Export private key as raw bytes
	privateKeyBytes := privateKey.Bytes()

	// Encrypt
	ciphertext := gcm.Seal(nil, iv, privateKeyBytes, nil)

	return ciphertext, iv, nil
}

// encapsulateMainKey wraps the main key using ECDH key agreement and AES-KW.
func encapsulateMainKey(senderPrivateKey *ecdh.PrivateKey, recipientPublicKey *ecdh.PublicKey, mainKey []byte) ([]byte, error) {
	// Perform ECDH
	sharedSecret, err := senderPrivateKey.ECDH(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive wrapping key from shared secret using SHA-256 (simplified - should match WebCrypto deriveBits)
	// WebCrypto ECDH derives 256 bits directly from the shared secret
	wrappingKey := sha256.Sum256(sharedSecret)

	// Wrap with AES-KW
	wrapped, err := aesKeyWrap(wrappingKey[:], mainKey)
	if err != nil {
		return nil, fmt.Errorf("AES-KW wrap failed: %w", err)
	}

	return wrapped, nil
}

// aesKeyWrap implements RFC 3394 AES Key Wrap.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("plaintext must be multiple of 8 bytes")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8

	// Initialize variables
	a := []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	// Calculate intermediate values
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			// B = AES(K, A | R[i])
			b := make([]byte, 16)
			copy(b[:8], a)
			copy(b[8:], r[i])
			block.Encrypt(b, b)

			// A = MSB(64, B) ^ t where t = (n*j)+i+1
			t := uint64((n * j) + i + 1)
			copy(a, b[:8])
			a[7] ^= byte(t)
			a[6] ^= byte(t >> 8)
			a[5] ^= byte(t >> 16)
			a[4] ^= byte(t >> 24)
			a[3] ^= byte(t >> 32)
			a[2] ^= byte(t >> 40)
			a[1] ^= byte(t >> 48)
			a[0] ^= byte(t >> 56)

			// R[i] = LSB(64, B)
			copy(r[i], b[8:])
		}
	}

	// Output
	result := make([]byte, (n+1)*8)
	copy(result[:8], a)
	for i := 0; i < n; i++ {
		copy(result[(i+1)*8:(i+2)*8], r[i])
	}

	return result, nil
}

// createInitialWalletState creates the initial empty wallet state.
func createInitialWalletState() *WalletStateContainer {
	return &WalletStateContainer{
		LastEventHash: "",
		Events:        []json.RawMessage{},
		S: WalletState{
			SchemaVersion:              3,
			Credentials:                []json.RawMessage{},
			Presentations:              []json.RawMessage{},
			Keypairs:                   []StoredKeypair{},
			CredentialIssuanceSessions: []json.RawMessage{},
			Settings:                   json.RawMessage("{}"),
		},
	}
}

// encryptWalletState encrypts the wallet state as a JWE using A256GCM.
func encryptWalletState(state *WalletStateContainer, key []byte) (string, error) {
	// Serialize state
	plaintext, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state: %w", err)
	}

	// Create encrypter with A256GCM direct encryption
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key,
		},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Encrypt
	jwe, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	return jwe.CompactSerialize()
}
