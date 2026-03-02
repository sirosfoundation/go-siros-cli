package fido2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"sync"
)

// TestProvider is an enhanced mock implementation of the Provider interface
// for integration testing. Unlike the simpler test-only mock in provider_test.go,
// this provider actually generates cryptographic keys and can be used to test
// full authentication flows.
type TestProvider struct {
	mu sync.Mutex

	// RPID is the relying party ID for this provider.
	RPID string

	// Credentials stores registered credentials keyed by base64url credential ID.
	Credentials map[string]*TestCredential

	// SupportedExtensions lists extensions this provider supports.
	SupportedExtensions map[ExtensionID]bool

	// Devices lists the mock devices to return from ListDevices.
	Devices []DeviceInfo

	// Error can be set to make operations return this error.
	Error error

	// RegisterCallback is called during Register if set.
	RegisterCallback func(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error)

	// AuthenticateCallback is called during Authenticate if set.
	AuthenticateCallback func(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error)
}

// TestCredential represents a registered credential in the test provider.
type TestCredential struct {
	ID           CredentialID
	PrivateKey   *ecdsa.PrivateKey
	PublicKey    []byte
	UserID       []byte
	UserName     string
	RPID         string
	PRFSupported bool
	SignCount    uint32
	ResidentKey  bool
	Transports   []string
}

// NewTestProvider creates a new test FIDO2 provider with sensible defaults.
func NewTestProvider() *TestProvider {
	return &TestProvider{
		RPID:        "localhost",
		Credentials: make(map[string]*TestCredential),
		SupportedExtensions: map[ExtensionID]bool{
			ExtensionPRF:        true,
			ExtensionHMACSecret: true,
		},
		Devices: []DeviceInfo{
			{
				Path:         "test://device/0",
				ProductName:  "Test FIDO2 Device",
				Manufacturer: "Test",
				HasPIN:       false,
				PRFSupported: true,
				IsFIDO2:      true,
				Extensions:   []string{"prf", "hmac-secret"},
				Options:      map[string]bool{"rk": true, "uv": true},
			},
		},
	}
}

// WithRPID sets the relying party ID.
func (p *TestProvider) WithRPID(rpID string) *TestProvider {
	p.RPID = rpID
	return p
}

// WithError sets an error to be returned by all operations.
func (p *TestProvider) WithError(err error) *TestProvider {
	p.Error = err
	return p
}

// WithExtension enables or disables an extension.
func (p *TestProvider) WithExtension(ext ExtensionID, supported bool) *TestProvider {
	if p.SupportedExtensions == nil {
		p.SupportedExtensions = make(map[ExtensionID]bool)
	}
	p.SupportedExtensions[ext] = supported
	return p
}

// WithDevices sets the devices to return from ListDevices.
func (p *TestProvider) WithDevices(devices []DeviceInfo) *TestProvider {
	p.Devices = devices
	return p
}

// WithNoDevices configures the provider to return no devices.
func (p *TestProvider) WithNoDevices() *TestProvider {
	p.Devices = nil
	return p
}

// SupportsExtension checks if an extension is available.
func (p *TestProvider) SupportsExtension(ext ExtensionID) bool {
	if p.SupportedExtensions == nil {
		return false
	}
	return p.SupportedExtensions[ext]
}

// ListDevices returns the configured mock devices.
func (p *TestProvider) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	if p.Error != nil {
		return nil, p.Error
	}
	if len(p.Devices) == 0 {
		return nil, ErrNoDeviceFound
	}
	return p.Devices, nil
}

// Register performs a test WebAuthn registration that generates real keys.
func (p *TestProvider) Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
	if p.Error != nil {
		return nil, p.Error
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Use callback if set
	if p.RegisterCallback != nil {
		return p.RegisterCallback(ctx, opts)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate a new credential
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate credential ID
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		return nil, err
	}

	// Build public key in uncompressed point format using ECDH
	ecdhKey, err := privateKey.ECDH()
	if err != nil {
		return nil, err
	}
	publicKeyBytes := ecdhKey.PublicKey().Bytes()

	// Store the credential
	cred := &TestCredential{
		ID:           credentialID,
		PrivateKey:   privateKey,
		PublicKey:    publicKeyBytes,
		UserID:       opts.UserID,
		UserName:     opts.UserName,
		RPID:         opts.RPID,
		PRFSupported: opts.EnablePRF && p.SupportsExtension(ExtensionPRF),
		ResidentKey:  opts.ResidentKey,
		Transports:   []string{"usb"},
	}
	p.Credentials[string(credentialID)] = cred

	// Build clientDataJSON
	clientData := map[string]interface{}{
		"type":        "webauthn.create",
		"challenge":   opts.Challenge,
		"origin":      "https://" + opts.RPID,
		"crossOrigin": false,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	// Build a minimal attestation object
	attestationObject := p.buildAttestationObject(publicKeyBytes, credentialID, opts.RPID)

	return &RegistrationResult{
		CredentialID:      credentialID,
		PublicKey:         publicKeyBytes,
		AttestationObject: attestationObject,
		ClientDataJSON:    clientDataJSON,
		PRFSupported:      cred.PRFSupported,
	}, nil
}

// Authenticate performs a test WebAuthn authentication with real signatures.
func (p *TestProvider) Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
	if p.Error != nil {
		return nil, p.Error
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Use callback if set
	if p.AuthenticateCallback != nil {
		return p.AuthenticateCallback(ctx, opts)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Find matching credential
	var cred *TestCredential
	if len(opts.AllowCredentials) > 0 {
		for _, allowedID := range opts.AllowCredentials {
			if c, ok := p.Credentials[string(allowedID)]; ok {
				cred = c
				break
			}
		}
	} else {
		// Discoverable credential - find any credential for this RP
		for _, c := range p.Credentials {
			if c.RPID == opts.RPID && c.ResidentKey {
				cred = c
				break
			}
		}
	}

	if cred == nil {
		return nil, ErrNoDeviceFound
	}

	// Increment sign counter
	cred.SignCount++

	// Build clientDataJSON
	clientData := map[string]interface{}{
		"type":        "webauthn.get",
		"challenge":   opts.Challenge,
		"origin":      "https://" + opts.RPID,
		"crossOrigin": false,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	// Build authenticator data
	authData := p.buildAuthData(opts.RPID, cred.SignCount)

	// Sign the data
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(signedData)

	r, s, err := ecdsa.Sign(rand.Reader, cred.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}

	// Create signature (fixed size for P-256: 32+32 bytes)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	result := &AssertionResult{
		CredentialID:   cred.ID,
		AuthData:       authData,
		Signature:      signature,
		UserHandle:     cred.UserID,
		ClientDataJSON: clientDataJSON,
	}

	// Generate PRF output if requested
	if len(opts.PRFSalt1) > 0 && cred.PRFSupported {
		result.PRFOutput = p.generatePRFOutput(cred, opts.PRFSalt1, opts.PRFSalt2)
	}

	return result, nil
}

// GetPRFOutput evaluates the PRF extension.
func (p *TestProvider) GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error) {
	if p.Error != nil {
		return nil, p.Error
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	cred, ok := p.Credentials[string(credential)]
	if !ok {
		return nil, ErrNoDeviceFound
	}

	if !cred.PRFSupported {
		return nil, ErrPRFNotSupported
	}

	return p.generatePRFOutput(cred, salt1, salt2), nil
}

// generatePRFOutput creates deterministic PRF output based on the credential and salts.
func (p *TestProvider) generatePRFOutput(cred *TestCredential, salt1, salt2 []byte) *PRFOutput {
	// Generate deterministic output based on credential ID and salts
	first := sha256.Sum256(append(cred.ID, salt1...))

	output := &PRFOutput{
		First: first[:],
	}

	if len(salt2) > 0 {
		second := sha256.Sum256(append(cred.ID, salt2...))
		output.Second = second[:]
	}

	return output
}

// AddCredential adds a pre-existing credential to the provider.
func (p *TestProvider) AddCredential(cred *TestCredential) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Credentials == nil {
		p.Credentials = make(map[string]*TestCredential)
	}
	p.Credentials[string(cred.ID)] = cred
}

// GetCredential returns a credential by ID.
func (p *TestProvider) GetCredential(id CredentialID) *TestCredential {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Credentials[string(id)]
}

// ClearCredentials removes all stored credentials.
func (p *TestProvider) ClearCredentials() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Credentials = make(map[string]*TestCredential)
}

// buildAuthData creates authenticator data.
func (p *TestProvider) buildAuthData(rpID string, signCount uint32) []byte {
	// RP ID hash (32 bytes)
	rpIDHash := sha256.Sum256([]byte(rpID))

	// Flags: UP=1, UV=1
	flags := byte(0x05)

	// Sign count (4 bytes, big-endian)
	signCountBytes := []byte{
		byte(signCount >> 24),
		byte(signCount >> 16),
		byte(signCount >> 8),
		byte(signCount),
	}

	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, signCountBytes...)

	return authData
}

// buildAttestationObject creates a minimal attestation object.
func (p *TestProvider) buildAttestationObject(publicKey, credentialID []byte, rpID string) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	flags := byte(0x45) // UP + UV + AT

	authData := make([]byte, 0, 37+len(credentialID)+len(publicKey)+100)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, 0, 0, 0, 0) // sign count = 0

	// AAGUID (16 bytes of zeros for test)
	authData = append(authData, make([]byte, 16)...)

	// Credential ID length (2 bytes, big-endian)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))

	// Credential ID
	authData = append(authData, credentialID...)

	// Public key
	authData = append(authData, publicKey...)

	return authData
}

// Ensure TestProvider implements Provider interface
var _ Provider = (*TestProvider)(nil)
