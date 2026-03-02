package fido2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"

	"github.com/descope/virtualwebauthn"
)

// VirtualWebAuthnProvider uses the virtualwebauthn library for proper
// WebAuthn attestation and assertion generation. This provider generates
// attestations that pass verification by standard WebAuthn libraries.
type VirtualWebAuthnProvider struct {
	mu sync.Mutex

	// RPID is the relying party ID for this provider.
	RPID string

	// Origin is the origin for clientDataJSON.
	Origin string

	// Authenticator is the virtual authenticator.
	Authenticator virtualwebauthn.Authenticator

	// RelyingParty configuration.
	RelyingParty virtualwebauthn.RelyingParty

	// Credentials maps credential IDs to their virtualwebauthn.Credential.
	Credentials map[string]virtualwebauthn.Credential

	// PRFOutputs stores deterministic PRF outputs for credentials.
	// Key is credential ID string.
	PRFOutputs map[string]map[string][]byte

	// Error can be set to make operations return this error.
	Error error
}

// NewVirtualWebAuthnProvider creates a new provider with proper WebAuthn attestations.
func NewVirtualWebAuthnProvider(rpID, origin string) *VirtualWebAuthnProvider {
	if origin == "" {
		origin = "https://" + rpID
	}

	return &VirtualWebAuthnProvider{
		RPID:   rpID,
		Origin: origin,
		Authenticator: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
			UserNotPresent:  false,
			UserNotVerified: false,
		}),
		RelyingParty: virtualwebauthn.RelyingParty{
			ID:     rpID,
			Name:   rpID,
			Origin: origin,
		},
		Credentials: make(map[string]virtualwebauthn.Credential),
		PRFOutputs:  make(map[string]map[string][]byte),
	}
}

// WithError sets an error to be returned by all operations.
func (p *VirtualWebAuthnProvider) WithError(err error) *VirtualWebAuthnProvider {
	p.Error = err
	return p
}

// SupportsExtension checks if an extension is available.
func (p *VirtualWebAuthnProvider) SupportsExtension(ext ExtensionID) bool {
	// virtualwebauthn doesn't support PRF natively, but we simulate it
	return ext == ExtensionPRF || ext == ExtensionHMACSecret
}

// ListDevices returns a single virtual device.
func (p *VirtualWebAuthnProvider) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	if p.Error != nil {
		return nil, p.Error
	}
	return []DeviceInfo{
		{
			Path:         "virtualwebauthn://0",
			ProductName:  "Virtual WebAuthn Authenticator",
			Manufacturer: "go-siros-cli",
			HasPIN:       false,
			PRFSupported: true,
			IsFIDO2:      true,
			Extensions:   []string{"prf", "hmac-secret"},
			Options:      map[string]bool{"rk": true, "uv": true},
		},
	}, nil
}

// Register performs a WebAuthn registration with proper attestation format.
func (p *VirtualWebAuthnProvider) Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
	if p.Error != nil {
		return nil, p.Error
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Create a new credential using virtualwebauthn
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Create attestation options
	attOpts := virtualwebauthn.AttestationOptions{
		Challenge:        opts.Challenge,
		RelyingPartyID:   opts.RPID,
		RelyingPartyName: opts.RPName,
		UserID:           string(opts.UserID),
		UserName:         opts.UserName,
		UserDisplayName:  opts.UserDisplayName,
	}

	// Generate the attestation response
	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		p.RelyingParty,
		p.Authenticator,
		cred,
		attOpts,
	)

	// Parse the response to extract the parts we need
	var response struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			AttestationObject string `json:"attestationObject"`
			ClientDataJSON    string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := decodeJSON(attestationResponse, &response); err != nil {
		return nil, err
	}

	// Decode the attestation object and client data
	attestationObject, err := base64.RawURLEncoding.DecodeString(response.Response.AttestationObject)
	if err != nil {
		return nil, err
	}
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}

	// Store the credential
	credIDStr := string(cred.ID)
	p.Credentials[credIDStr] = cred
	p.Authenticator.AddCredential(cred)

	// Initialize PRF output storage for this credential
	p.PRFOutputs[credIDStr] = make(map[string][]byte)

	return &RegistrationResult{
		CredentialID:      cred.ID,
		PublicKey:         cred.Key.AttestationData(),
		AttestationObject: attestationObject,
		ClientDataJSON:    clientDataJSON,
		PRFSupported:      opts.EnablePRF,
	}, nil
}

// Authenticate performs a WebAuthn authentication with proper assertion format.
func (p *VirtualWebAuthnProvider) Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
	if p.Error != nil {
		return nil, p.Error
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Find matching credential
	var cred *virtualwebauthn.Credential
	if len(opts.AllowCredentials) > 0 {
		for _, allowedID := range opts.AllowCredentials {
			if c, ok := p.Credentials[string(allowedID)]; ok {
				cred = &c
				break
			}
		}
	} else {
		// Discoverable credential - find any credential for this RP
		for _, c := range p.Credentials {
			cred = &c
			break
		}
	}

	if cred == nil {
		return nil, ErrNoDeviceFound
	}

	// Build assertion options
	assertOpts := virtualwebauthn.AssertionOptions{
		Challenge:      opts.Challenge,
		RelyingPartyID: opts.RPID,
	}

	// Add allowed credentials
	for _, id := range opts.AllowCredentials {
		assertOpts.AllowCredentials = append(assertOpts.AllowCredentials, base64.RawURLEncoding.EncodeToString(id))
	}

	// Generate the assertion response
	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		p.RelyingParty,
		p.Authenticator,
		*cred,
		assertOpts,
	)

	// Parse the response
	var response struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle,omitempty"`
			ClientDataJSON    string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := decodeJSON(assertionResponse, &response); err != nil {
		return nil, err
	}

	// Decode the parts
	authData, err := base64.RawURLEncoding.DecodeString(response.Response.AuthenticatorData)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(response.Response.Signature)
	if err != nil {
		return nil, err
	}
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}

	var userHandle []byte
	if response.Response.UserHandle != "" {
		userHandle, _ = base64.RawURLEncoding.DecodeString(response.Response.UserHandle)
	}

	result := &AssertionResult{
		CredentialID:   cred.ID,
		AuthData:       authData,
		Signature:      signature,
		UserHandle:     userHandle,
		ClientDataJSON: clientDataJSON,
	}

	// Generate PRF output if requested
	if len(opts.PRFSalt1) > 0 {
		result.PRFOutput = p.generatePRFOutput(cred.ID, opts.PRFSalt1, opts.PRFSalt2)
	}

	return result, nil
}

// GetPRFOutput evaluates the PRF extension.
func (p *VirtualWebAuthnProvider) GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error) {
	if p.Error != nil {
		return nil, p.Error
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.Credentials[string(credential)]; !ok {
		return nil, ErrNoDeviceFound
	}

	return p.generatePRFOutput(credential, salt1, salt2), nil
}

// generatePRFOutput creates deterministic PRF output based on credential and salts.
func (p *VirtualWebAuthnProvider) generatePRFOutput(credentialID []byte, salt1, salt2 []byte) *PRFOutput {
	credIDStr := string(credentialID)
	saltKey := string(salt1) + "|" + string(salt2)

	// Check if we have a cached output
	if outputs, ok := p.PRFOutputs[credIDStr]; ok {
		if cached, ok := outputs[saltKey]; ok {
			// Return cached output
			if len(salt2) > 0 {
				return &PRFOutput{
					First:  cached[:32],
					Second: cached[32:],
				}
			}
			return &PRFOutput{First: cached[:32]}
		}
	}

	// Generate deterministic output based on credential ID and salts
	first := sha256.Sum256(append(credentialID, salt1...))

	output := &PRFOutput{
		First: first[:],
	}

	if len(salt2) > 0 {
		second := sha256.Sum256(append(credentialID, salt2...))
		output.Second = second[:]
	}

	// Cache the output
	if p.PRFOutputs[credIDStr] == nil {
		p.PRFOutputs[credIDStr] = make(map[string][]byte)
	}
	cached := append([]byte{}, output.First...)
	if output.Second != nil {
		cached = append(cached, output.Second...)
	}
	p.PRFOutputs[credIDStr][saltKey] = cached

	return output
}

// decodeJSON is a helper to decode JSON from a string.
func decodeJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

// Ensure VirtualWebAuthnProvider implements Provider interface
var _ Provider = (*VirtualWebAuthnProvider)(nil)
