//go:build sdk

// Package sdk provides integration with the go-wallet-backend native SDK.
// This package bridges the existing go-siros-cli packages with the SDK
// interfaces, enabling unified wallet functionality.
package sdk

import (
	"context"
	"fmt"

	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
	native "github.com/sirosfoundation/go-wallet-backend/sdk/native"
)

// Ensure type compatibility at compile time
var (
	_ native.BackendConnection = (*BackendAdapter)(nil)
	_ native.AuthProvider      = (*AuthProviderAdapter)(nil)
	_ native.KeystoreManager   = (*KeystoreAdapter)(nil)
)

// BackendAdapter wraps backend.Client to implement native.BackendConnection.
type BackendAdapter struct {
	client *backend.Client
}

// NewBackendAdapter creates a new backend adapter.
func NewBackendAdapter(client *backend.Client) *BackendAdapter {
	return &BackendAdapter{client: client}
}

// Status checks backend status.
func (a *BackendAdapter) Status(ctx context.Context) (*native.StatusResponse, error) {
	resp, err := a.client.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &native.StatusResponse{
		Status:  resp.Status,
		Service: resp.Service,
	}, nil
}

// StartRegistration begins WebAuthn registration.
func (a *BackendAdapter) StartRegistration(ctx context.Context, displayName string) (*native.RegistrationChallenge, error) {
	resp, err := a.client.StartRegistration(ctx, displayName)
	if err != nil {
		return nil, err
	}

	challenge := &native.RegistrationChallenge{
		ChallengeID: resp.ChallengeID,
	}

	// Parse createOptions to extract challenge details
	if pk, ok := resp.CreateOptions["publicKey"].(map[string]interface{}); ok {
		if rp, ok := pk["rp"].(map[string]interface{}); ok {
			challenge.RPID, _ = rp["id"].(string)
			challenge.RPName, _ = rp["name"].(string)
		}
		if user, ok := pk["user"].(map[string]interface{}); ok {
			if id, ok := user["id"].(string); ok {
				challenge.UserID = []byte(id)
			}
			challenge.UserName, _ = user["name"].(string)
		}
		if ch, ok := pk["challenge"].(string); ok {
			challenge.Challenge = []byte(ch)
		}
		if params, ok := pk["pubKeyCredParams"].([]interface{}); ok {
			for _, p := range params {
				if pm, ok := p.(map[string]interface{}); ok {
					if alg, ok := pm["alg"].(float64); ok {
						challenge.Algorithms = append(challenge.Algorithms, int(alg))
					}
				}
			}
		}
	}

	return challenge, nil
}

// FinishRegistration completes WebAuthn registration.
func (a *BackendAdapter) FinishRegistration(ctx context.Context, req *native.RegistrationResponse) (*native.AuthResult, error) {
	backendReq := &backend.RegistrationFinishRequest{
		ChallengeID: req.ChallengeID,
		Credential: map[string]interface{}{
			"id":    string(req.CredentialID),
			"type":  "public-key",
			"rawId": string(req.CredentialID),
			"response": map[string]interface{}{
				"attestationObject": string(req.AttestationObject),
				"clientDataJSON":    string(req.ClientDataJSON),
			},
		},
	}

	resp, err := a.client.FinishRegistration(ctx, backendReq)
	if err != nil {
		return nil, err
	}

	return &native.AuthResult{
		UserID:      resp.UUID,
		Token:       resp.Token,
		DisplayName: resp.DisplayName,
		RpID:        resp.WebauthnRpId,
	}, nil
}

// StartLogin begins WebAuthn login.
func (a *BackendAdapter) StartLogin(ctx context.Context) (*native.LoginChallenge, error) {
	resp, err := a.client.StartLogin(ctx)
	if err != nil {
		return nil, err
	}

	challenge := &native.LoginChallenge{
		ChallengeID: resp.ChallengeID,
	}

	if pk, ok := resp.GetOptions["publicKey"].(map[string]interface{}); ok {
		challenge.RPID, _ = pk["rpId"].(string)
		if ch, ok := pk["challenge"].(string); ok {
			challenge.Challenge = []byte(ch)
		}
		challenge.UserVerification, _ = pk["userVerification"].(string)
		if creds, ok := pk["allowCredentials"].([]interface{}); ok {
			for _, c := range creds {
				if cm, ok := c.(map[string]interface{}); ok {
					if id, ok := cm["id"].(string); ok {
						challenge.AllowCredentials = append(challenge.AllowCredentials, []byte(id))
					}
				}
			}
		}
	}

	return challenge, nil
}

// FinishLogin completes WebAuthn login.
func (a *BackendAdapter) FinishLogin(ctx context.Context, req *native.LoginResponse) (*native.AuthResult, error) {
	backendReq := &backend.LoginFinishRequest{
		ChallengeID: req.ChallengeID,
		Credential: map[string]interface{}{
			"id":    string(req.CredentialID),
			"type":  "public-key",
			"rawId": string(req.CredentialID),
			"response": map[string]interface{}{
				"authenticatorData": string(req.AuthenticatorData),
				"signature":         string(req.Signature),
				"userHandle":        string(req.UserHandle),
				"clientDataJSON":    string(req.ClientDataJSON),
			},
		},
	}

	resp, err := a.client.FinishLogin(ctx, backendReq)
	if err != nil {
		return nil, err
	}

	return &native.AuthResult{
		UserID:      resp.UUID,
		Token:       resp.Token,
		DisplayName: resp.DisplayName,
		RpID:        resp.WebauthnRpId,
	}, nil
}

// GetCredentials retrieves all verifiable credentials.
func (a *BackendAdapter) GetCredentials(ctx context.Context) ([]native.Credential, error) {
	creds, err := a.client.GetCredentials(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]native.Credential, len(creds))
	for i, c := range creds {
		result[i] = native.Credential{
			ID:         c.ID,
			Format:     c.Format,
			Credential: c.Credential,
		}
	}
	return result, nil
}

// GetAccountInfo retrieves account information.
func (a *BackendAdapter) GetAccountInfo(ctx context.Context) (*native.AccountInfo, error) {
	resp, err := a.client.GetAccountInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &native.AccountInfo{
		UserID:               resp.UUID,
		DisplayName:          resp.DisplayName,
		EncryptedPrivateData: resp.PrivateData,
	}, nil
}

// ConnectStream opens a gRPC stream (not supported over HTTP).
func (a *BackendAdapter) ConnectStream(ctx context.Context) (native.SigningStream, error) {
	return nil, ErrStreamingNotSupported
}

// AuthProviderAdapter wraps fido2.Provider to implement native.AuthProvider.
type AuthProviderAdapter struct {
	provider fido2.Provider
}

// NewAuthProviderAdapter creates a new auth provider adapter.
func NewAuthProviderAdapter(provider fido2.Provider) *AuthProviderAdapter {
	return &AuthProviderAdapter{provider: provider}
}

// Register creates a new credential.
func (a *AuthProviderAdapter) Register(ctx context.Context, opts *native.RegisterOptions) (*native.RegisterResult, error) {
	result, err := a.provider.Register(ctx, &fido2.RegisterOptions{
		Challenge:       opts.Challenge,
		RPID:            opts.RPID,
		RPName:          opts.RPName,
		UserID:          opts.UserID,
		UserName:        opts.UserName,
		UserDisplayName: opts.UserDisplayName,
		EnablePRF:       opts.PRFEnabled,
	})
	if err != nil {
		return nil, err
	}

	return &native.RegisterResult{
		CredentialID:      result.CredentialID,
		PublicKey:         result.PublicKey,
		AttestationObject: result.AttestationObject,
		ClientDataJSON:    result.ClientDataJSON,
		PRFSupported:      result.PRFSupported,
	}, nil
}

// Authenticate performs an assertion.
func (a *AuthProviderAdapter) Authenticate(ctx context.Context, opts *native.AuthenticateOptions) (*native.AuthenticateResult, error) {
	allowCreds := make([]fido2.CredentialID, len(opts.AllowCredentials))
	for i, c := range opts.AllowCredentials {
		allowCreds[i] = fido2.CredentialID(c)
	}

	fido2Opts := &fido2.AuthenticateOptions{
		Challenge:        opts.Challenge,
		RPID:             opts.RPID,
		AllowCredentials: allowCreds,
		UserVerification: fido2.UserVerificationRequirement(opts.UserVerification),
	}

	if opts.PRFInputs != nil {
		fido2Opts.PRFSalt1 = opts.PRFInputs.Salt1
		fido2Opts.PRFSalt2 = opts.PRFInputs.Salt2
	}

	result, err := a.provider.Authenticate(ctx, fido2Opts)
	if err != nil {
		return nil, err
	}

	authResult := &native.AuthenticateResult{
		CredentialID:      result.CredentialID,
		AuthenticatorData: result.AuthData,
		Signature:         result.Signature,
		UserHandle:        result.UserHandle,
		ClientDataJSON:    result.ClientDataJSON,
	}

	if result.PRFOutput != nil {
		authResult.PRFOutput = &native.PRFOutput{
			First:  result.PRFOutput.First,
			Second: result.PRFOutput.Second,
		}
	}

	return authResult, nil
}

// GetPRFOutput evaluates PRF extension for key derivation.
func (a *AuthProviderAdapter) GetPRFOutput(ctx context.Context, credentialID []byte, salt1, salt2 []byte) (*native.PRFOutput, error) {
	result, err := a.provider.GetPRFOutput(ctx, credentialID, salt1, salt2)
	if err != nil {
		return nil, err
	}

	return &native.PRFOutput{
		First:  result.First,
		Second: result.Second,
	}, nil
}

// KeystoreAdapter wraps keystore.Manager to implement native.KeystoreManager.
type KeystoreAdapter struct {
	manager *keystore.DefaultManager
}

// NewKeystoreAdapter creates a new keystore adapter.
func NewKeystoreAdapter(manager *keystore.DefaultManager) *KeystoreAdapter {
	return &KeystoreAdapter{manager: manager}
}

// IsLocked returns true if keystore is locked.
func (a *KeystoreAdapter) IsLocked() bool {
	return a.manager.IsLocked()
}

// Unlock decrypts the keystore using PRF-derived key.
func (a *KeystoreAdapter) Unlock(ctx context.Context, credentialID, prfOutput []byte, encryptedData interface{}) error {
	// Convert encryptedData to []byte
	var data []byte
	switch v := encryptedData.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	case nil:
		data = nil
	default:
		return fmt.Errorf("unsupported encrypted data type: %T", encryptedData)
	}
	return a.manager.Unlock(ctx, credentialID, prfOutput, data)
}

// Lock re-locks the keystore.
func (a *KeystoreAdapter) Lock() {
	_ = a.manager.Lock() // ignore error - always succeeds
}

// Sign signs data with the specified key.
// Note: algorithm parameter is ignored as the keystore uses the key's configured algorithm.
func (a *KeystoreAdapter) Sign(ctx context.Context, keyID string, payload []byte, algorithm string) ([]byte, error) {
	return a.manager.Sign(ctx, keyID, payload)
}

// GenerateProof generates an OID4VCI proof JWT.
func (a *KeystoreAdapter) GenerateProof(ctx context.Context, audience, nonce string) (string, error) {
	// Get the first available key for signing
	keys, err := a.manager.ListKeys()
	if err != nil {
		return "", fmt.Errorf("failed to list keys: %w", err)
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("no keys available")
	}

	claims := map[string]interface{}{
		"aud":   audience,
		"nonce": nonce,
	}
	return a.manager.SignJWT(ctx, keys[0].KeyID, claims)
}

// SignPresentation creates a VP JWT.
func (a *KeystoreAdapter) SignPresentation(ctx context.Context, nonce, audience string, credentials []interface{}) (string, error) {
	// Get the first available key for signing
	keys, err := a.manager.ListKeys()
	if err != nil {
		return "", fmt.Errorf("failed to list keys: %w", err)
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("no keys available")
	}

	claims := map[string]interface{}{
		"aud":   audience,
		"nonce": nonce,
		"vp": map[string]interface{}{
			"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": credentials,
		},
	}
	return a.manager.SignJWT(ctx, keys[0].KeyID, claims)
}
