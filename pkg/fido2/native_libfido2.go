//go:build libfido2
// +build libfido2

package fido2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/keys-pub/go-libfido2"
)

// NativeProvider implements the Provider interface using libfido2.
type NativeProvider struct {
	// rpID is the relying party ID for operations
	rpID string
}

// NewNativeProvider creates a new native FIDO2 provider.
func NewNativeProvider() (*NativeProvider, error) {
	return &NativeProvider{}, nil
}

// WithRPID sets the relying party ID for this provider.
func (p *NativeProvider) WithRPID(rpID string) *NativeProvider {
	p.rpID = rpID
	return p
}

// buildClientDataJSON creates the clientDataJSON structure as per the WebAuthn spec.
// type is "webauthn.create" for registration or "webauthn.get" for authentication.
func buildClientDataJSON(typ string, challenge []byte, origin string) []byte {
	clientData := map[string]interface{}{
		"type":        typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	}
	data, _ := json.Marshal(clientData)
	return data
}

// attestationObject represents the CBOR structure for WebAuthn attestation.
type attestationObject struct {
	Fmt      string                 `cbor:"fmt"`
	AuthData []byte                 `cbor:"authData"`
	AttStmt  map[string]interface{} `cbor:"attStmt"`
}

// unwrapCBORBytes checks if the data is CBOR-wrapped bytes and unwraps them.
// libfido2 returns authData as CBOR-encoded byte strings (starting with 0x58, 0x59, etc.)
// We need to unwrap these to get the raw bytes.
func unwrapCBORBytes(data []byte) ([]byte, error) {
	// Check if this looks like CBOR-wrapped bytes
	// CBOR byte strings start with:
	// 0x40-0x57: bytes string with length 0-23
	// 0x58: byte string with 1-byte length
	// 0x59: byte string with 2-byte length
	// 0x5a: byte string with 4-byte length
	// 0x5b: byte string with 8-byte length
	if len(data) > 0 && data[0] >= 0x40 && data[0] <= 0x5b {
		var unwrapped []byte
		if err := cbor.Unmarshal(data, &unwrapped); err == nil {
			return unwrapped, nil
		}
	}
	// Not CBOR-wrapped or failed to unwrap, return as-is
	return data, nil
}

// buildAttestationObject creates a CBOR-encoded attestation object with "none" format.
// authDataCBOR is the CBOR-wrapped authenticator data from libfido2.
func buildAttestationObject(authDataCBOR []byte) ([]byte, error) {
	// libfido2 returns authData as CBOR-wrapped bytes, unwrap it first
	authData, err := unwrapCBORBytes(authDataCBOR)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap authData: %w", err)
	}

	attObj := attestationObject{
		Fmt:      "none",
		AuthData: authData,
		AttStmt:  map[string]interface{}{},
	}

	// Use deterministic encoding for consistent output
	em, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	data, err := em.Marshal(attObj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode attestation object: %w", err)
	}

	return data, nil
}

// SupportsExtension checks if an extension is available.
func (p *NativeProvider) SupportsExtension(ext ExtensionID) bool {
	switch ext {
	case ExtensionPRF, ExtensionHMACSecret:
		// libfido2 supports hmac-secret, which maps to PRF
		return true
	case ExtensionLargeBlob:
		// libfido2 supports largeBlob in newer versions
		return false
	default:
		return false
	}
}

// ListDevices returns a list of connected FIDO2 devices.
func (p *NativeProvider) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	devices := make([]DeviceInfo, len(locs))
	for i, loc := range locs {
		devices[i] = DeviceInfo{
			Path:         loc.Path,
			ProductName:  loc.Product,
			Manufacturer: loc.Manufacturer,
			Options:      make(map[string]bool),
		}

		// Try to get more info by opening the device
		dev, err := libfido2.NewDevice(loc.Path)
		if err == nil {
			info, err := dev.Info()
			if err == nil {
				// Device supports FIDO2 CTAP2
				devices[i].IsFIDO2 = true
				devices[i].Extensions = info.Extensions

				// Check for hmac-secret extension support
				for _, ext := range info.Extensions {
					if ext == "hmac-secret" {
						devices[i].PRFSupported = true
						break
					}
				}
				// Store all options
				for _, opt := range info.Options {
					switch opt.Value {
					case libfido2.True:
						devices[i].Options[opt.Name] = true
					case libfido2.False:
						devices[i].Options[opt.Name] = false
					}
					// Check PIN status
					if opt.Name == "clientPin" {
						devices[i].HasPIN = opt.Value == libfido2.True
					}
				}
			}
			// If Info() fails, device is likely U2F-only
		}
	}

	return devices, nil
}

// findFIDO2Device finds and opens the first FIDO2-capable device.
// It skips U2F-only devices and prefers devices with hmac-secret support.
func (p *NativeProvider) findFIDO2Device() (*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	if len(locs) == 0 {
		return nil, ErrNoDeviceFound
	}

	// First pass: look for a device with hmac-secret support
	for _, loc := range locs {
		dev, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			continue
		}
		info, err := dev.Info()
		if err != nil {
			// Device doesn't support CTAP2 Info command - likely U2F-only
			continue
		}
		// Check for hmac-secret extension
		for _, ext := range info.Extensions {
			if ext == "hmac-secret" {
				return dev, nil
			}
		}
	}

	// Second pass: accept any FIDO2 device
	for _, loc := range locs {
		dev, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			continue
		}
		_, err = dev.Info()
		if err != nil {
			// Device doesn't support CTAP2 Info command - likely U2F-only
			continue
		}
		return dev, nil
	}

	// If we get here, all devices are U2F-only
	return nil, fmt.Errorf("%w: all connected devices are U2F-only. Please connect a FIDO2-capable security key", ErrNoDeviceFound)
}

// checkDeviceCapabilities checks if a device supports the required features.
// Returns nil if the device is capable, or a descriptive error otherwise.
func (p *NativeProvider) checkDeviceCapabilities(dev *libfido2.Device, opts *RegisterOptions) error {
	info, err := dev.Info()
	if err != nil {
		return fmt.Errorf("%w: this appears to be a U2F-only device (like YubiKey 4). "+
			"Please use a FIDO2-capable device (YubiKey 5 or newer, or another FIDO2 security key)", ErrDeviceNotFIDO2)
	}

	// Build a map of options for easier checking
	deviceOpts := make(map[string]libfido2.OptionValue)
	for _, opt := range info.Options {
		deviceOpts[opt.Name] = opt.Value
	}

	// Check resident key support if required
	if opts.ResidentKey {
		if rkVal, ok := deviceOpts["rk"]; ok {
			if rkVal == libfido2.False {
				return fmt.Errorf("%w: device does not support discoverable credentials", ErrResidentKeyNotSupported)
			}
		}
	}

	// Check PRF/hmac-secret support if required
	if opts.EnablePRF {
		hasHMACSecret := false
		for _, ext := range info.Extensions {
			if ext == "hmac-secret" {
				hasHMACSecret = true
				break
			}
		}
		if !hasHMACSecret {
			return fmt.Errorf("%w: device does not support the hmac-secret extension needed for PRF", ErrPRFNotSupported)
		}
	}

	// Check user verification if required
	if opts.UserVerification == UVRequired {
		uvVal, uvOk := deviceOpts["uv"]
		pinVal, pinOk := deviceOpts["clientPin"]

		// Device can do UV if it has built-in UV or if it has PIN set
		hasUV := (uvOk && uvVal == libfido2.True)
		hasPIN := (pinOk && pinVal == libfido2.True)

		if !hasUV && !hasPIN {
			return fmt.Errorf("%w: device has no PIN set and no built-in user verification. "+
				"Please set a PIN on your device using a tool like ykman or fido2-token", ErrUserVerificationNotSupported)
		}
	}

	return nil
}

// checkAuthCapabilities checks if a device supports the required features for authentication.
// Returns nil if the device is capable, or a descriptive error otherwise.
func (p *NativeProvider) checkAuthCapabilities(dev *libfido2.Device, opts *AuthenticateOptions) error {
	info, err := dev.Info()
	if err != nil {
		return fmt.Errorf("%w: this appears to be a U2F-only device (like YubiKey 4). "+
			"Please use a FIDO2-capable device (YubiKey 5 or newer, or another FIDO2 security key)", ErrDeviceNotFIDO2)
	}

	// Check PRF/hmac-secret support if PRF salts are provided
	if len(opts.PRFSalt1) > 0 {
		hasHMACSecret := false
		for _, ext := range info.Extensions {
			if ext == "hmac-secret" {
				hasHMACSecret = true
				break
			}
		}
		if !hasHMACSecret {
			return fmt.Errorf("%w: device does not support the hmac-secret extension needed for PRF", ErrPRFNotSupported)
		}
	}

	// Check user verification if required
	if opts.UserVerification == UVRequired {
		deviceOpts := make(map[string]libfido2.OptionValue)
		for _, opt := range info.Options {
			deviceOpts[opt.Name] = opt.Value
		}

		uvVal, uvOk := deviceOpts["uv"]
		pinVal, pinOk := deviceOpts["clientPin"]

		// Device can do UV if it has built-in UV or if it has PIN set
		hasUV := (uvOk && uvVal == libfido2.True)
		hasPIN := (pinOk && pinVal == libfido2.True)

		if !hasUV && !hasPIN {
			return fmt.Errorf("%w: device has no PIN set and no built-in user verification. "+
				"Please set a PIN on your device using a tool like ykman or fido2-token", ErrUserVerificationNotSupported)
		}
	}

	return nil
}

// Register performs a WebAuthn registration ceremony.
func (p *NativeProvider) Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
	// Find a FIDO2-capable device (skips U2F-only devices)
	dev, err := p.findFIDO2Device()
	if err != nil {
		return nil, err
	}

	// Check device capabilities before attempting registration
	if err := p.checkDeviceCapabilities(dev, opts); err != nil {
		return nil, err
	}

	// Build credential parameters
	rpID := opts.RPID
	if rpID == "" {
		rpID = p.rpID
	}

	rp := libfido2.RelyingParty{
		ID:   rpID,
		Name: opts.RPName,
	}

	user := libfido2.User{
		ID:          opts.UserID,
		Name:        opts.UserName,
		DisplayName: opts.UserDisplayName,
	}

	// Convert user verification requirement
	var uv libfido2.OptionValue
	switch opts.UserVerification {
	case UVRequired:
		uv = libfido2.True
	case UVPreferred:
		uv = libfido2.True
	case UVDiscouraged:
		uv = libfido2.False
	default:
		uv = libfido2.True
	}

	// Build extensions
	var extensions []libfido2.Extension
	if opts.EnablePRF {
		extensions = append(extensions, libfido2.HMACSecretExtension)
	}

	// Convert RK option
	var rk libfido2.OptionValue
	if opts.ResidentKey {
		rk = libfido2.True
	} else {
		rk = libfido2.Default
	}

	// Set credential type (ES256 by default)
	credType := libfido2.ES256

	// Build the origin from the RP ID
	origin := "https://" + rpID

	// Build clientDataJSON as per WebAuthn spec - MUST be done before MakeCredential
	// because MakeCredential expects the SHA-256 hash of clientDataJSON, not the challenge
	clientDataJSON := buildClientDataJSON("webauthn.create", opts.Challenge, origin)

	// Hash the clientDataJSON - this is what we pass to the authenticator
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Create credential with the clientDataHash
	attest, err := dev.MakeCredential(
		clientDataHash[:],
		rp,
		user,
		credType,
		opts.PIN, // PIN for user verification
		&libfido2.MakeCredentialOpts{
			Extensions: extensions,
			RK:         rk,
			UV:         uv,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make credential: %w", err)
	}

	// Build proper CBOR-encoded attestation object
	attestationObject, err := buildAttestationObject(attest.AuthData)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestation object: %w", err)
	}

	return &RegistrationResult{
		CredentialID:      attest.CredentialID,
		PublicKey:         attest.PubKey,
		AttestationObject: attestationObject,
		ClientDataJSON:    clientDataJSON,
		PRFSupported:      opts.EnablePRF,
	}, nil
}

// Authenticate performs a WebAuthn authentication ceremony.
func (p *NativeProvider) Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
	// Find a FIDO2-capable device (skips U2F-only devices)
	dev, err := p.findFIDO2Device()
	if err != nil {
		return nil, err
	}

	// Check device capabilities for authentication
	if err := p.checkAuthCapabilities(dev, opts); err != nil {
		return nil, err
	}

	rpID := opts.RPID
	if rpID == "" {
		rpID = p.rpID
	}

	// Convert user verification requirement
	var uv libfido2.OptionValue
	switch opts.UserVerification {
	case UVRequired:
		uv = libfido2.True
	case UVPreferred:
		uv = libfido2.True
	case UVDiscouraged:
		uv = libfido2.False
	default:
		uv = libfido2.True
	}

	// Build assertion options
	assertOpts := &libfido2.AssertionOpts{
		UV: uv,
		UP: libfido2.True,
	}

	// Add hmac-secret extension if PRF salts provided
	if len(opts.PRFSalt1) > 0 {
		assertOpts.Extensions = append(assertOpts.Extensions, libfido2.HMACSecretExtension)
		// Note: PRF uses the salt directly, hmac-secret uses SHA-256 of the salt
		// For compatibility with WebAuthn PRF, we should hash the salt
		// But libfido2 expects raw salt for hmac-secret
		assertOpts.HMACSalt = opts.PRFSalt1
	}

	// Convert credential IDs
	var credentialIDs [][]byte
	for _, cid := range opts.AllowCredentials {
		credentialIDs = append(credentialIDs, cid)
	}

	// Build the origin from the RP ID
	origin := "https://" + rpID

	// Build clientDataJSON as per WebAuthn spec - MUST be done before Assertion
	// because Assertion expects the SHA-256 hash of clientDataJSON, not the challenge
	clientDataJSON := buildClientDataJSON("webauthn.get", opts.Challenge, origin)

	// Hash the clientDataJSON - this is what we pass to the authenticator
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Get assertion with the clientDataHash
	assertion, err := dev.Assertion(
		rpID,
		clientDataHash[:],
		credentialIDs,
		opts.PIN, // PIN for user verification
		assertOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get assertion: %w", err)
	}

	// Unwrap the CBOR-encoded authData from libfido2
	authData, err := unwrapCBORBytes(assertion.AuthDataCBOR)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap authData: %w", err)
	}

	result := &AssertionResult{
		CredentialID:   assertion.CredentialID,
		AuthData:       authData,
		Signature:      assertion.Sig,
		UserHandle:     assertion.User.ID,
		ClientDataJSON: clientDataJSON,
	}

	// Extract PRF output from hmac-secret result
	if len(assertion.HMACSecret) > 0 {
		result.PRFOutput = &PRFOutput{
			First: assertion.HMACSecret,
		}
	}

	return result, nil
}

// GetPRFOutput evaluates the PRF extension with the given salts.
func (p *NativeProvider) GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error) {
	result, err := p.Authenticate(ctx, &AuthenticateOptions{
		AllowCredentials: []CredentialID{credential},
		UserVerification: UVRequired,
		PRFSalt1:         salt1,
		PRFSalt2:         salt2,
	})
	if err != nil {
		return nil, err
	}
	return result.PRFOutput, nil
}

// Ensure NativeProvider implements Provider
var _ Provider = (*NativeProvider)(nil)
