// Package fido2 provides WebAuthn/FIDO2 authentication functionality.package fido2

package fido2

import (
	"context"
	"errors"
)

// Common errors
var (
	ErrNoDeviceFound                = errors.New("no FIDO2 device found")
	ErrUserCancelled                = errors.New("user cancelled the operation")
	ErrPRFNotSupported              = errors.New("PRF extension not supported by device")
	ErrTimeout                      = errors.New("operation timed out")
	ErrAuthenticationFailed         = errors.New("authentication failed")
	ErrDeviceNotFIDO2               = errors.New("device is not FIDO2 capable (U2F-only devices are not supported)")
	ErrResidentKeyNotSupported      = errors.New("device does not support resident keys (discoverable credentials)")
	ErrUserVerificationNotSupported = errors.New("device does not support user verification")
)

// ExtensionID identifies a WebAuthn extension.
type ExtensionID string

const (
	ExtensionPRF        ExtensionID = "prf"
	ExtensionHMACSecret ExtensionID = "hmac-secret"
	ExtensionLargeBlob  ExtensionID = "largeBlob"
	ExtensionCredBlob   ExtensionID = "credBlob"
)

// CredentialID is a WebAuthn credential identifier.
type CredentialID []byte

// PRFOutput contains the result of a PRF evaluation.
type PRFOutput struct {
	First  []byte
	Second []byte // Optional, if evalByCredential was used
}

// AssertionResult contains the result of a WebAuthn assertion.
type AssertionResult struct {
	CredentialID   CredentialID
	AuthData       []byte
	Signature      []byte
	UserHandle     []byte
	ClientDataJSON []byte
	PRFOutput      *PRFOutput
}

// RegistrationResult contains the result of a WebAuthn registration.
type RegistrationResult struct {
	CredentialID      CredentialID
	PublicKey         []byte
	AttestationObject []byte
	ClientDataJSON    []byte
	PRFSupported      bool
}

// Provider is the interface for FIDO2/WebAuthn operations.
// This abstraction allows for different implementations (libfido2, browser, etc.)
type Provider interface {
	// SupportsExtension checks if an extension is available.
	SupportsExtension(ext ExtensionID) bool

	// ListDevices returns a list of connected FIDO2 devices.
	ListDevices(ctx context.Context) ([]DeviceInfo, error)

	// Register performs a WebAuthn registration ceremony.
	Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error)

	// Authenticate performs a WebAuthn authentication ceremony.
	Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error)

	// GetPRFOutput evaluates the PRF extension with the given salts.
	// This is a convenience method that combines authentication with PRF evaluation.
	GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error)
}

// DeviceInfo contains information about a FIDO2 device.
type DeviceInfo struct {
	Path         string
	ProductName  string
	Manufacturer string
	HasPIN       bool
	PRFSupported bool
	IsFIDO2      bool            // True if device supports FIDO2, false for U2F-only
	Extensions   []string        // Supported extensions (e.g., "hmac-secret", "credProtect")
	Options      map[string]bool // Device options (e.g., "rk", "uv", "clientPin")
}

// RegisterOptions contains options for WebAuthn registration.
type RegisterOptions struct {
	// RelyingParty information
	RPID   string
	RPName string

	// User information
	UserID          []byte
	UserName        string
	UserDisplayName string

	// Challenge from the server
	Challenge []byte

	// Credential options
	ResidentKey      bool
	UserVerification UserVerificationRequirement
	Attestation      AttestationPreference

	// Extensions
	EnablePRF bool
	PRFSalt   []byte // PRF salt to use during registration (for keystore initialization)

	// PIN for devices that require it (native FIDO2 only)
	PIN string
}

// AuthenticateOptions contains options for WebAuthn authentication.
type AuthenticateOptions struct {
	// RelyingParty ID
	RPID string

	// Challenge from the server
	Challenge []byte

	// Allowed credentials (empty for discoverable credentials)
	AllowCredentials []CredentialID

	// User verification requirement
	UserVerification UserVerificationRequirement

	// PRF extension inputs
	PRFSalt1 []byte
	PRFSalt2 []byte // Optional

	// PIN for devices that require it (native FIDO2 only)
	PIN string
}

// UserVerificationRequirement specifies user verification requirements.
type UserVerificationRequirement string

const (
	UVRequired    UserVerificationRequirement = "required"
	UVPreferred   UserVerificationRequirement = "preferred"
	UVDiscouraged UserVerificationRequirement = "discouraged"
)

// AttestationPreference specifies attestation preferences.
type AttestationPreference string

const (
	AttestationNone     AttestationPreference = "none"
	AttestationIndirect AttestationPreference = "indirect"
	AttestationDirect   AttestationPreference = "direct"
)
