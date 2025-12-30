//go:build !libfido2
// +build !libfido2

package fido2

import (
	"context"
	"fmt"
)

// NativeProvider implements the Provider interface using libfido2.
// This is a stub implementation when libfido2 is not available.
// Build with -tags libfido2 to enable native FIDO2 support.
type NativeProvider struct {
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

// SupportsExtension checks if an extension is available.
func (p *NativeProvider) SupportsExtension(ext ExtensionID) bool {
	return false
}

// ListDevices returns a list of connected FIDO2 devices.
func (p *NativeProvider) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	return nil, fmt.Errorf("native FIDO2 not available: build with -tags libfido2")
}

// Register performs a WebAuthn registration ceremony.
func (p *NativeProvider) Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
	return nil, fmt.Errorf("native FIDO2 not available: build with -tags libfido2")
}

// Authenticate performs a WebAuthn authentication ceremony.
func (p *NativeProvider) Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
	return nil, fmt.Errorf("native FIDO2 not available: build with -tags libfido2")
}

// GetPRFOutput evaluates the PRF extension with the given salts.
func (p *NativeProvider) GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error) {
	return nil, fmt.Errorf("native FIDO2 not available: build with -tags libfido2")
}

// Ensure NativeProvider implements Provider
var _ Provider = (*NativeProvider)(nil)
