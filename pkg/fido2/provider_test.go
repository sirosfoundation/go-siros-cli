package fido2

import (
	"context"
	"testing"
	"time"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"NoDeviceFound", ErrNoDeviceFound, "no FIDO2 device found"},
		{"UserCancelled", ErrUserCancelled, "user cancelled the operation"},
		{"PRFNotSupported", ErrPRFNotSupported, "PRF extension not supported by device"},
		{"Timeout", ErrTimeout, "operation timed out"},
		{"AuthenticationFailed", ErrAuthenticationFailed, "authentication failed"},
		{"DeviceNotFIDO2", ErrDeviceNotFIDO2, "device is not FIDO2 capable (U2F-only devices are not supported)"},
		{"ResidentKeyNotSupported", ErrResidentKeyNotSupported, "device does not support resident keys (discoverable credentials)"},
		{"UserVerificationNotSupported", ErrUserVerificationNotSupported, "device does not support user verification"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.msg {
				t.Errorf("Error message = %q, want %q", tt.err.Error(), tt.msg)
			}
		})
	}
}

func TestExtensionIDConstants(t *testing.T) {
	tests := []struct {
		name string
		ext  ExtensionID
		val  string
	}{
		{"PRF", ExtensionPRF, "prf"},
		{"HMACSecret", ExtensionHMACSecret, "hmac-secret"},
		{"LargeBlob", ExtensionLargeBlob, "largeBlob"},
		{"CredBlob", ExtensionCredBlob, "credBlob"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.ext) != tt.val {
				t.Errorf("ExtensionID %s = %q, want %q", tt.name, tt.ext, tt.val)
			}
		})
	}
}

func TestUserVerificationRequirementConstants(t *testing.T) {
	tests := []struct {
		name string
		uv   UserVerificationRequirement
		val  string
	}{
		{"Required", UVRequired, "required"},
		{"Preferred", UVPreferred, "preferred"},
		{"Discouraged", UVDiscouraged, "discouraged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.uv) != tt.val {
				t.Errorf("UserVerificationRequirement %s = %q, want %q", tt.name, tt.uv, tt.val)
			}
		})
	}
}

func TestAttestationPreferenceConstants(t *testing.T) {
	tests := []struct {
		name string
		pref AttestationPreference
		val  string
	}{
		{"None", AttestationNone, "none"},
		{"Indirect", AttestationIndirect, "indirect"},
		{"Direct", AttestationDirect, "direct"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.pref) != tt.val {
				t.Errorf("AttestationPreference %s = %q, want %q", tt.name, tt.pref, tt.val)
			}
		})
	}
}

func TestDeviceInfo(t *testing.T) {
	info := DeviceInfo{
		Path:         "/dev/hidraw0",
		ProductName:  "YubiKey 5",
		Manufacturer: "Yubico",
		HasPIN:       true,
		PRFSupported: true,
		IsFIDO2:      true,
		Extensions:   []string{"hmac-secret", "credProtect"},
		Options:      map[string]bool{"rk": true, "uv": true, "clientPin": true},
	}

	if info.Path != "/dev/hidraw0" {
		t.Errorf("Path = %q, want %q", info.Path, "/dev/hidraw0")
	}
	if info.ProductName != "YubiKey 5" {
		t.Errorf("ProductName = %q, want %q", info.ProductName, "YubiKey 5")
	}
	if info.Manufacturer != "Yubico" {
		t.Errorf("Manufacturer = %q, want %q", info.Manufacturer, "Yubico")
	}
	if !info.HasPIN {
		t.Error("HasPIN should be true")
	}
	if !info.PRFSupported {
		t.Error("PRFSupported should be true")
	}
	if !info.IsFIDO2 {
		t.Error("IsFIDO2 should be true")
	}
	if len(info.Extensions) != 2 {
		t.Errorf("Extensions length = %d, want 2", len(info.Extensions))
	}
	if len(info.Options) != 3 {
		t.Errorf("Options length = %d, want 3", len(info.Options))
	}
}

func TestRegisterOptions(t *testing.T) {
	opts := RegisterOptions{
		RPID:             "example.com",
		RPName:           "Example",
		UserID:           []byte("user123"),
		UserName:         "user@example.com",
		UserDisplayName:  "Test User",
		Challenge:        []byte("challenge123"),
		ResidentKey:      true,
		UserVerification: UVRequired,
		Attestation:      AttestationDirect,
		EnablePRF:        true,
	}

	if opts.RPID != "example.com" {
		t.Errorf("RPID = %q, want %q", opts.RPID, "example.com")
	}
	if opts.UserVerification != UVRequired {
		t.Errorf("UserVerification = %q, want %q", opts.UserVerification, UVRequired)
	}
	if !opts.EnablePRF {
		t.Error("EnablePRF should be true")
	}
}

func TestAuthenticateOptions(t *testing.T) {
	opts := AuthenticateOptions{
		RPID:             "example.com",
		Challenge:        []byte("challenge456"),
		AllowCredentials: []CredentialID{[]byte("cred1"), []byte("cred2")},
		UserVerification: UVPreferred,
		PRFSalt1:         []byte("salt1"),
		PRFSalt2:         []byte("salt2"),
	}

	if opts.RPID != "example.com" {
		t.Errorf("RPID = %q, want %q", opts.RPID, "example.com")
	}
	if len(opts.AllowCredentials) != 2 {
		t.Errorf("AllowCredentials length = %d, want 2", len(opts.AllowCredentials))
	}
	if len(opts.PRFSalt1) != 5 {
		t.Errorf("PRFSalt1 length = %d, want 5", len(opts.PRFSalt1))
	}
}

func TestPRFOutput(t *testing.T) {
	prf := PRFOutput{
		First:  []byte("first32bytesofprfoutput123456789"),
		Second: []byte("second32bytesofprfoutput12345678"),
	}

	if len(prf.First) != 32 {
		t.Errorf("First length = %d, want 32", len(prf.First))
	}
	if len(prf.Second) != 32 {
		t.Errorf("Second length = %d, want 32", len(prf.Second))
	}
}

func TestAssertionResult(t *testing.T) {
	result := AssertionResult{
		CredentialID: []byte("credential-id"),
		AuthData:     []byte("auth-data"),
		Signature:    []byte("signature"),
		UserHandle:   []byte("user-handle"),
		PRFOutput: &PRFOutput{
			First: []byte("prf-output"),
		},
	}

	if len(result.CredentialID) == 0 {
		t.Error("CredentialID should not be empty")
	}
	if result.PRFOutput == nil {
		t.Error("PRFOutput should not be nil")
	}
}

func TestRegistrationResult(t *testing.T) {
	result := RegistrationResult{
		CredentialID:      []byte("credential-id"),
		PublicKey:         []byte("public-key"),
		AttestationObject: []byte("attestation-object"),
		ClientDataJSON:    []byte("client-data-json"),
		PRFSupported:      true,
	}

	if len(result.CredentialID) == 0 {
		t.Error("CredentialID should not be empty")
	}
	if !result.PRFSupported {
		t.Error("PRFSupported should be true")
	}
}

func TestCredentialID(t *testing.T) {
	cid := CredentialID([]byte{0x01, 0x02, 0x03, 0x04})

	if len(cid) != 4 {
		t.Errorf("CredentialID length = %d, want 4", len(cid))
	}
	if cid[0] != 0x01 {
		t.Errorf("First byte = %d, want 1", cid[0])
	}
}

// MockProvider is a mock implementation for testing
type MockProvider struct {
	devices     []DeviceInfo
	listErr     error
	registerErr error
	authErr     error
	prfErr      error
	extensions  map[ExtensionID]bool
	regResult   *RegistrationResult
	authResult  *AssertionResult
	prfOutput   *PRFOutput
}

func NewMockProvider() *MockProvider {
	return &MockProvider{
		extensions: make(map[ExtensionID]bool),
	}
}

func (m *MockProvider) SupportsExtension(ext ExtensionID) bool {
	return m.extensions[ext]
}

func (m *MockProvider) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.devices, nil
}

func (m *MockProvider) Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	return m.regResult, nil
}

func (m *MockProvider) Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
	if m.authErr != nil {
		return nil, m.authErr
	}
	return m.authResult, nil
}

func (m *MockProvider) GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error) {
	if m.prfErr != nil {
		return nil, m.prfErr
	}
	return m.prfOutput, nil
}

// Verify MockProvider implements Provider
var _ Provider = (*MockProvider)(nil)

func TestMockProvider_ListDevices(t *testing.T) {
	tests := []struct {
		name    string
		devices []DeviceInfo
		listErr error
		wantLen int
		wantErr bool
	}{
		{
			name:    "No devices",
			devices: nil,
			wantLen: 0,
		},
		{
			name: "One device",
			devices: []DeviceInfo{
				{Path: "/dev/hidraw0", ProductName: "Test Key"},
			},
			wantLen: 1,
		},
		{
			name:    "Error listing",
			listErr: ErrNoDeviceFound,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockProvider()
			mock.devices = tt.devices
			mock.listErr = tt.listErr

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			devices, err := mock.ListDevices(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListDevices() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(devices) != tt.wantLen {
				t.Errorf("ListDevices() returned %d devices, want %d", len(devices), tt.wantLen)
			}
		})
	}
}

func TestMockProvider_Register(t *testing.T) {
	tests := []struct {
		name        string
		regResult   *RegistrationResult
		registerErr error
		wantErr     bool
	}{
		{
			name: "Successful registration",
			regResult: &RegistrationResult{
				CredentialID: []byte("cred123"),
				PublicKey:    []byte("pubkey"),
				PRFSupported: true,
			},
		},
		{
			name:        "No device",
			registerErr: ErrNoDeviceFound,
			wantErr:     true,
		},
		{
			name:        "PRF not supported",
			registerErr: ErrPRFNotSupported,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockProvider()
			mock.regResult = tt.regResult
			mock.registerErr = tt.registerErr

			ctx := context.Background()
			opts := &RegisterOptions{
				RPID:      "example.com",
				Challenge: []byte("challenge"),
			}

			result, err := mock.Register(ctx, opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("Register() returned nil result")
			}
		})
	}
}

func TestMockProvider_Authenticate(t *testing.T) {
	tests := []struct {
		name       string
		authResult *AssertionResult
		authErr    error
		wantErr    bool
	}{
		{
			name: "Successful authentication",
			authResult: &AssertionResult{
				CredentialID: []byte("cred123"),
				AuthData:     []byte("authdata"),
				Signature:    []byte("sig"),
			},
		},
		{
			name:    "Authentication failed",
			authErr: ErrAuthenticationFailed,
			wantErr: true,
		},
		{
			name:    "User cancelled",
			authErr: ErrUserCancelled,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockProvider()
			mock.authResult = tt.authResult
			mock.authErr = tt.authErr

			ctx := context.Background()
			opts := &AuthenticateOptions{
				RPID:      "example.com",
				Challenge: []byte("challenge"),
			}

			result, err := mock.Authenticate(ctx, opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("Authenticate() returned nil result")
			}
		})
	}
}

func TestMockProvider_GetPRFOutput(t *testing.T) {
	tests := []struct {
		name      string
		prfOutput *PRFOutput
		prfErr    error
		wantErr   bool
	}{
		{
			name: "Successful PRF",
			prfOutput: &PRFOutput{
				First: []byte("32bytesofprfoutputdata12345678"),
			},
		},
		{
			name:    "PRF not supported",
			prfErr:  ErrPRFNotSupported,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockProvider()
			mock.prfOutput = tt.prfOutput
			mock.prfErr = tt.prfErr

			ctx := context.Background()
			result, err := mock.GetPRFOutput(ctx, []byte("cred"), []byte("salt1"), []byte("salt2"))

			if (err != nil) != tt.wantErr {
				t.Errorf("GetPRFOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("GetPRFOutput() returned nil result")
			}
		})
	}
}

func TestMockProvider_SupportsExtension(t *testing.T) {
	mock := NewMockProvider()
	mock.extensions[ExtensionPRF] = true
	mock.extensions[ExtensionHMACSecret] = true

	if !mock.SupportsExtension(ExtensionPRF) {
		t.Error("Should support PRF extension")
	}
	if !mock.SupportsExtension(ExtensionHMACSecret) {
		t.Error("Should support hmac-secret extension")
	}
	if mock.SupportsExtension(ExtensionLargeBlob) {
		t.Error("Should not support largeBlob extension")
	}
}
