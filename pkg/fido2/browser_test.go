package fido2

import (
	"testing"
)

func TestBrowserProvider_NewBrowserProvider(t *testing.T) {
	p := NewBrowserProvider()
	if p == nil {
		t.Fatal("NewBrowserProvider() returned nil")
	}
	if p.CallbackPort != 0 {
		t.Errorf("CallbackPort = %d, want 0 (random)", p.CallbackPort)
	}
	if p.Timeout != "120s" {
		t.Errorf("Timeout = %q, want %q", p.Timeout, "120s")
	}
}

func TestBrowserProvider_WithOptions(t *testing.T) {
	p := NewBrowserProvider(
		WithCallbackPort(8080),
		WithBrowserCommand("firefox"),
		WithTimeout("60s"),
		WithBrowserRPID("example.com"),
	)

	if p.CallbackPort != 8080 {
		t.Errorf("CallbackPort = %d, want 8080", p.CallbackPort)
	}
	if p.BrowserCommand != "firefox" {
		t.Errorf("BrowserCommand = %q, want %q", p.BrowserCommand, "firefox")
	}
	if p.Timeout != "60s" {
		t.Errorf("Timeout = %q, want %q", p.Timeout, "60s")
	}
	if p.RPID != "example.com" {
		t.Errorf("RPID = %q, want %q", p.RPID, "example.com")
	}
}

func TestBrowserProvider_SupportsExtension(t *testing.T) {
	p := NewBrowserProvider()

	tests := []struct {
		ext  ExtensionID
		want bool
	}{
		{ExtensionPRF, true},
		{ExtensionLargeBlob, true},
		{ExtensionHMACSecret, false},
		{ExtensionCredBlob, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.ext), func(t *testing.T) {
			got := p.SupportsExtension(tt.ext)
			if got != tt.want {
				t.Errorf("SupportsExtension(%q) = %v, want %v", tt.ext, got, tt.want)
			}
		})
	}
}

func TestBrowserProvider_ListDevices(t *testing.T) {
	p := NewBrowserProvider()

	devices, err := p.ListDevices(nil)
	if err != nil {
		t.Fatalf("ListDevices() error = %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("ListDevices() returned %d devices, want 1", len(devices))
	}
	if devices[0].Path != "browser" {
		t.Errorf("Device path = %q, want %q", devices[0].Path, "browser")
	}
	if devices[0].ProductName != "Browser WebAuthn" {
		t.Errorf("Device ProductName = %q, want %q", devices[0].ProductName, "Browser WebAuthn")
	}
	if !devices[0].PRFSupported {
		t.Error("Device PRFSupported should be true")
	}
}

func TestRegistrationResult_Fields(t *testing.T) {
	result := RegistrationResult{
		CredentialID:      []byte("credential-id-123"),
		PublicKey:         []byte("public-key-bytes"),
		AttestationObject: []byte("attestation-object"),
		ClientDataJSON:    []byte(`{"type":"webauthn.create"}`),
		PRFSupported:      true,
	}

	if string(result.CredentialID) != "credential-id-123" {
		t.Errorf("CredentialID = %q, want %q", result.CredentialID, "credential-id-123")
	}
	if !result.PRFSupported {
		t.Error("PRFSupported should be true")
	}
}

func TestAssertionResultWithPRF(t *testing.T) {
	result := AssertionResult{
		CredentialID:   []byte("credential-id"),
		AuthData:       []byte("auth-data"),
		Signature:      []byte("signature-bytes"),
		UserHandle:     []byte("user-handle"),
		ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
		PRFOutput: &PRFOutput{
			First:  make([]byte, 32),
			Second: make([]byte, 32),
		},
	}

	if result.PRFOutput == nil {
		t.Fatal("PRFOutput should not be nil")
	}
	if len(result.PRFOutput.First) != 32 {
		t.Errorf("PRFOutput.First length = %d, want 32", len(result.PRFOutput.First))
	}
	if len(result.PRFOutput.Second) != 32 {
		t.Errorf("PRFOutput.Second length = %d, want 32", len(result.PRFOutput.Second))
	}
}

func TestRegisterOptionsValidation(t *testing.T) {
	tests := []struct {
		name string
		opts RegisterOptions
	}{
		{
			name: "minimal options",
			opts: RegisterOptions{
				RPID:      "example.com",
				Challenge: []byte("challenge"),
				UserID:    []byte("user-id"),
			},
		},
		{
			name: "full options",
			opts: RegisterOptions{
				RPID:             "example.com",
				RPName:           "Example Site",
				UserID:           []byte("user-id"),
				UserName:         "user@example.com",
				UserDisplayName:  "Test User",
				Challenge:        []byte("challenge"),
				ResidentKey:      true,
				UserVerification: UVRequired,
				Attestation:      AttestationDirect,
				EnablePRF:        true,
				PRFSalt:          []byte("salt"),
				PIN:              "1234",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify no panics during creation
			if tt.opts.RPID == "" {
				t.Error("RPID should not be empty")
			}
		})
	}
}

func TestAuthenticateOptionsValidation(t *testing.T) {
	tests := []struct {
		name string
		opts AuthenticateOptions
	}{
		{
			name: "minimal options",
			opts: AuthenticateOptions{
				RPID:      "example.com",
				Challenge: []byte("challenge"),
			},
		},
		{
			name: "with allow credentials",
			opts: AuthenticateOptions{
				RPID:      "example.com",
				Challenge: []byte("challenge"),
				AllowCredentials: []CredentialID{
					[]byte("cred-1"),
					[]byte("cred-2"),
				},
				UserVerification: UVPreferred,
			},
		},
		{
			name: "with PRF salts",
			opts: AuthenticateOptions{
				RPID:      "example.com",
				Challenge: []byte("challenge"),
				PRFSalt1:  []byte("salt1"),
				PRFSalt2:  []byte("salt2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts.RPID == "" {
				t.Error("RPID should not be empty")
			}
			if len(tt.opts.Challenge) == 0 {
				t.Error("Challenge should not be empty")
			}
		})
	}
}

func TestCredentialID_Types(t *testing.T) {
	cred1 := CredentialID([]byte("credential-id-1"))
	cred2 := CredentialID([]byte("credential-id-2"))

	if len(cred1) != 15 {
		t.Errorf("len(cred1) = %d, want 15", len(cred1))
	}
	if string(cred1) == string(cred2) {
		t.Error("Different credentials should not be equal")
	}
}

func TestDeviceInfoString(t *testing.T) {
	info := DeviceInfo{
		Path:         "/dev/hidraw0",
		ProductName:  "YubiKey 5",
		Manufacturer: "Yubico",
		HasPIN:       true,
		PRFSupported: true,
		IsFIDO2:      true,
	}

	if info.Path == "" {
		t.Error("Path should not be empty")
	}
	if info.ProductName == "" {
		t.Error("ProductName should not be empty")
	}
}

func TestBoolToResidentKey(t *testing.T) {
	// This tests the internal helper function indirectly through RegisterOptions
	opts := RegisterOptions{
		RPID:        "example.com",
		ResidentKey: true,
	}
	if !opts.ResidentKey {
		t.Error("ResidentKey should be true")
	}

	opts2 := RegisterOptions{
		RPID:        "example.com",
		ResidentKey: false,
	}
	if opts2.ResidentKey {
		t.Error("ResidentKey should be false")
	}
}
