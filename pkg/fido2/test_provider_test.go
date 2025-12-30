package fido2

import (
	"context"
	"errors"
	"testing"
)

func TestNewTestProvider(t *testing.T) {
	p := NewTestProvider()

	if p == nil {
		t.Fatal("NewTestProvider returned nil")
	}
	if p.RPID != "localhost" {
		t.Errorf("expected RPID 'localhost', got %q", p.RPID)
	}
	if len(p.Credentials) != 0 {
		t.Errorf("expected empty credentials, got %d", len(p.Credentials))
	}
	if !p.SupportedExtensions[ExtensionPRF] {
		t.Error("expected PRF extension to be supported")
	}
	if len(p.Devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(p.Devices))
	}
}

func TestTestProvider_Builder(t *testing.T) {
	customErr := errors.New("custom error")
	devices := []DeviceInfo{{Path: "custom://device"}}

	p := NewTestProvider().
		WithRPID("example.com").
		WithError(customErr).
		WithExtension(ExtensionPRF, false).
		WithDevices(devices)

	if p.RPID != "example.com" {
		t.Errorf("expected RPID 'example.com', got %q", p.RPID)
	}
	if p.Error != customErr {
		t.Error("expected custom error to be set")
	}
	if p.SupportedExtensions[ExtensionPRF] {
		t.Error("expected PRF extension to be disabled")
	}
	if len(p.Devices) != 1 || p.Devices[0].Path != "custom://device" {
		t.Error("devices not set correctly")
	}
}

func TestTestProvider_WithNoDevices(t *testing.T) {
	p := NewTestProvider().WithNoDevices()
	if len(p.Devices) != 0 {
		t.Errorf("expected no devices, got %d", len(p.Devices))
	}
}

func TestTestProvider_SupportsExtension(t *testing.T) {
	p := NewTestProvider()

	if !p.SupportsExtension(ExtensionPRF) {
		t.Error("expected PRF to be supported")
	}
	if !p.SupportsExtension(ExtensionHMACSecret) {
		t.Error("expected HMAC-Secret to be supported")
	}

	// Disable PRF
	p.WithExtension(ExtensionPRF, false)
	if p.SupportsExtension(ExtensionPRF) {
		t.Error("expected PRF to be disabled")
	}

	// Test with nil extensions map
	p2 := &TestProvider{}
	if p2.SupportsExtension(ExtensionPRF) {
		t.Error("expected false for nil extensions map")
	}
}

func TestTestProvider_ListDevices(t *testing.T) {
	ctx := context.Background()

	t.Run("returns configured devices", func(t *testing.T) {
		p := NewTestProvider()
		devices, err := p.ListDevices(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(devices) != 1 {
			t.Errorf("expected 1 device, got %d", len(devices))
		}
		if devices[0].ProductName != "Test FIDO2 Device" {
			t.Errorf("unexpected product name: %s", devices[0].ProductName)
		}
	})

	t.Run("returns error when set", func(t *testing.T) {
		customErr := errors.New("device error")
		p := NewTestProvider().WithError(customErr)
		_, err := p.ListDevices(ctx)
		if err != customErr {
			t.Errorf("expected custom error, got %v", err)
		}
	})

	t.Run("returns ErrNoDeviceFound when no devices", func(t *testing.T) {
		p := NewTestProvider().WithNoDevices()
		_, err := p.ListDevices(ctx)
		if !errors.Is(err, ErrNoDeviceFound) {
			t.Errorf("expected ErrNoDeviceFound, got %v", err)
		}
	})
}

func TestTestProvider_Register(t *testing.T) {
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		p := NewTestProvider()
		opts := &RegisterOptions{
			RPID:        "localhost",
			Challenge:   []byte("test-challenge"),
			UserID:      []byte("user-123"),
			UserName:    "testuser",
			EnablePRF:   true,
			ResidentKey: true,
		}

		result, err := p.Register(ctx, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.CredentialID) == 0 {
			t.Error("expected non-empty credential ID")
		}
		if len(result.PublicKey) == 0 {
			t.Error("expected non-empty public key")
		}
		if len(result.AttestationObject) == 0 {
			t.Error("expected non-empty attestation object")
		}
		if len(result.ClientDataJSON) == 0 {
			t.Error("expected non-empty client data JSON")
		}
		if !result.PRFSupported {
			t.Error("expected PRF to be supported")
		}

		// Verify credential was stored
		cred := p.GetCredential(result.CredentialID)
		if cred == nil {
			t.Error("credential should be stored")
		}
		if string(cred.UserID) != "user-123" {
			t.Errorf("unexpected user ID: %s", string(cred.UserID))
		}
	})

	t.Run("returns error when set", func(t *testing.T) {
		customErr := errors.New("register error")
		p := NewTestProvider().WithError(customErr)
		_, err := p.Register(ctx, &RegisterOptions{})
		if err != customErr {
			t.Errorf("expected custom error, got %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		p := NewTestProvider()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := p.Register(ctx, &RegisterOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("uses callback when set", func(t *testing.T) {
		customResult := &RegistrationResult{
			CredentialID: []byte("custom-id"),
		}
		p := NewTestProvider()
		p.RegisterCallback = func(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
			return customResult, nil
		}

		result, err := p.Register(ctx, &RegisterOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result.CredentialID) != "custom-id" {
			t.Error("expected callback result to be used")
		}
	})

	t.Run("PRF disabled when extension not supported", func(t *testing.T) {
		p := NewTestProvider().WithExtension(ExtensionPRF, false)
		opts := &RegisterOptions{
			RPID:      "localhost",
			Challenge: []byte("test-challenge"),
			EnablePRF: true,
		}

		result, err := p.Register(ctx, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.PRFSupported {
			t.Error("expected PRF to not be supported")
		}
	})
}

func TestTestProvider_Authenticate(t *testing.T) {
	ctx := context.Background()

	// Helper to create a registered credential
	setupProvider := func() (*TestProvider, CredentialID) {
		p := NewTestProvider()
		result, _ := p.Register(ctx, &RegisterOptions{
			RPID:        "localhost",
			Challenge:   []byte("reg-challenge"),
			UserID:      []byte("user-123"),
			UserName:    "testuser",
			EnablePRF:   true,
			ResidentKey: true,
		})
		return p, result.CredentialID
	}

	t.Run("successful authentication", func(t *testing.T) {
		p, credID := setupProvider()
		opts := &AuthenticateOptions{
			RPID:             "localhost",
			Challenge:        []byte("auth-challenge"),
			AllowCredentials: []CredentialID{credID},
		}

		result, err := p.Authenticate(ctx, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(result.CredentialID) != string(credID) {
			t.Error("credential ID mismatch")
		}
		if len(result.AuthData) == 0 {
			t.Error("expected non-empty auth data")
		}
		if len(result.Signature) == 0 {
			t.Error("expected non-empty signature")
		}
		if string(result.UserHandle) != "user-123" {
			t.Errorf("unexpected user handle: %s", string(result.UserHandle))
		}
	})

	t.Run("with PRF", func(t *testing.T) {
		p, credID := setupProvider()
		opts := &AuthenticateOptions{
			RPID:             "localhost",
			Challenge:        []byte("auth-challenge"),
			AllowCredentials: []CredentialID{credID},
			PRFSalt1:         []byte("salt1"),
			PRFSalt2:         []byte("salt2"),
		}

		result, err := p.Authenticate(ctx, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.PRFOutput == nil {
			t.Fatal("expected PRF output")
		}
		if len(result.PRFOutput.First) != 32 {
			t.Errorf("expected 32-byte PRF output, got %d", len(result.PRFOutput.First))
		}
		if len(result.PRFOutput.Second) != 32 {
			t.Errorf("expected 32-byte second PRF output, got %d", len(result.PRFOutput.Second))
		}
	})

	t.Run("discoverable credential", func(t *testing.T) {
		p, _ := setupProvider()
		opts := &AuthenticateOptions{
			RPID:      "localhost",
			Challenge: []byte("auth-challenge"),
			// No AllowCredentials - should use discoverable credential
		}

		result, err := p.Authenticate(ctx, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.CredentialID) == 0 {
			t.Error("expected credential to be found")
		}
	})

	t.Run("no matching credential", func(t *testing.T) {
		p := NewTestProvider()
		opts := &AuthenticateOptions{
			RPID:             "localhost",
			Challenge:        []byte("auth-challenge"),
			AllowCredentials: []CredentialID{[]byte("nonexistent")},
		}

		_, err := p.Authenticate(ctx, opts)
		if !errors.Is(err, ErrNoDeviceFound) {
			t.Errorf("expected ErrNoDeviceFound, got %v", err)
		}
	})

	t.Run("returns error when set", func(t *testing.T) {
		customErr := errors.New("auth error")
		p := NewTestProvider().WithError(customErr)
		_, err := p.Authenticate(ctx, &AuthenticateOptions{})
		if err != customErr {
			t.Errorf("expected custom error, got %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		p, _ := setupProvider()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := p.Authenticate(ctx, &AuthenticateOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("uses callback when set", func(t *testing.T) {
		customResult := &AssertionResult{
			CredentialID: []byte("custom-cred"),
		}
		p := NewTestProvider()
		p.AuthenticateCallback = func(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
			return customResult, nil
		}

		result, err := p.Authenticate(ctx, &AuthenticateOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result.CredentialID) != "custom-cred" {
			t.Error("expected callback result to be used")
		}
	})

	t.Run("sign count increments", func(t *testing.T) {
		p, credID := setupProvider()
		opts := &AuthenticateOptions{
			RPID:             "localhost",
			Challenge:        []byte("auth-challenge"),
			AllowCredentials: []CredentialID{credID},
		}

		// Authenticate twice
		p.Authenticate(ctx, opts)
		p.Authenticate(ctx, opts)

		cred := p.GetCredential(credID)
		if cred.SignCount != 2 {
			t.Errorf("expected sign count 2, got %d", cred.SignCount)
		}
	})
}

func TestTestProvider_GetPRFOutput(t *testing.T) {
	ctx := context.Background()

	// Setup provider with credential
	setupProvider := func() (*TestProvider, CredentialID) {
		p := NewTestProvider()
		result, _ := p.Register(ctx, &RegisterOptions{
			RPID:      "localhost",
			Challenge: []byte("challenge"),
			EnablePRF: true,
		})
		return p, result.CredentialID
	}

	t.Run("successful PRF output", func(t *testing.T) {
		p, credID := setupProvider()

		output, err := p.GetPRFOutput(ctx, credID, []byte("salt1"), []byte("salt2"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(output.First) != 32 {
			t.Errorf("expected 32-byte first output, got %d", len(output.First))
		}
		if len(output.Second) != 32 {
			t.Errorf("expected 32-byte second output, got %d", len(output.Second))
		}
	})

	t.Run("PRF output without salt2", func(t *testing.T) {
		p, credID := setupProvider()

		output, err := p.GetPRFOutput(ctx, credID, []byte("salt1"), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(output.First) != 32 {
			t.Errorf("expected 32-byte first output, got %d", len(output.First))
		}
		if output.Second != nil {
			t.Error("expected nil second output")
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		p, credID := setupProvider()

		output1, _ := p.GetPRFOutput(ctx, credID, []byte("salt1"), nil)
		output2, _ := p.GetPRFOutput(ctx, credID, []byte("salt1"), nil)

		if string(output1.First) != string(output2.First) {
			t.Error("PRF output should be deterministic")
		}
	})

	t.Run("unknown credential", func(t *testing.T) {
		p := NewTestProvider()

		_, err := p.GetPRFOutput(ctx, []byte("unknown"), []byte("salt1"), nil)
		if !errors.Is(err, ErrNoDeviceFound) {
			t.Errorf("expected ErrNoDeviceFound, got %v", err)
		}
	})

	t.Run("PRF not supported", func(t *testing.T) {
		p := NewTestProvider().WithExtension(ExtensionPRF, false)
		result, _ := p.Register(ctx, &RegisterOptions{
			RPID:      "localhost",
			Challenge: []byte("challenge"),
			EnablePRF: false,
		})

		_, err := p.GetPRFOutput(ctx, result.CredentialID, []byte("salt1"), nil)
		if !errors.Is(err, ErrPRFNotSupported) {
			t.Errorf("expected ErrPRFNotSupported, got %v", err)
		}
	})

	t.Run("returns error when set", func(t *testing.T) {
		customErr := errors.New("prf error")
		p := NewTestProvider().WithError(customErr)
		_, err := p.GetPRFOutput(ctx, []byte("any"), []byte("salt1"), nil)
		if err != customErr {
			t.Errorf("expected custom error, got %v", err)
		}
	})
}

func TestTestProvider_CredentialManagement(t *testing.T) {
	p := NewTestProvider()

	// Add a pre-existing credential
	cred := &TestCredential{
		ID:           []byte("test-cred-id"),
		UserID:       []byte("user-456"),
		UserName:     "existinguser",
		RPID:         "example.com",
		PRFSupported: true,
		ResidentKey:  true,
	}
	p.AddCredential(cred)

	// Verify retrieval
	retrieved := p.GetCredential([]byte("test-cred-id"))
	if retrieved == nil {
		t.Fatal("credential should exist")
	}
	if retrieved.UserName != "existinguser" {
		t.Errorf("unexpected username: %s", retrieved.UserName)
	}

	// Clear credentials
	p.ClearCredentials()
	if p.GetCredential([]byte("test-cred-id")) != nil {
		t.Error("credentials should be cleared")
	}
}

func TestTestProvider_AddCredential_NilMap(t *testing.T) {
	// Test adding credential when Credentials map is nil
	p := &TestProvider{}
	cred := &TestCredential{
		ID: []byte("cred-id"),
	}
	p.AddCredential(cred)

	if p.GetCredential([]byte("cred-id")) == nil {
		t.Error("credential should be added even with initially nil map")
	}
}

// Test that TestProvider implements Provider interface
func TestTestProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*TestProvider)(nil)
}
