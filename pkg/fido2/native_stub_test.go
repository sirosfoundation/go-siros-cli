//go:build !libfido2
// +build !libfido2

package fido2

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNativeProviderStub_NewNativeProvider(t *testing.T) {
	provider, err := NewNativeProvider()
	if err != nil {
		t.Fatalf("NewNativeProvider() error = %v", err)
	}
	if provider == nil {
		t.Fatal("NewNativeProvider() returned nil")
	}
}

func TestNativeProviderStub_WithRPID(t *testing.T) {
	provider, _ := NewNativeProvider()
	result := provider.WithRPID("example.com")

	if result == nil {
		t.Fatal("WithRPID() returned nil")
	}
	if result.rpID != "example.com" {
		t.Errorf("rpID = %q, want %q", result.rpID, "example.com")
	}
	// Verify it returns the same instance for chaining
	if result != provider {
		t.Error("WithRPID() should return the same instance")
	}
}

func TestNativeProviderStub_SupportsExtension(t *testing.T) {
	provider, _ := NewNativeProvider()

	// Stub should not support any extensions
	extensions := []ExtensionID{
		ExtensionPRF,
		ExtensionHMACSecret,
		ExtensionLargeBlob,
		ExtensionCredBlob,
	}

	for _, ext := range extensions {
		if provider.SupportsExtension(ext) {
			t.Errorf("Stub should not support extension %s", ext)
		}
	}
}

func TestNativeProviderStub_ListDevices(t *testing.T) {
	provider, _ := NewNativeProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	devices, err := provider.ListDevices(ctx)

	if err == nil {
		t.Fatal("ListDevices() should return error for stub")
	}
	if devices != nil {
		t.Error("ListDevices() should return nil devices for stub")
	}
	if !strings.Contains(err.Error(), "build with -tags libfido2") {
		t.Errorf("Error should mention libfido2 build tag, got: %v", err)
	}
}

func TestNativeProviderStub_Register(t *testing.T) {
	provider, _ := NewNativeProvider()
	ctx := context.Background()

	opts := &RegisterOptions{
		RPID:      "example.com",
		Challenge: []byte("challenge"),
	}

	result, err := provider.Register(ctx, opts)

	if err == nil {
		t.Fatal("Register() should return error for stub")
	}
	if result != nil {
		t.Error("Register() should return nil result for stub")
	}
	if !strings.Contains(err.Error(), "build with -tags libfido2") {
		t.Errorf("Error should mention libfido2 build tag, got: %v", err)
	}
}

func TestNativeProviderStub_Authenticate(t *testing.T) {
	provider, _ := NewNativeProvider()
	ctx := context.Background()

	opts := &AuthenticateOptions{
		RPID:      "example.com",
		Challenge: []byte("challenge"),
	}

	result, err := provider.Authenticate(ctx, opts)

	if err == nil {
		t.Fatal("Authenticate() should return error for stub")
	}
	if result != nil {
		t.Error("Authenticate() should return nil result for stub")
	}
	if !strings.Contains(err.Error(), "build with -tags libfido2") {
		t.Errorf("Error should mention libfido2 build tag, got: %v", err)
	}
}

func TestNativeProviderStub_GetPRFOutput(t *testing.T) {
	provider, _ := NewNativeProvider()
	ctx := context.Background()

	result, err := provider.GetPRFOutput(ctx, []byte("cred"), []byte("salt1"), []byte("salt2"))

	if err == nil {
		t.Fatal("GetPRFOutput() should return error for stub")
	}
	if result != nil {
		t.Error("GetPRFOutput() should return nil result for stub")
	}
	if !strings.Contains(err.Error(), "build with -tags libfido2") {
		t.Errorf("Error should mention libfido2 build tag, got: %v", err)
	}
}
