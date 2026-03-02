//go:build e2e
// +build e2e

// Package e2e contains end-to-end integration tests for go-siros-cli.
// This file tests API compatibility and tagged binary format handling,
// mirroring the TypeScript tests from wallet-e2e-tests.
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
)

// TestTaggedBinaryFormatCompatibility tests that the backend returns
// tagged binary format ($b64u) correctly.
func TestTaggedBinaryFormatCompatibility(t *testing.T) {
	config := DefaultTestConfig()
	client := backend.NewClient(config.BackendURL)
	client.SetTenantID(config.TenantID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Verify backend is available
	status, err := client.Status(ctx)
	if err != nil {
		t.Skipf("Backend not available at %s: %v", config.BackendURL, err)
	}
	t.Logf("Backend status: %s (%s)", status.Status, status.Service)

	t.Run("registration-begin returns tagged binary", func(t *testing.T) {
		resp, err := client.StartRegistration(ctx, "Test User")
		if err != nil {
			t.Fatalf("StartRegistration failed: %v", err)
		}

		// Check createOptions.publicKey.challenge.$b64u
		publicKey, ok := resp.CreateOptions["publicKey"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing publicKey in createOptions")
		}

		challenge, ok := publicKey["challenge"].(map[string]interface{})
		if !ok {
			t.Fatal("Challenge should be a tagged binary object")
		}

		b64u, ok := challenge["$b64u"].(string)
		if !ok {
			t.Fatal("Challenge should have $b64u field")
		}

		// Verify we can decode it
		decoded, err := base64.RawURLEncoding.DecodeString(b64u)
		if err != nil {
			t.Fatalf("Failed to decode challenge: %v", err)
		}
		if len(decoded) == 0 {
			t.Fatal("Challenge bytes should not be empty")
		}
		t.Logf("Challenge decoded: %d bytes", len(decoded))

		// Check user.id.$b64u
		user, ok := publicKey["user"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing user in publicKey")
		}

		userID, ok := user["id"].(map[string]interface{})
		if !ok {
			t.Fatal("User ID should be a tagged binary object")
		}

		userIDB64u, ok := userID["$b64u"].(string)
		if !ok {
			t.Fatal("User ID should have $b64u field")
		}

		userIDDecoded, err := base64.RawURLEncoding.DecodeString(userIDB64u)
		if err != nil {
			t.Fatalf("Failed to decode user ID: %v", err)
		}
		t.Logf("User ID decoded: %d bytes", len(userIDDecoded))
	})

	t.Run("login-begin returns tagged binary", func(t *testing.T) {
		resp, err := client.StartLogin(ctx)
		if err != nil {
			t.Fatalf("StartLogin failed: %v", err)
		}

		// Check getOptions.publicKey.challenge.$b64u
		publicKey, ok := resp.GetOptions["publicKey"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing publicKey in getOptions")
		}

		challenge, ok := publicKey["challenge"].(map[string]interface{})
		if !ok {
			t.Fatal("Challenge should be a tagged binary object")
		}

		b64u, ok := challenge["$b64u"].(string)
		if !ok {
			t.Fatal("Challenge should have $b64u field")
		}

		decoded, err := base64.RawURLEncoding.DecodeString(b64u)
		if err != nil {
			t.Fatalf("Failed to decode challenge: %v", err)
		}
		if len(decoded) == 0 {
			t.Fatal("Challenge bytes should not be empty")
		}
		t.Logf("Login challenge decoded: %d bytes", len(decoded))
	})
}

// TestTenantAwareAPI tests that tenant ID is properly sent and handled.
func TestTenantAwareAPI(t *testing.T) {
	config := DefaultTestConfig()

	t.Run("default tenant works", func(t *testing.T) {
		client := backend.NewClient(config.BackendURL)
		// Don't set tenant ID, should default to "default"

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		status, err := client.Status(ctx)
		if err != nil {
			t.Skipf("Backend not available: %v", err)
		}
		t.Logf("Status (default tenant): %s", status.Status)
	})

	t.Run("explicit tenant header sent", func(t *testing.T) {
		client := backend.NewClient(config.BackendURL)
		client.SetTenantID("test-tenant-123")

		if got := client.GetTenantID(); got != "test-tenant-123" {
			t.Errorf("GetTenantID() = %q, want %q", got, "test-tenant-123")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Backend should accept the tenant header even if tenant doesn't exist
		// for status endpoint (which is typically unauthenticated)
		status, err := client.Status(ctx)
		if err != nil {
			t.Skipf("Backend not available: %v", err)
		}
		t.Logf("Status (explicit tenant): %s", status.Status)
	})

	t.Run("SetTenantID with empty string uses default", func(t *testing.T) {
		client := backend.NewClient(config.BackendURL)
		client.SetTenantID("custom")
		client.SetTenantID("") // Should reset to default

		if got := client.GetTenantID(); got != backend.DefaultTenantID {
			t.Errorf("GetTenantID() after empty = %q, want %q", got, backend.DefaultTenantID)
		}
	})
}

// TestMultiTenantRegistration tests registration flows with different tenants.
func TestMultiTenantRegistration(t *testing.T) {
	config := DefaultTestConfig()

	// Skip if not running full e2e tests
	if testing.Short() {
		t.Skip("Skipping multi-tenant registration test in short mode")
	}

	t.Run("registration creates tenant-scoped user", func(t *testing.T) {
		env := NewTestEnvironment(t, config)
		defer env.Cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Verify backend connectivity first
		status, err := env.Backend.Status(ctx)
		if err != nil {
			t.Skipf("Backend not available: %v", err)
		}
		t.Logf("Testing against %s (tenant: %s)", status.Service, config.TenantID)

		// Start registration
		startResp, err := env.Backend.StartRegistration(ctx, "Tenant Test User")
		if err != nil {
			t.Fatalf("StartRegistration failed: %v", err)
		}

		// Verify challenge ID is returned
		if startResp.ChallengeID == "" {
			t.Fatal("ChallengeID should not be empty")
		}
		t.Logf("Got challenge ID: %s", startResp.ChallengeID)

		// Extract challenge for FIDO2 operation
		publicKey, ok := startResp.CreateOptions["publicKey"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing publicKey in createOptions")
		}

		challengeObj, ok := publicKey["challenge"].(map[string]interface{})
		if !ok {
			t.Fatal("Challenge should be tagged binary")
		}

		challengeB64u, ok := challengeObj["$b64u"].(string)
		if !ok {
			t.Fatal("Challenge missing $b64u")
		}

		challenge, err := base64.RawURLEncoding.DecodeString(challengeB64u)
		if err != nil {
			t.Fatalf("Failed to decode challenge: %v", err)
		}

		// Extract RP info
		rpObj, ok := publicKey["rp"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing rp in publicKey")
		}
		rpID, _ := rpObj["id"].(string)
		rpName, _ := rpObj["name"].(string)
		if rpID == "" {
			rpID = config.RPID
		}

		// Extract user info
		userObj, ok := publicKey["user"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing user in publicKey")
		}
		userIDObj, ok := userObj["id"].(map[string]interface{})
		if !ok {
			t.Fatal("User ID should be tagged binary")
		}
		userIDB64u, _ := userIDObj["$b64u"].(string)
		userID, err := base64.RawURLEncoding.DecodeString(userIDB64u)
		if err != nil {
			t.Fatalf("Failed to decode user ID: %v", err)
		}
		userName, _ := userObj["name"].(string)

		// Perform FIDO2 registration with virtual provider
		regResult, err := env.Provider.Register(ctx, &fido2.RegisterOptions{
			Challenge:       challenge,
			RPID:            rpID,
			RPName:          rpName,
			UserID:          userID,
			UserName:        userName,
			UserDisplayName: "Tenant Test User",
		})
		if err != nil {
			t.Fatalf("Provider.Register failed: %v", err)
		}

		t.Logf("Created credential: %d bytes", len(regResult.CredentialID))
		t.Logf("Attestation object: %d bytes", len(regResult.AttestationObject))

		// Finish registration - build credential map as expected by backend
		credential := map[string]interface{}{
			"id":   base64.RawURLEncoding.EncodeToString(regResult.CredentialID),
			"type": "public-key",
			"response": map[string]interface{}{
				"attestationObject": base64.RawURLEncoding.EncodeToString(regResult.AttestationObject),
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(regResult.ClientDataJSON),
			},
		}

		finishReq := &backend.RegistrationFinishRequest{
			ChallengeID: startResp.ChallengeID,
			DisplayName: "Tenant Test User",
			Credential:  credential,
		}

		finishResp, err := env.Backend.FinishRegistration(ctx, finishReq)
		if err != nil {
			t.Fatalf("FinishRegistration failed: %v", err)
		}

		if finishResp.Token == "" {
			t.Fatal("Expected authentication token after registration")
		}
		t.Logf("Registration successful! UUID: %s", finishResp.UUID)
	})
}

// Helper to pretty-print JSON for debugging
func prettyJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
