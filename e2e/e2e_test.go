//go:build e2e
// +build e2e

// Package e2e contains end-to-end integration tests for go-siros-cli.
// These tests validate the CLI wallet functionality against a real
// go-wallet-backend instance. Tests can use either:
//   - TestProvider: Simple in-memory FIDO2 (fast, for unit tests)
//   - VirtualWebAuthnProvider: Proper WebAuthn attestations (for backend integration)
//   - Real hardware: When FIDO2_DEVICE is set (requires security key)
//
// Run these tests with: go test -tags=e2e ./e2e/...
package e2e

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
)

// TestConfig holds e2e test configuration.
type TestConfig struct {
	BackendURL string
	TenantID   string
	RPID       string
	Origin     string
	Timeout    time.Duration
}

// DefaultTestConfig returns default test configuration.
func DefaultTestConfig() *TestConfig {
	backendURL := os.Getenv("WALLET_BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:8080"
	}

	tenantID := os.Getenv("WALLET_TENANT_ID")
	if tenantID == "" {
		tenantID = backend.DefaultTenantID
	}

	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}

	origin := os.Getenv("WEBAUTHN_ORIGIN")
	if origin == "" {
		origin = "http://" + rpID + ":8080"
	}

	return &TestConfig{
		BackendURL: backendURL,
		TenantID:   tenantID,
		RPID:       rpID,
		Origin:     origin,
		Timeout:    30 * time.Second,
	}
}

// TestEnvironment holds test resources.
type TestEnvironment struct {
	Config   *TestConfig
	Provider fido2.Provider
	Backend  *backend.Client
	Keystore *keystore.DefaultManager
}

// NewTestEnvironment creates a new test environment.
// By default uses VirtualWebAuthnProvider for proper WebAuthn attestations.
func NewTestEnvironment(t *testing.T, config *TestConfig) *TestEnvironment {
	if config == nil {
		config = DefaultTestConfig()
	}

	// Use VirtualWebAuthnProvider for proper attestation format
	provider := fido2.NewVirtualWebAuthnProvider(config.RPID, config.Origin)

	// Create backend client
	backendClient := backend.NewClient(config.BackendURL)
	backendClient.SetTenantID(config.TenantID)

	// Create keystore manager
	keystoreManager := keystore.NewManager()

	return &TestEnvironment{
		Config:   config,
		Provider: provider,
		Backend:  backendClient,
		Keystore: keystoreManager,
	}
}

// NewTestEnvironmentWithTestProvider creates a test environment with simple TestProvider.
// This is faster but generates simplified attestations - good for unit tests.
func NewTestEnvironmentWithTestProvider(t *testing.T, config *TestConfig) *TestEnvironment {
	if config == nil {
		config = DefaultTestConfig()
	}

	provider := fido2.NewTestProvider().WithRPID(config.RPID)
	backendClient := backend.NewClient(config.BackendURL)
	backendClient.SetTenantID(config.TenantID)
	keystoreManager := keystore.NewManager()

	return &TestEnvironment{
		Config:   config,
		Provider: provider,
		Backend:  backendClient,
		Keystore: keystoreManager,
	}
}

// Cleanup releases test resources.
func (env *TestEnvironment) Cleanup() {
	if env.Keystore != nil {
		_ = env.Keystore.Lock()
	}
}

// TestBackendStatus verifies backend connectivity.
func TestBackendStatus(t *testing.T) {
	config := DefaultTestConfig()
	client := backend.NewClient(config.BackendURL)
	client.SetTenantID(config.TenantID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		t.Skipf("Backend not available at %s: %v", config.BackendURL, err)
	}

	if status.Status != "ok" && status.Status != "healthy" {
		t.Errorf("Expected status ok/healthy, got %s", status.Status)
	}

	t.Logf("Backend status: %s (%s)", status.Status, status.Service)
}

// TestRegistrationFlow tests user registration with software FIDO2 token.
func TestRegistrationFlow(t *testing.T) {
	env := NewTestEnvironment(t, nil)
	defer env.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check backend connectivity first
	if _, err := env.Backend.Status(ctx); err != nil {
		t.Skipf("Backend not available: %v", err)
	}

	displayName := fmt.Sprintf("Test User %d", time.Now().UnixNano())

	// Step 1: Start registration
	t.Log("Starting registration...")
	challenge, err := env.Backend.StartRegistration(ctx, displayName)
	if err != nil {
		t.Fatalf("StartRegistration failed: %v", err)
	}

	t.Logf("Got challenge ID: %s", challenge.ChallengeID)

	// Step 2: Create credential with software token
	t.Log("Creating credential with virtual authenticator...")

	// Parse the createOptions to get the challenge
	publicKey, ok := challenge.CreateOptions["publicKey"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid createOptions format")
	}

	// Extract challenge bytes
	var challengeBytes []byte
	if ch, ok := publicKey["challenge"].(string); ok {
		challengeBytes, _ = base64.RawURLEncoding.DecodeString(ch)
	}

	// Extract user info
	var userID []byte
	var userName string
	if user, ok := publicKey["user"].(map[string]interface{}); ok {
		if id, ok := user["id"].(string); ok {
			userID, _ = base64.RawURLEncoding.DecodeString(id)
		}
		userName, _ = user["name"].(string)
	}

	// Get RP info
	var rpID, rpName string
	if rp, ok := publicKey["rp"].(map[string]interface{}); ok {
		rpID, _ = rp["id"].(string)
		rpName, _ = rp["name"].(string)
	}
	if rpID == "" {
		rpID = env.Config.RPID
	}

	// Register with software token
	regResult, err := env.Provider.Register(ctx, &fido2.RegisterOptions{
		Challenge:       challengeBytes,
		RPID:            rpID,
		RPName:          rpName,
		UserID:          userID,
		UserName:        userName,
		UserDisplayName: displayName,
		ResidentKey:     true,
		EnablePRF:       true,
	})
	if err != nil {
		t.Fatalf("Provider.Register failed: %v", err)
	}

	t.Logf("Created credential ID: %s", base64.RawURLEncoding.EncodeToString(regResult.CredentialID))
	t.Logf("PRF supported: %v", regResult.PRFSupported)

	// Step 3: Finish registration with backend
	t.Log("Finishing registration with backend...")

	finishReq := &backend.RegistrationFinishRequest{
		ChallengeID: challenge.ChallengeID,
		Credential: map[string]interface{}{
			"id":    base64.RawURLEncoding.EncodeToString(regResult.CredentialID),
			"type":  "public-key",
			"rawId": base64.RawURLEncoding.EncodeToString(regResult.CredentialID),
			"response": map[string]interface{}{
				"attestationObject": base64.RawURLEncoding.EncodeToString(regResult.AttestationObject),
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(regResult.ClientDataJSON),
			},
		},
		DisplayName: displayName,
	}

	result, err := env.Backend.FinishRegistration(ctx, finishReq)
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	t.Logf("Registration successful! User ID: %s", result.UUID)
	t.Logf("Display name: %s", result.DisplayName)
	t.Logf("Got app token: %v", result.Token != "")

	// Store token for subsequent operations
	env.Backend.SetToken(result.Token)
}

// TestLoginFlow tests user login with software FIDO2 token.
func TestLoginFlow(t *testing.T) {
	env := NewTestEnvironment(t, nil)
	defer env.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check backend connectivity first
	if _, err := env.Backend.Status(ctx); err != nil {
		t.Skipf("Backend not available: %v", err)
	}

	// First register a user
	displayName := fmt.Sprintf("Login Test User %d", time.Now().UnixNano())
	token, credentialID := registerTestUser(t, env, ctx, displayName)
	if token == "" {
		t.Fatal("Failed to register test user")
	}

	// Clear token to test login
	env.Backend.SetToken("")

	// Step 1: Start login
	t.Log("Starting login...")
	loginChallenge, err := env.Backend.StartLogin(ctx)
	if err != nil {
		t.Fatalf("StartLogin failed: %v", err)
	}

	t.Logf("Got login challenge ID: %s", loginChallenge.ChallengeID)

	// Extract challenge from getOptions
	publicKey, ok := loginChallenge.GetOptions["publicKey"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid getOptions format")
	}

	var challengeBytes []byte
	if ch, ok := publicKey["challenge"].(string); ok {
		challengeBytes, _ = base64.RawURLEncoding.DecodeString(ch)
	}

	rpID, _ := publicKey["rpId"].(string)
	if rpID == "" {
		rpID = env.Config.RPID
	}

	// Step 2: Authenticate with software token
	t.Log("Authenticating with virtual authenticator...")

	authResult, err := env.Provider.Authenticate(ctx, &fido2.AuthenticateOptions{
		Challenge:        challengeBytes,
		RPID:             rpID,
		AllowCredentials: []fido2.CredentialID{credentialID},
	})
	if err != nil {
		t.Fatalf("Provider.Authenticate failed: %v", err)
	}

	t.Logf("Authentication successful, credential ID: %s", base64.RawURLEncoding.EncodeToString(authResult.CredentialID))

	// Step 3: Finish login with backend
	t.Log("Finishing login with backend...")

	finishReq := &backend.LoginFinishRequest{
		ChallengeID: loginChallenge.ChallengeID,
		Credential: map[string]interface{}{
			"id":    base64.RawURLEncoding.EncodeToString(authResult.CredentialID),
			"type":  "public-key",
			"rawId": base64.RawURLEncoding.EncodeToString(authResult.CredentialID),
			"response": map[string]interface{}{
				"authenticatorData": base64.RawURLEncoding.EncodeToString(authResult.AuthData),
				"signature":         base64.RawURLEncoding.EncodeToString(authResult.Signature),
				"userHandle":        base64.RawURLEncoding.EncodeToString(authResult.UserHandle),
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(authResult.ClientDataJSON),
			},
		},
	}

	loginResult, err := env.Backend.FinishLogin(ctx, finishReq)
	if err != nil {
		t.Fatalf("FinishLogin failed: %v", err)
	}

	t.Logf("Login successful! User ID: %s", loginResult.UUID)
	t.Logf("Display name: %s", loginResult.DisplayName)
	t.Logf("Got app token: %v", loginResult.Token != "")
}

// TestPRFKeyDerivation tests PRF extension for key derivation.
func TestPRFKeyDerivation(t *testing.T) {
	env := NewTestEnvironment(t, nil)
	defer env.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register a credential with PRF support
	regResult, err := env.Provider.Register(ctx, &fido2.RegisterOptions{
		Challenge:       []byte("test-challenge"),
		RPID:            env.Config.RPID,
		RPName:          "Test",
		UserID:          []byte("test-user"),
		UserName:        "testuser",
		UserDisplayName: "Test User",
		ResidentKey:     true,
		EnablePRF:       true,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if !regResult.PRFSupported {
		t.Skip("PRF not supported by provider")
	}

	// Test PRF evaluation
	salt1 := []byte("encryption-key-salt")
	salt2 := []byte("authentication-key-salt")

	prfOutput, err := env.Provider.GetPRFOutput(ctx, regResult.CredentialID, salt1, salt2)
	if err != nil {
		t.Fatalf("GetPRFOutput failed: %v", err)
	}

	if len(prfOutput.First) != 32 {
		t.Errorf("Expected 32-byte PRF output, got %d bytes", len(prfOutput.First))
	}

	if len(prfOutput.Second) != 32 {
		t.Errorf("Expected 32-byte second PRF output, got %d bytes", len(prfOutput.Second))
	}

	t.Logf("PRF output (first): %s", base64.StdEncoding.EncodeToString(prfOutput.First))
	t.Logf("PRF output (second): %s", base64.StdEncoding.EncodeToString(prfOutput.Second))

	// Verify determinism - same inputs should give same outputs
	prfOutput2, err := env.Provider.GetPRFOutput(ctx, regResult.CredentialID, salt1, salt2)
	if err != nil {
		t.Fatalf("Second GetPRFOutput failed: %v", err)
	}

	if string(prfOutput.First) != string(prfOutput2.First) {
		t.Error("PRF output should be deterministic")
	}
}

// registerTestUser is a helper that registers a user and returns the token and credential ID.
func registerTestUser(t *testing.T, env *TestEnvironment, ctx context.Context, displayName string) (string, fido2.CredentialID) {
	t.Helper()

	// Start registration
	challenge, err := env.Backend.StartRegistration(ctx, displayName)
	if err != nil {
		t.Fatalf("StartRegistration failed: %v", err)
	}

	// Parse createOptions
	publicKey, ok := challenge.CreateOptions["publicKey"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid createOptions format")
	}

	var challengeBytes []byte
	if ch, ok := publicKey["challenge"].(string); ok {
		challengeBytes, _ = base64.RawURLEncoding.DecodeString(ch)
	}

	var userID []byte
	var userName string
	if user, ok := publicKey["user"].(map[string]interface{}); ok {
		if id, ok := user["id"].(string); ok {
			userID, _ = base64.RawURLEncoding.DecodeString(id)
		}
		userName, _ = user["name"].(string)
	}

	var rpID, rpName string
	if rp, ok := publicKey["rp"].(map[string]interface{}); ok {
		rpID, _ = rp["id"].(string)
		rpName, _ = rp["name"].(string)
	}
	if rpID == "" {
		rpID = env.Config.RPID
	}

	// Register with software token
	regResult, err := env.Provider.Register(ctx, &fido2.RegisterOptions{
		Challenge:       challengeBytes,
		RPID:            rpID,
		RPName:          rpName,
		UserID:          userID,
		UserName:        userName,
		UserDisplayName: displayName,
		ResidentKey:     true,
		EnablePRF:       true,
	})
	if err != nil {
		t.Fatalf("Provider.Register failed: %v", err)
	}

	// Finish registration
	finishReq := &backend.RegistrationFinishRequest{
		ChallengeID: challenge.ChallengeID,
		Credential: map[string]interface{}{
			"id":    base64.RawURLEncoding.EncodeToString(regResult.CredentialID),
			"type":  "public-key",
			"rawId": base64.RawURLEncoding.EncodeToString(regResult.CredentialID),
			"response": map[string]interface{}{
				"attestationObject": base64.RawURLEncoding.EncodeToString(regResult.AttestationObject),
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(regResult.ClientDataJSON),
			},
		},
		DisplayName: displayName,
	}

	result, err := env.Backend.FinishRegistration(ctx, finishReq)
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	return result.Token, regResult.CredentialID
}
