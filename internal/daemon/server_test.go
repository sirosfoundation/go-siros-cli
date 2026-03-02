package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	daemonv1 "github.com/sirosfoundation/go-siros-cli/api/proto/daemon/v1"
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
	"github.com/sirosfoundation/go-siros-cli/pkg/pinentry"
)

// mockEngine is a mock implementation of Engine for testing.
type mockEngine struct {
	unlocked  bool
	status    *EngineStatus
	keys      []keystore.KeyInfo
	signErr   error
	jwt       string
	signature []byte
}

func (m *mockEngine) Status(ctx context.Context) (*EngineStatus, error) {
	if m.status != nil {
		return m.status, nil
	}
	return &EngineStatus{
		Unlocked:   m.unlocked,
		BackendURL: "https://mock.example.com",
		TenantID:   "mock-tenant",
		KeyCount:   len(m.keys),
	}, nil
}

func (m *mockEngine) UnlockWithPRF(ctx context.Context, credentialID, prfOutput, encryptedData []byte) error {
	m.unlocked = true
	return nil
}

func (m *mockEngine) UnlockWithPassword(ctx context.Context, password string, encryptedData []byte) error {
	m.unlocked = true
	return nil
}

func (m *mockEngine) Lock(ctx context.Context) error {
	m.unlocked = false
	return nil
}

func (m *mockEngine) IsUnlocked() bool {
	return m.unlocked
}

func (m *mockEngine) GetKeystore() keystore.Manager {
	return nil
}

func (m *mockEngine) GetBackendClient() *backend.Client {
	return nil
}

func (m *mockEngine) GetFIDO2Provider() fido2.Provider {
	return nil
}

func (m *mockEngine) SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error) {
	if m.signErr != nil {
		return "", m.signErr
	}
	if m.jwt != "" {
		return m.jwt, nil
	}
	return "mock.jwt.token", nil
}

func (m *mockEngine) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	if m.signature != nil {
		return m.signature, nil
	}
	return []byte("mock-signature"), nil
}

func (m *mockEngine) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, nil
}

func (m *mockEngine) ListKeys() ([]keystore.KeyInfo, error) {
	return m.keys, nil
}

func (m *mockEngine) ResetTimeout() {}

func (m *mockEngine) Close() error {
	return nil
}

// Ensure mockEngine implements Engine
var _ Engine = (*mockEngine)(nil)

func TestServer_Status_Unlocked(t *testing.T) {
	engine := &mockEngine{
		unlocked: true,
		status: &EngineStatus{
			Unlocked:       true,
			BackendURL:     "https://test.example.com",
			TenantID:       "test-tenant",
			KeyCount:       3,
			SessionTimeout: time.Now().Add(30 * time.Minute),
		},
	}

	server := &Server{
		engine:   engine,
		tenantID: "test-tenant",
	}

	ctx := context.Background()
	resp, err := server.Status(ctx, &daemonv1.StatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if !resp.Running {
		t.Error("Status.Running should be true")
	}
	if !resp.Unlocked {
		t.Error("Status.Unlocked should be true")
	}
	if resp.KeyCount != 3 {
		t.Errorf("Status.KeyCount = %d, want 3", resp.KeyCount)
	}
	if resp.TenantId != "test-tenant" {
		t.Errorf("Status.TenantId = %q, want %q", resp.TenantId, "test-tenant")
	}
	if resp.TimeoutRemaining <= 0 {
		t.Error("TimeoutRemaining should be positive for unlocked status")
	}
}

func TestServer_Status_Locked(t *testing.T) {
	engine := &mockEngine{
		unlocked: false,
	}

	server := &Server{
		engine:   engine,
		tenantID: "test-tenant",
	}

	ctx := context.Background()
	resp, err := server.Status(ctx, &daemonv1.StatusRequest{})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if !resp.Running {
		t.Error("Status.Running should be true even when locked")
	}
	if resp.Unlocked {
		t.Error("Status.Unlocked should be false")
	}
}

func TestServer_Lock(t *testing.T) {
	engine := &mockEngine{
		unlocked: true,
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.Lock(ctx, &daemonv1.LockRequest{})
	if err != nil {
		t.Fatalf("Lock() error = %v", err)
	}

	if !resp.Success {
		t.Error("Lock.Success should be true")
	}
	if engine.unlocked {
		t.Error("Engine should be locked after Lock()")
	}
}

func TestServer_SignJWT_Unlocked(t *testing.T) {
	engine := &mockEngine{
		unlocked: true,
		jwt:      "eyJ.test.jwt",
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.SignJWT(ctx, &daemonv1.SignJWTRequest{
		KeyId:      "test-key",
		ClaimsJson: []byte(`{"sub": "user123"}`),
	})
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}

	if resp.Error != "" {
		t.Errorf("SignJWT.Error = %q, want empty", resp.Error)
	}
	if resp.Jwt != "eyJ.test.jwt" {
		t.Errorf("SignJWT.Jwt = %q, want %q", resp.Jwt, "eyJ.test.jwt")
	}
}

func TestServer_SignJWT_Locked(t *testing.T) {
	engine := &mockEngine{
		unlocked: false,
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.SignJWT(ctx, &daemonv1.SignJWTRequest{
		KeyId:      "test-key",
		ClaimsJson: []byte(`{"sub": "user123"}`),
	})
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}

	if resp.Error == "" {
		t.Error("SignJWT.Error should not be empty when locked")
	}
	if resp.Jwt != "" {
		t.Error("SignJWT.Jwt should be empty when locked")
	}
}

func TestServer_SignJWT_InvalidJSON(t *testing.T) {
	engine := &mockEngine{
		unlocked: true,
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.SignJWT(ctx, &daemonv1.SignJWTRequest{
		KeyId:      "test-key",
		ClaimsJson: []byte(`{invalid json}`),
	})
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}

	if resp.Error == "" {
		t.Error("SignJWT.Error should not be empty for invalid JSON")
	}
}

func TestServer_Sign_Unlocked(t *testing.T) {
	engine := &mockEngine{
		unlocked:  true,
		signature: []byte("test-signature"),
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.Sign(ctx, &daemonv1.SignRequest{
		KeyId: "test-key",
		Data:  []byte("data to sign"),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if resp.Error != "" {
		t.Errorf("Sign.Error = %q, want empty", resp.Error)
	}
	if string(resp.Signature) != "test-signature" {
		t.Errorf("Sign.Signature = %q, want %q", resp.Signature, "test-signature")
	}
}

func TestServer_Sign_Locked(t *testing.T) {
	engine := &mockEngine{
		unlocked: false,
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.Sign(ctx, &daemonv1.SignRequest{
		KeyId: "test-key",
		Data:  []byte("data to sign"),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if resp.Error == "" {
		t.Error("Sign.Error should not be empty when locked")
	}
}

func TestServer_ListKeys_Unlocked(t *testing.T) {
	engine := &mockEngine{
		unlocked: true,
		keys: []keystore.KeyInfo{
			{KeyID: "key1", Algorithm: "ES256"},
			{KeyID: "key2", Algorithm: "ES256"},
		},
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.ListKeys(ctx, &daemonv1.ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(resp.Keys) != 2 {
		t.Errorf("ListKeys() returned %d keys, want 2", len(resp.Keys))
	}
	if resp.Keys[0].KeyId != "key1" {
		t.Errorf("Keys[0].KeyId = %q, want %q", resp.Keys[0].KeyId, "key1")
	}
}

func TestServer_ListKeys_Locked(t *testing.T) {
	engine := &mockEngine{
		unlocked: false,
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.ListKeys(ctx, &daemonv1.ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(resp.Keys) != 0 {
		t.Errorf("ListKeys() returned %d keys, want 0 when locked", len(resp.Keys))
	}
}

func TestServer_GetApproval_NoPinentry(t *testing.T) {
	// Skip if pinentry is available - it would show a dialog
	if pinentry.HasPinentry() {
		t.Skip("Skipping test - pinentry is available and would show dialog")
	}

	engine := &mockEngine{
		unlocked: true,
	}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.GetApproval(ctx, &daemonv1.GetApprovalRequest{
		OperationType:  "sign",
		Description:    "Sign a credential",
		TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("GetApproval() error = %v", err)
	}

	// In test environment without pinentry/terminal, should fail
	// The function doesn't return error, but puts it in response
	if resp.Approved {
		t.Error("GetApproval.Approved should be false without pinentry/terminal")
	}
	// Error should indicate why approval failed (no terminal)
	if resp.Error == "" {
		t.Error("GetApproval.Error should indicate no terminal available")
	}
}

func TestServer_UnlockWithPRF_NotImplemented(t *testing.T) {
	engine := &mockEngine{}

	server := &Server{
		engine: engine,
	}

	ctx := context.Background()
	resp, err := server.UnlockWithPRF(ctx, &daemonv1.UnlockWithPRFRequest{})
	if err != nil {
		t.Fatalf("UnlockWithPRF() error = %v", err)
	}

	// PRF unlock via daemon is not yet implemented
	if resp.Success {
		t.Error("UnlockWithPRF.Success should be false (not implemented)")
	}
}

func TestServerConfig(t *testing.T) {
	cfg := &ServerConfig{
		SocketPath: "/tmp/test.sock",
		TenantID:   "test-tenant",
	}

	if cfg.SocketPath != "/tmp/test.sock" {
		t.Errorf("SocketPath = %q, want %q", cfg.SocketPath, "/tmp/test.sock")
	}
}
