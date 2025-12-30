package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()

	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if !m.IsLocked() {
		t.Error("New manager should be locked")
	}
	if m.privateKeys == nil {
		t.Error("privateKeys map should be initialized")
	}
}

func TestManager_IsLocked(t *testing.T) {
	m := NewManager()

	// Should be locked initially
	if !m.IsLocked() {
		t.Error("Manager should be locked initially")
	}

	// Manually unlock for testing
	m.locked = false
	if m.IsLocked() {
		t.Error("Manager should be unlocked after setting locked=false")
	}

	// Lock again
	m.locked = true
	if !m.IsLocked() {
		t.Error("Manager should be locked after setting locked=true")
	}
}

func TestManager_Lock(t *testing.T) {
	m := NewManager()
	m.locked = false

	// Add some test keys
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m.privateKeys["test-key"] = key
	m.container = &WalletStateContainer{}

	// Lock the manager
	err := m.Lock()
	if err != nil {
		t.Fatalf("Lock() error = %v", err)
	}

	if !m.IsLocked() {
		t.Error("Manager should be locked after Lock()")
	}
	if len(m.privateKeys) != 0 {
		t.Error("privateKeys should be cleared after Lock()")
	}
	if m.container != nil {
		t.Error("container should be nil after Lock()")
	}
}

func TestManager_GetPrivateKey_Locked(t *testing.T) {
	m := NewManager()

	_, err := m.GetPrivateKey("test-key")
	if err != ErrKeystoreLocked {
		t.Errorf("GetPrivateKey() error = %v, want ErrKeystoreLocked", err)
	}
}

func TestManager_GetPrivateKey_NotFound(t *testing.T) {
	m := NewManager()
	m.locked = false

	_, err := m.GetPrivateKey("nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetPrivateKey() error = %v, want ErrKeyNotFound", err)
	}
}

func TestManager_GetPrivateKey_Success(t *testing.T) {
	m := NewManager()
	m.locked = false

	// Add a test key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m.privateKeys["test-key"] = key

	got, err := m.GetPrivateKey("test-key")
	if err != nil {
		t.Fatalf("GetPrivateKey() error = %v", err)
	}
	if got != key {
		t.Error("GetPrivateKey() returned wrong key")
	}
}

func TestManager_ListKeys_Locked(t *testing.T) {
	m := NewManager()

	_, err := m.ListKeys()
	if err != ErrKeystoreLocked {
		t.Errorf("ListKeys() error = %v, want ErrKeystoreLocked", err)
	}
}

func TestManager_ListKeys_Empty(t *testing.T) {
	m := NewManager()
	m.locked = false

	keys, err := m.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys() returned %d keys, want 0", len(keys))
	}
}

func TestManager_ListKeys_WithContainer(t *testing.T) {
	m := NewManager()
	m.locked = false
	m.container = &WalletStateContainer{
		S: WalletState{
			Keypairs: []StoredKeypair{
				{
					KID: "key1",
					Keypair: KeypairData{
						DID:       "did:example:123",
						Algorithm: "ES256",
						PublicKey: map[string]interface{}{"kty": "EC"},
					},
				},
				{
					KID: "key2",
					Keypair: KeypairData{
						DID:       "did:example:456",
						Algorithm: "ES384",
						PublicKey: map[string]interface{}{"kty": "EC"},
					},
				},
			},
		},
	}

	keys, err := m.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys() returned %d keys, want 2", len(keys))
	}
	if keys[0].KeyID != "key1" {
		t.Errorf("First key ID = %q, want %q", keys[0].KeyID, "key1")
	}
	if keys[1].DID != "did:example:456" {
		t.Errorf("Second key DID = %q, want %q", keys[1].DID, "did:example:456")
	}
}

func TestManager_Sign_Locked(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	_, err := m.Sign(ctx, "test-key", []byte("data"))
	if err != ErrKeystoreLocked {
		t.Errorf("Sign() error = %v, want ErrKeystoreLocked", err)
	}
}

func TestManager_Sign_KeyNotFound(t *testing.T) {
	m := NewManager()
	m.locked = false
	ctx := context.Background()

	_, err := m.Sign(ctx, "nonexistent", []byte("data"))
	if err != ErrKeyNotFound {
		t.Errorf("Sign() error = %v, want ErrKeyNotFound", err)
	}
}

func TestManager_Sign_Success(t *testing.T) {
	m := NewManager()
	m.locked = false
	ctx := context.Background()

	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	m.privateKeys["test-key"] = key

	data := []byte("test data to sign")
	sig, err := m.Sign(ctx, "test-key", data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// P-256 signature should be 64 bytes (32 bytes for r, 32 bytes for s)
	if len(sig) != 64 {
		t.Errorf("Signature length = %d, want 64", len(sig))
	}
}

func TestManager_SignJWT_Locked(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	_, err := m.SignJWT(ctx, "test-key", map[string]interface{}{"sub": "test"})
	if err != ErrKeystoreLocked {
		t.Errorf("SignJWT() error = %v, want ErrKeystoreLocked", err)
	}
}

func TestManager_SignJWT_KeyNotFound(t *testing.T) {
	m := NewManager()
	m.locked = false
	ctx := context.Background()

	_, err := m.SignJWT(ctx, "nonexistent", map[string]interface{}{"sub": "test"})
	if err != ErrKeyNotFound {
		t.Errorf("SignJWT() error = %v, want ErrKeyNotFound", err)
	}
}

func TestManager_SignJWT_Success(t *testing.T) {
	m := NewManager()
	m.locked = false
	ctx := context.Background()

	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	m.privateKeys["test-key"] = key
	m.container = &WalletStateContainer{
		S: WalletState{
			Keypairs: []StoredKeypair{
				{
					KID: "test-key",
					Keypair: KeypairData{
						Algorithm: "ES256",
					},
				},
			},
		},
	}

	claims := map[string]interface{}{
		"sub": "user123",
		"iss": "test-issuer",
	}

	jwt, err := m.SignJWT(ctx, "test-key", claims)
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}

	// JWT should have 3 parts
	parts := 0
	for i := range jwt {
		if jwt[i] == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("JWT should have 3 parts (2 dots), got %d dots", parts)
	}
}

func TestManager_GetEncryptedData_NoData(t *testing.T) {
	m := NewManager()

	_, err := m.GetEncryptedData()
	if err == nil {
		t.Error("GetEncryptedData() should return error when no data")
	}
}

func TestManager_GetEncryptedData_WithData(t *testing.T) {
	m := NewManager()
	m.encryptedData = []byte("encrypted-data")

	data, err := m.GetEncryptedData()
	if err != nil {
		t.Fatalf("GetEncryptedData() error = %v", err)
	}
	if string(data) != "encrypted-data" {
		t.Errorf("GetEncryptedData() = %q, want %q", data, "encrypted-data")
	}
}

func TestManager_GetPRFKeyInfos_InvalidContainer(t *testing.T) {
	m := NewManager()

	_, err := m.GetPRFKeyInfos([]byte("invalid json"))
	if err == nil {
		t.Error("GetPRFKeyInfos() should return error for invalid JSON")
	}
}

func TestManager_Unlock_InvalidContainer(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	err := m.Unlock(ctx, []byte("cred"), []byte("prf"), []byte("invalid json"))
	if err == nil {
		t.Error("Unlock() should return error for invalid container")
	}
}

func TestManager_UnlockWithPassword_InvalidContainer(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	err := m.UnlockWithPassword(ctx, "password", []byte("invalid json"))
	if err == nil {
		t.Error("UnlockWithPassword() should return error for invalid container")
	}
}

// Test thread safety
func TestManager_ConcurrentAccess(t *testing.T) {
	m := NewManager()
	m.locked = false

	// Add some test keys
	for i := 0; i < 5; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		m.privateKeys[string(rune('A'+i))] = key
	}

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				m.IsLocked()
				m.GetPrivateKey("A")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestKeyInfo(t *testing.T) {
	info := KeyInfo{
		KeyID:     "key-123",
		DID:       "did:example:123",
		Algorithm: "ES256",
		PublicKey: map[string]interface{}{"kty": "EC", "crv": "P-256"},
	}

	if info.KeyID != "key-123" {
		t.Errorf("KeyID = %q, want %q", info.KeyID, "key-123")
	}
	if info.DID != "did:example:123" {
		t.Errorf("DID = %q, want %q", info.DID, "did:example:123")
	}
}
