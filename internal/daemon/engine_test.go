package daemon

import (
	"context"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *EngineConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: &EngineConfig{
				BackendURL:     "https://test.example.com",
				TenantID:       "test-tenant",
				SessionTimeout: 30 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "zero timeout uses default",
			cfg: &EngineConfig{
				BackendURL: "https://test.example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewEngine(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && engine == nil {
				t.Error("NewEngine() returned nil engine")
			}
		})
	}
}

func TestNewEngine_DefaultTimeout(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if engine.sessionTimeout != 30*time.Minute {
		t.Errorf("sessionTimeout = %v, want %v", engine.sessionTimeout, 30*time.Minute)
	}
}

func TestDefaultEngine_Status_Locked(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
		TenantID:   "test-tenant",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	status, err := engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if status.Unlocked {
		t.Error("Status.Unlocked should be false for locked engine")
	}
	if status.BackendURL != "https://test.example.com" {
		t.Errorf("Status.BackendURL = %q, want %q", status.BackendURL, "https://test.example.com")
	}
	if status.TenantID != "test-tenant" {
		t.Errorf("Status.TenantID = %q, want %q", status.TenantID, "test-tenant")
	}
}

func TestDefaultEngine_IsUnlocked(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	// Should be locked initially
	if engine.IsUnlocked() {
		t.Error("Engine should be locked initially")
	}
}

func TestDefaultEngine_Lock(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	err = engine.Lock(ctx)
	if err != nil {
		t.Fatalf("Lock() error = %v", err)
	}

	if engine.IsUnlocked() {
		t.Error("Engine should be locked after Lock()")
	}
}

func TestDefaultEngine_GetKeystore(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	ks := engine.GetKeystore()
	if ks == nil {
		t.Error("GetKeystore() returned nil")
	}
}

func TestDefaultEngine_GetBackendClient(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	client := engine.GetBackendClient()
	if client == nil {
		t.Error("GetBackendClient() returned nil")
	}
}

func TestDefaultEngine_GetFIDO2Provider(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	// Provider should be nil when not set
	provider := engine.GetFIDO2Provider()
	if provider != nil {
		t.Error("GetFIDO2Provider() should return nil when not set")
	}
}

func TestDefaultEngine_SignJWT_Locked(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	_, err = engine.SignJWT(ctx, "test-key", map[string]interface{}{"foo": "bar"})
	if err == nil {
		t.Error("SignJWT() should return error when locked")
	}
}

func TestDefaultEngine_Sign_Locked(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	_, err = engine.Sign(ctx, "test-key", []byte("data"))
	if err == nil {
		t.Error("Sign() should return error when locked")
	}
}

func TestDefaultEngine_ListKeys_Locked(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	// When locked, ListKeys should return an error from the underlying keystore
	_, err = engine.ListKeys()
	if err == nil {
		t.Error("ListKeys() should return error when locked")
	}
}

func TestDefaultEngine_GetPrivateKey_Locked(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	_, err = engine.GetPrivateKey("test-key")
	if err == nil {
		t.Error("GetPrivateKey() should return error when locked")
	}
}

func TestDefaultEngine_Close(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	err = engine.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Should be locked after close
	if engine.IsUnlocked() {
		t.Error("Engine should be locked after Close()")
	}
}

func TestDefaultEngine_ResetTimeout(t *testing.T) {
	engine, err := NewEngine(&EngineConfig{
		BackendURL:     "https://test.example.com",
		SessionTimeout: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	defer engine.Close()

	// ResetTimeout should not panic when locked
	engine.ResetTimeout()
}

func TestEngineStatus_Fields(t *testing.T) {
	status := &EngineStatus{
		Unlocked:       true,
		BackendURL:     "https://test.example.com",
		TenantID:       "test-tenant",
		UserID:         "user123",
		KeyCount:       5,
		UnlockedSince:  time.Now(),
		SessionTimeout: time.Now().Add(30 * time.Minute),
	}

	if !status.Unlocked {
		t.Error("Unlocked should be true")
	}
	if status.BackendURL != "https://test.example.com" {
		t.Errorf("BackendURL = %q, want %q", status.BackendURL, "https://test.example.com")
	}
	if status.KeyCount != 5 {
		t.Errorf("KeyCount = %d, want 5", status.KeyCount)
	}
}
