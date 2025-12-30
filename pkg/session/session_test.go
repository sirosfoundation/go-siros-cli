package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	t.Run("with default dir", func(t *testing.T) {
		tempDir := t.TempDir()
		oldHome := os.Getenv("HOME")
		os.Setenv("HOME", tempDir)
		defer os.Setenv("HOME", oldHome)

		m, err := NewManager("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m == nil {
			t.Fatal("expected non-nil manager")
		}

		expectedDir := filepath.Join(tempDir, ".wallet-cli", "sessions")
		if m.sessionDir != expectedDir {
			t.Errorf("expected sessionDir %q, got %q", expectedDir, m.sessionDir)
		}
	})

	t.Run("with custom dir", func(t *testing.T) {
		tempDir := t.TempDir()
		customDir := filepath.Join(tempDir, "custom-sessions")

		m, err := NewManager(customDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.sessionDir != customDir {
			t.Errorf("expected sessionDir %q, got %q", customDir, m.sessionDir)
		}

		// Check directory was created
		if _, err := os.Stat(customDir); os.IsNotExist(err) {
			t.Error("expected session directory to be created")
		}
	})
}

func TestManager_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	m, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	session := &Session{
		Token:       "test-token",
		UserID:      "user-123",
		DisplayName: "Test User",
		BackendURL:  "https://backend.example.com",
		RpID:        "example.com",
		CreatedAt:   time.Now(),
	}

	// Save
	err = m.Save("test-profile", session)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file was created
	sessionPath := filepath.Join(tempDir, "test-profile.json")
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		t.Error("session file was not created")
	}

	// Load
	loaded, err := m.Load("test-profile")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %q", loaded.Token)
	}
	if loaded.UserID != "user-123" {
		t.Errorf("expected user_id 'user-123', got %q", loaded.UserID)
	}
	if loaded.DisplayName != "Test User" {
		t.Errorf("expected display_name 'Test User', got %q", loaded.DisplayName)
	}
	if loaded.BackendURL != "https://backend.example.com" {
		t.Errorf("expected backend_url, got %q", loaded.BackendURL)
	}
	if loaded.RpID != "example.com" {
		t.Errorf("expected rp_id 'example.com', got %q", loaded.RpID)
	}
}

func TestManager_Load_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	m, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	_, err = m.Load("nonexistent")
	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}

func TestManager_Delete(t *testing.T) {
	tempDir := t.TempDir()
	m, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Save a session first
	session := &Session{Token: "test-token"}
	err = m.Save("to-delete", session)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Delete
	err = m.Delete("to-delete")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file is gone
	sessionPath := filepath.Join(tempDir, "to-delete.json")
	if _, err := os.Stat(sessionPath); !os.IsNotExist(err) {
		t.Error("session file should have been deleted")
	}

	// Current should be nil
	if m.Current() != nil {
		t.Error("expected Current() to be nil after delete")
	}
}

func TestManager_Delete_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	m, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Should not error when deleting nonexistent
	err = m.Delete("nonexistent")
	if err != nil {
		t.Errorf("Delete of nonexistent should not error: %v", err)
	}
}

func TestManager_Current(t *testing.T) {
	tempDir := t.TempDir()
	m, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Initially nil
	if m.Current() != nil {
		t.Error("expected Current() to be nil initially")
	}

	// After save, should be set
	session := &Session{Token: "test"}
	m.Save("profile", session)
	if m.Current() != session {
		t.Error("expected Current() to return saved session")
	}

	// After load, should be the loaded session
	m2, _ := NewManager(tempDir)
	m2.Load("profile")
	if m2.Current() == nil {
		t.Error("expected Current() to be set after load")
	}
}

func TestSession_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
		valid   bool
	}{
		{
			name:    "empty token",
			session: &Session{Token: ""},
			valid:   false,
		},
		{
			name:    "valid token no expiry",
			session: &Session{Token: "valid-token"},
			valid:   true,
		},
		{
			name: "valid token with future expiry",
			session: &Session{
				Token:     "valid-token",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			valid: true,
		},
		{
			name: "valid token with past expiry",
			session: &Session{
				Token:     "valid-token",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestSession_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
		expired bool
	}{
		{
			name:    "no expiry set",
			session: &Session{Token: "test"},
			expired: false,
		},
		{
			name: "future expiry",
			session: &Session{
				Token:     "test",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expired: false,
		},
		{
			name: "past expiry",
			session: &Session{
				Token:     "test",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsExpired(); got != tt.expired {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expired)
			}
		})
	}
}

func TestSession_TimeUntilExpiry(t *testing.T) {
	t.Run("no expiry", func(t *testing.T) {
		s := &Session{Token: "test"}
		if d := s.TimeUntilExpiry(); d != 0 {
			t.Errorf("expected 0, got %v", d)
		}
	})

	t.Run("future expiry", func(t *testing.T) {
		s := &Session{
			Token:     "test",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		d := s.TimeUntilExpiry()
		if d < 59*time.Minute || d > 61*time.Minute {
			t.Errorf("expected ~1 hour, got %v", d)
		}
	})

	t.Run("past expiry", func(t *testing.T) {
		s := &Session{
			Token:     "test",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		if d := s.TimeUntilExpiry(); d != 0 {
			t.Errorf("expected 0 for expired, got %v", d)
		}
	})
}

func TestSession_SetExpiry(t *testing.T) {
	s := &Session{Token: "test"}
	expiry := time.Now().Add(2 * time.Hour)

	s.SetExpiry(expiry)

	if !s.ExpiresAt.Equal(expiry) {
		t.Errorf("expected expiry %v, got %v", expiry, s.ExpiresAt)
	}
}

func TestSession_GetToken(t *testing.T) {
	s := &Session{Token: "my-secret-token"}
	if got := s.GetToken(); got != "my-secret-token" {
		t.Errorf("expected 'my-secret-token', got %q", got)
	}
}

func TestNewSession(t *testing.T) {
	s := NewSession("token", "user", "display", "https://backend", "rpid")

	if s.Token != "token" {
		t.Errorf("Token mismatch")
	}
	if s.UserID != "user" {
		t.Errorf("UserID mismatch")
	}
	if s.DisplayName != "display" {
		t.Errorf("DisplayName mismatch")
	}
	if s.BackendURL != "https://backend" {
		t.Errorf("BackendURL mismatch")
	}
	if s.RpID != "rpid" {
		t.Errorf("RpID mismatch")
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestNewSessionWithExpiry(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour)
	s := NewSessionWithExpiry("token", "user", "display", "https://backend", "rpid", expiry)

	if !s.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt mismatch: expected %v, got %v", expiry, s.ExpiresAt)
	}
}

// Mock validator for testing
type mockValidator struct {
	valid bool
	err   error
}

func (m *mockValidator) ValidateSession(ctx context.Context, token string) (bool, error) {
	return m.valid, m.err
}

func TestManager_ValidateWithBackend(t *testing.T) {
	tempDir := t.TempDir()
	m, _ := NewManager(tempDir)

	t.Run("no session", func(t *testing.T) {
		validator := &mockValidator{valid: true}
		_, err := m.ValidateWithBackend(context.Background(), validator)
		if err != ErrNoSession {
			t.Errorf("expected ErrNoSession, got %v", err)
		}
	})

	t.Run("valid session", func(t *testing.T) {
		session := &Session{Token: "valid"}
		m.Save("test", session)

		validator := &mockValidator{valid: true}
		valid, err := m.ValidateWithBackend(context.Background(), validator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Error("expected session to be valid")
		}
	})

	t.Run("invalid session on backend", func(t *testing.T) {
		session := &Session{Token: "invalid"}
		m.Save("test", session)

		validator := &mockValidator{valid: false}
		valid, err := m.ValidateWithBackend(context.Background(), validator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Error("expected session to be invalid")
		}
	})

	t.Run("expired session", func(t *testing.T) {
		session := &Session{
			Token:     "expired",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		m.Save("test", session)

		validator := &mockValidator{valid: true}
		valid, err := m.ValidateWithBackend(context.Background(), validator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Error("expected expired session to be invalid")
		}
	})
}
