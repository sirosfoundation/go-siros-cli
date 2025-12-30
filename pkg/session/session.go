// Package session provides session management for the CLI wallet.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Session represents an authenticated user session.
type Session struct {
	Token       string    `json:"token"`
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	BackendURL  string    `json:"backend_url"`
	RpID        string    `json:"rp_id"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`

	mu sync.RWMutex
}

// Manager handles session persistence and lifecycle.
type Manager struct {
	sessionDir string
	current    *Session
	mu         sync.RWMutex
}

// NewManager creates a new session manager.
func NewManager(sessionDir string) (*Manager, error) {
	if sessionDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %w", err)
		}
		sessionDir = filepath.Join(home, ".wallet-cli", "sessions")
	}

	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create session dir: %w", err)
	}

	return &Manager{
		sessionDir: sessionDir,
	}, nil
}

// Save persists a session to disk.
func (m *Manager) Save(profileName string, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionPath := filepath.Join(m.sessionDir, profileName+".json")

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(sessionPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	m.current = session
	return nil
}

// Load retrieves a session from disk.
func (m *Manager) Load(profileName string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionPath := filepath.Join(m.sessionDir, profileName+".json")

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to parse session file: %w", err)
	}

	m.current = &session
	return &session, nil
}

// Delete removes a session from disk.
func (m *Manager) Delete(profileName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionPath := filepath.Join(m.sessionDir, profileName+".json")

	if err := os.Remove(sessionPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete session file: %w", err)
	}

	m.current = nil
	return nil
}

// Current returns the currently loaded session.
func (m *Manager) Current() *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// IsValid checks if the session is valid and not expired.
func (s *Session) IsValid() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Token == "" {
		return false
	}

	// If expiry is set, check it
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		return false
	}

	return true
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ExpiresAt.IsZero() {
		return false // No expiry set
	}

	return time.Now().After(s.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the session expires.
func (s *Session) TimeUntilExpiry() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ExpiresAt.IsZero() {
		return 0
	}

	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// SetExpiry sets the session expiry time.
func (s *Session) SetExpiry(expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpiresAt = expiresAt
}

// GetToken returns the session token.
func (s *Session) GetToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Token
}

// Validator can validate a session token against the backend.
type Validator interface {
	ValidateSession(ctx context.Context, token string) (bool, error)
}

// ValidateWithBackend checks if the session is still valid on the backend.
func (m *Manager) ValidateWithBackend(ctx context.Context, validator Validator) (bool, error) {
	m.mu.RLock()
	session := m.current
	m.mu.RUnlock()

	if session == nil {
		return false, ErrNoSession
	}

	if !session.IsValid() {
		return false, nil
	}

	return validator.ValidateSession(ctx, session.Token)
}

// NewSession creates a new session with the given parameters.
func NewSession(token, userID, displayName, backendURL, rpID string) *Session {
	return &Session{
		Token:       token,
		UserID:      userID,
		DisplayName: displayName,
		BackendURL:  backendURL,
		RpID:        rpID,
		CreatedAt:   time.Now(),
	}
}

// NewSessionWithExpiry creates a new session with an expiry time.
func NewSessionWithExpiry(token, userID, displayName, backendURL, rpID string, expiresAt time.Time) *Session {
	session := NewSession(token, userID, displayName, backendURL, rpID)
	session.ExpiresAt = expiresAt
	return session
}

// Errors
var (
	ErrNoSession      = fmt.Errorf("no active session")
	ErrSessionExpired = fmt.Errorf("session has expired")
)
