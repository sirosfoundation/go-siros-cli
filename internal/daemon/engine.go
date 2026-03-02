// Package daemon provides the wallet daemon infrastructure.
package daemon

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
)

// Engine provides the core wallet functionality.
// It can be used in both direct CLI mode and daemon mode.
type Engine interface {
	// Status returns the current engine status.
	Status(ctx context.Context) (*EngineStatus, error)

	// UnlockWithPRF unlocks the keystore using PRF output.
	UnlockWithPRF(ctx context.Context, credentialID, prfOutput, encryptedData []byte) error

	// UnlockWithPassword unlocks the keystore using a password.
	UnlockWithPassword(ctx context.Context, password string, encryptedData []byte) error

	// Lock locks the keystore.
	Lock(ctx context.Context) error

	// IsUnlocked returns true if the keystore is unlocked.
	IsUnlocked() bool

	// GetKeystore returns the keystore manager.
	GetKeystore() keystore.Manager

	// GetBackendClient returns the backend client.
	GetBackendClient() *backend.Client

	// GetFIDO2Provider returns the FIDO2 provider.
	GetFIDO2Provider() fido2.Provider

	// SignJWT signs a JWT using the specified key.
	SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error)

	// Sign creates a raw signature.
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)

	// GetPrivateKey returns a private key for direct signing.
	GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error)

	// ListKeys returns all available keys.
	ListKeys() ([]keystore.KeyInfo, error)

	// ResetTimeout resets the session timeout.
	ResetTimeout()

	// Close shuts down the engine.
	Close() error
}

// EngineStatus contains the current engine state.
type EngineStatus struct {
	Unlocked       bool      `json:"unlocked"`
	BackendURL     string    `json:"backend_url"`
	TenantID       string    `json:"tenant_id"`
	UserID         string    `json:"user_id,omitempty"`
	KeyCount       int       `json:"key_count"`
	UnlockedSince  time.Time `json:"unlocked_since,omitempty"`
	SessionTimeout time.Time `json:"session_timeout,omitempty"`
}

// EngineConfig contains configuration for the engine.
type EngineConfig struct {
	Profile        *config.ProfileConfig
	BackendURL     string
	TenantID       string
	SessionTimeout time.Duration
	FIDO2Provider  fido2.Provider
}

// DefaultEngine is the default implementation of Engine.
type DefaultEngine struct {
	mu             sync.RWMutex
	config         *EngineConfig
	keystore       *keystore.DefaultManager
	backendClient  *backend.Client
	fido2Provider  fido2.Provider
	unlockedSince  time.Time
	sessionTimeout time.Duration
	unlockTimer    *time.Timer
}

// NewEngine creates a new engine instance.
func NewEngine(cfg *EngineConfig) (*DefaultEngine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Create backend client
	backendClient := backend.NewClient(cfg.BackendURL)
	if cfg.TenantID != "" {
		backendClient.SetTenantID(cfg.TenantID)
	}

	// Create keystore manager
	ks := keystore.NewManager()

	// Use provided FIDO2 provider or nil (will be set later)
	provider := cfg.FIDO2Provider

	sessionTimeout := cfg.SessionTimeout
	if sessionTimeout == 0 {
		sessionTimeout = 30 * time.Minute
	}

	return &DefaultEngine{
		config:         cfg,
		keystore:       ks,
		backendClient:  backendClient,
		fido2Provider:  provider,
		sessionTimeout: sessionTimeout,
	}, nil
}

// SetFIDO2Provider sets the FIDO2 provider.
func (e *DefaultEngine) SetFIDO2Provider(provider fido2.Provider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fido2Provider = provider
}

// Status returns the current engine status.
func (e *DefaultEngine) Status(ctx context.Context) (*EngineStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &EngineStatus{
		Unlocked:   !e.keystore.IsLocked(),
		BackendURL: e.config.BackendURL,
		TenantID:   e.config.TenantID,
	}

	if status.Unlocked {
		status.UnlockedSince = e.unlockedSince
		status.SessionTimeout = e.unlockedSince.Add(e.sessionTimeout)

		keys, err := e.keystore.ListKeys()
		if err == nil {
			status.KeyCount = len(keys)
		}
	}

	return status, nil
}

// UnlockWithPRF unlocks the keystore using PRF output.
func (e *DefaultEngine) UnlockWithPRF(ctx context.Context, credentialID, prfOutput, encryptedData []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.keystore.IsLocked() {
		// Already unlocked, reset timeout
		e.resetUnlockTimer()
		return nil
	}

	// Unlock keystore with PRF output
	if err := e.keystore.Unlock(ctx, credentialID, prfOutput, encryptedData); err != nil {
		return fmt.Errorf("failed to unlock keystore: %w", err)
	}

	e.unlockedSince = time.Now()
	e.resetUnlockTimer()

	return nil
}

// UnlockWithPassword unlocks the keystore using a password.
func (e *DefaultEngine) UnlockWithPassword(ctx context.Context, password string, encryptedData []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.keystore.IsLocked() {
		// Already unlocked, reset timeout
		e.resetUnlockTimer()
		return nil
	}

	// Unlock keystore with password
	if err := e.keystore.UnlockWithPassword(ctx, password, encryptedData); err != nil {
		return fmt.Errorf("failed to unlock keystore: %w", err)
	}

	e.unlockedSince = time.Now()
	e.resetUnlockTimer()

	return nil
}

// Lock locks the keystore.
func (e *DefaultEngine) Lock(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.unlockTimer != nil {
		e.unlockTimer.Stop()
		e.unlockTimer = nil
	}

	return e.keystore.Lock()
}

// IsUnlocked returns true if the keystore is unlocked.
func (e *DefaultEngine) IsUnlocked() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return !e.keystore.IsLocked()
}

// GetKeystore returns the keystore manager.
func (e *DefaultEngine) GetKeystore() keystore.Manager {
	return e.keystore
}

// GetBackendClient returns the backend client.
func (e *DefaultEngine) GetBackendClient() *backend.Client {
	return e.backendClient
}

// GetFIDO2Provider returns the FIDO2 provider.
func (e *DefaultEngine) GetFIDO2Provider() fido2.Provider {
	return e.fido2Provider
}

// SignJWT signs a JWT using the specified key.
func (e *DefaultEngine) SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.keystore.IsLocked() {
		return "", keystore.ErrKeystoreLocked
	}

	return e.keystore.SignJWT(ctx, keyID, claims)
}

// Sign creates a raw signature.
func (e *DefaultEngine) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.keystore.IsLocked() {
		return nil, keystore.ErrKeystoreLocked
	}

	return e.keystore.Sign(ctx, keyID, data)
}

// GetPrivateKey returns a private key for direct signing.
func (e *DefaultEngine) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.keystore.GetPrivateKey(keyID)
}

// ListKeys returns all available keys.
func (e *DefaultEngine) ListKeys() ([]keystore.KeyInfo, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.keystore.ListKeys()
}

// ResetTimeout resets the session timeout.
func (e *DefaultEngine) ResetTimeout() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.keystore.IsLocked() {
		e.resetUnlockTimer()
	}
}

// Close shuts down the engine.
func (e *DefaultEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.unlockTimer != nil {
		e.unlockTimer.Stop()
	}

	return e.keystore.Lock()
}

// resetUnlockTimer resets the session timeout timer.
func (e *DefaultEngine) resetUnlockTimer() {
	if e.unlockTimer != nil {
		e.unlockTimer.Stop()
	}

	e.unlockTimer = time.AfterFunc(e.sessionTimeout, func() {
		e.Lock(context.Background())
	})
}
