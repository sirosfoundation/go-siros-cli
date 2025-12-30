package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigDir(t *testing.T) {
	dir := DefaultConfigDir()
	if dir == "" {
		t.Error("expected non-empty config dir")
	}

	// Should be under home directory
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("could not get home dir")
	}
	expected := filepath.Join(home, ".wallet-cli")
	if dir != expected {
		t.Errorf("expected %q, got %q", expected, dir)
	}
}

func TestConfig_GetProfile(t *testing.T) {
	profile := &ProfileConfig{
		Name:       "test-profile",
		BackendURL: "https://test.example.com",
	}
	cfg := &Config{
		ProfileSettings: profile,
	}

	result := cfg.GetProfile()
	if result != profile {
		t.Error("expected GetProfile to return ProfileSettings")
	}
	if result.Name != "test-profile" {
		t.Errorf("expected name 'test-profile', got %q", result.Name)
	}
}

func TestGlobalConfig(t *testing.T) {
	// Test SetGlobal and Get
	original := Get()
	defer SetGlobal(original) // Restore

	testConfig := &Config{
		ActiveProfile: "test",
		Global: GlobalConfig{
			Debug: true,
		},
	}

	SetGlobal(testConfig)

	result := Get()
	if result != testConfig {
		t.Error("expected Get to return the config set by SetGlobal")
	}
	if result.ActiveProfile != "test" {
		t.Errorf("expected active_profile 'test', got %q", result.ActiveProfile)
	}
	if !result.Global.Debug {
		t.Error("expected Global.Debug to be true")
	}
}

func TestLoad_WithDefaults(t *testing.T) {
	// Create a temp directory to avoid interfering with real config
	tempDir := t.TempDir()

	// Override HOME to use temp directory
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	cfg, err := Load("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check defaults
	if cfg.ActiveProfile != "default" {
		t.Errorf("expected active_profile 'default', got %q", cfg.ActiveProfile)
	}
	if !cfg.Global.Auth.PreferNative {
		t.Error("expected prefer_native to default to true")
	}
	if !cfg.Global.Auth.BrowserFallback {
		t.Error("expected browser_fallback to default to true")
	}
	if cfg.Global.Auth.CallbackTimeout != "120s" {
		t.Errorf("expected callback_timeout '120s', got %q", cfg.Global.Auth.CallbackTimeout)
	}
}

func TestLoad_WithProfile(t *testing.T) {
	tempDir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	cfg, err := Load("", "custom-profile")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ActiveProfile != "custom-profile" {
		t.Errorf("expected active_profile 'custom-profile', got %q", cfg.ActiveProfile)
	}
}

func TestLoad_WithEnvironmentProfile(t *testing.T) {
	tempDir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	oldEnvProfile := os.Getenv("WALLET_PROFILE")
	os.Setenv("WALLET_PROFILE", "env-profile")
	defer os.Setenv("WALLET_PROFILE", oldEnvProfile)

	cfg, err := Load("", "") // No explicit profile
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ActiveProfile != "env-profile" {
		t.Errorf("expected active_profile 'env-profile', got %q", cfg.ActiveProfile)
	}
}

func TestSaveProfile_And_LoadProfile(t *testing.T) {
	tempDir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	// Save a profile
	profile := &ProfileConfig{
		Name:         "test-save",
		BackendURL:   "https://backend.example.com",
		DisplayName:  "Test Profile",
		CredentialID: "cred-123",
		AutoSync:     true,
		SyncInterval: "10m",
	}

	err := SaveProfile(profile)
	if err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}

	// Load it back
	loaded, err := LoadProfile("test-save")
	if err != nil {
		t.Fatalf("LoadProfile failed: %v", err)
	}

	if loaded.Name != "test-save" {
		t.Errorf("expected name 'test-save', got %q", loaded.Name)
	}
	if loaded.BackendURL != "https://backend.example.com" {
		t.Errorf("expected backend_url, got %q", loaded.BackendURL)
	}
	if loaded.DisplayName != "Test Profile" {
		t.Errorf("expected display_name 'Test Profile', got %q", loaded.DisplayName)
	}
	if loaded.CredentialID != "cred-123" {
		t.Errorf("expected credential_id 'cred-123', got %q", loaded.CredentialID)
	}
	if !loaded.AutoSync {
		t.Error("expected auto_sync to be true")
	}
	if loaded.SyncInterval != "10m" {
		t.Errorf("expected sync_interval '10m', got %q", loaded.SyncInterval)
	}
}

func TestLoadProfile_NotFound(t *testing.T) {
	tempDir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	_, err := LoadProfile("nonexistent-profile")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestListProfiles(t *testing.T) {
	tempDir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	// Initially no profiles
	profiles, err := ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(profiles))
	}

	// Save some profiles
	for _, name := range []string{"profile-a", "profile-b", "profile-c"} {
		err := SaveProfile(&ProfileConfig{Name: name, BackendURL: "http://test"})
		if err != nil {
			t.Fatalf("SaveProfile failed for %s: %v", name, err)
		}
	}

	// List again
	profiles, err = ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}
	if len(profiles) != 3 {
		t.Errorf("expected 3 profiles, got %d", len(profiles))
	}

	// Check all profiles are present
	profileMap := make(map[string]bool)
	for _, p := range profiles {
		profileMap[p] = true
	}
	for _, expected := range []string{"profile-a", "profile-b", "profile-c"} {
		if !profileMap[expected] {
			t.Errorf("expected profile %q in list", expected)
		}
	}
}

func TestEnsureConfigDir(t *testing.T) {
	tempDir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	err := EnsureConfigDir()
	if err != nil {
		t.Fatalf("EnsureConfigDir failed: %v", err)
	}

	// Check directories exist
	configDir := DefaultConfigDir()
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		t.Error("config dir was not created")
	}

	defaultProfileDir := filepath.Join(configDir, "profiles", "default")
	if _, err := os.Stat(defaultProfileDir); os.IsNotExist(err) {
		t.Error("default profile dir was not created")
	}
}

func TestProfileConfig_Fields(t *testing.T) {
	profile := &ProfileConfig{
		Name:         "test",
		BackendURL:   "https://backend.test",
		WebAuthnRpID: "test.example.com",
		Token:        "token-123",
		UserID:       "user-456",
		DisplayName:  "Test User",
		CredentialID: "cred-789",
		AutoSync:     true,
		SyncInterval: "5m",
	}

	// Test all fields are accessible
	if profile.Name != "test" {
		t.Errorf("Name mismatch")
	}
	if profile.BackendURL != "https://backend.test" {
		t.Errorf("BackendURL mismatch")
	}
	if profile.WebAuthnRpID != "test.example.com" {
		t.Errorf("WebAuthnRpID mismatch")
	}
	if profile.Token != "token-123" {
		t.Errorf("Token mismatch")
	}
	if profile.UserID != "user-456" {
		t.Errorf("UserID mismatch")
	}
	if profile.DisplayName != "Test User" {
		t.Errorf("DisplayName mismatch")
	}
	if profile.CredentialID != "cred-789" {
		t.Errorf("CredentialID mismatch")
	}
	if !profile.AutoSync {
		t.Errorf("AutoSync mismatch")
	}
	if profile.SyncInterval != "5m" {
		t.Errorf("SyncInterval mismatch")
	}
}

func TestGlobalConfig_Fields(t *testing.T) {
	global := GlobalConfig{
		Debug:      true,
		JSONOutput: true,
		Auth: AuthConfig{
			PreferNative:    true,
			BrowserFallback: false,
			BrowserCommand:  "/usr/bin/firefox",
			CallbackTimeout: "60s",
		},
	}

	if !global.Debug {
		t.Error("Debug mismatch")
	}
	if !global.JSONOutput {
		t.Error("JSONOutput mismatch")
	}
	if !global.Auth.PreferNative {
		t.Error("Auth.PreferNative mismatch")
	}
	if global.Auth.BrowserFallback {
		t.Error("Auth.BrowserFallback mismatch")
	}
	if global.Auth.BrowserCommand != "/usr/bin/firefox" {
		t.Error("Auth.BrowserCommand mismatch")
	}
	if global.Auth.CallbackTimeout != "60s" {
		t.Error("Auth.CallbackTimeout mismatch")
	}
}

func TestLoad_WithConfigFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create a config file
	configContent := `
active_profile: custom
global:
  debug: true
  json_output: true
  auth:
    prefer_native: false
    browser_fallback: true
    callback_timeout: "30s"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Also need to set HOME for profile loading
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", oldHome)

	cfg, err := Load(configPath, "")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.ActiveProfile != "custom" {
		t.Errorf("expected active_profile 'custom', got %q", cfg.ActiveProfile)
	}
	if !cfg.Global.Debug {
		t.Error("expected debug to be true")
	}
	if !cfg.Global.JSONOutput {
		t.Error("expected json_output to be true")
	}
	if cfg.Global.Auth.PreferNative {
		t.Error("expected prefer_native to be false")
	}
	if cfg.Global.Auth.CallbackTimeout != "30s" {
		t.Errorf("expected callback_timeout '30s', got %q", cfg.Global.Auth.CallbackTimeout)
	}
}
