// Package config handles configuration and profile management for wallet-cli.package config

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config holds the application configuration.
type Config struct {
	// ActiveProfile is the currently active profile name
	ActiveProfile string `mapstructure:"active_profile"`

	// GlobalSettings apply across all profiles
	Global GlobalConfig `mapstructure:"global"`

	// ProfileSettings holds profile-specific settings (not from viper config file)
	ProfileSettings *ProfileConfig `mapstructure:"-"`
}

// GetProfile returns the profile settings (convenience accessor).
func (c *Config) GetProfile() *ProfileConfig {
	return c.ProfileSettings
}

// GlobalConfig holds settings that apply across all profiles.
type GlobalConfig struct {
	// Debug enables debug logging
	Debug bool `mapstructure:"debug"`

	// JSONOutput enables JSON output format
	JSONOutput bool `mapstructure:"json_output"`

	// Auth settings
	Auth AuthConfig `mapstructure:"auth"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	// PreferNative tries libfido2 before browser fallback
	PreferNative bool `mapstructure:"prefer_native"`

	// BrowserFallback allows browser-based WebAuthn
	BrowserFallback bool `mapstructure:"browser_fallback"`

	// BrowserCommand overrides the browser launch command
	BrowserCommand string `mapstructure:"browser_command"`

	// CallbackTimeout is the timeout for browser callbacks
	CallbackTimeout string `mapstructure:"callback_timeout"`

	// PinMethod specifies how to obtain the FIDO2 PIN: "pinentry", "terminal", "stdin", or "arg"
	PinMethod string `mapstructure:"pin_method"`

	// PinentryProgram is the path to the pinentry program (optional)
	PinentryProgram string `mapstructure:"pinentry_program"`
}

// ProfileConfig holds settings for a specific profile.
type ProfileConfig struct {
	// Name is the profile name
	Name string `mapstructure:"name"`

	// BackendURL is the wallet backend server URL
	BackendURL string `mapstructure:"backend_url"`

	// WebAuthnRpID is the WebAuthn relying party ID
	WebAuthnRpID string `mapstructure:"webauthn_rp_id"`

	// Token is the current session token
	Token string `mapstructure:"token"`

	// UserID is the user's UUID on the backend
	UserID string `mapstructure:"user_id"`

	// DisplayName is a human-readable name for this profile
	DisplayName string `mapstructure:"display_name"`

	// CredentialID is the preferred WebAuthn credential for this profile
	CredentialID string `mapstructure:"credential_id"`

	// AutoSync enables automatic credential synchronization
	AutoSync bool `mapstructure:"auto_sync"`

	// SyncInterval is the interval between syncs (e.g., "5m")
	SyncInterval string `mapstructure:"sync_interval"`
}

var globalConfig *Config

// SetGlobal sets the global configuration instance.
func SetGlobal(cfg *Config) {
	globalConfig = cfg
}

// Get returns the global configuration instance.
func Get() *Config {
	return globalConfig
}

// DefaultConfigDir returns the default configuration directory.
func DefaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".wallet-cli"
	}
	return filepath.Join(home, ".wallet-cli")
}

// Load loads the configuration from file and environment.
func Load(cfgFile string, profile string) (*Config, error) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		configDir := DefaultConfigDir()
		viper.AddConfigPath(configDir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Environment variables
	viper.SetEnvPrefix("WALLET")
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("active_profile", "default")
	viper.SetDefault("global.auth.prefer_native", true)
	viper.SetDefault("global.auth.browser_fallback", true)
	viper.SetDefault("global.auth.callback_timeout", "120s")
	viper.SetDefault("global.auth.pin_method", "pinentry")

	// Read config file (ignore if not found)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
	}

	// Build config manually to avoid conflicts with CLI flags
	// that might have been bound to viper (like "profile")
	cfg := &Config{
		ActiveProfile: viper.GetString("active_profile"),
		Global: GlobalConfig{
			Debug:      viper.GetBool("global.debug"),
			JSONOutput: viper.GetBool("global.json_output"),
			Auth: AuthConfig{
				PreferNative:    viper.GetBool("global.auth.prefer_native"),
				BrowserFallback: viper.GetBool("global.auth.browser_fallback"),
				BrowserCommand:  viper.GetString("global.auth.browser_command"),
				CallbackTimeout: viper.GetString("global.auth.callback_timeout"),
				PinMethod:       viper.GetString("global.auth.pin_method"),
				PinentryProgram: viper.GetString("global.auth.pinentry_program"),
			},
		},
	}

	// Override active profile from flag or environment
	if profile != "" {
		cfg.ActiveProfile = profile
	}
	if envProfile := os.Getenv("WALLET_PROFILE"); envProfile != "" && profile == "" {
		cfg.ActiveProfile = envProfile
	}

	// Load profile-specific config
	profileCfg, err := LoadProfile(cfg.ActiveProfile)
	if err != nil {
		// Profile might not exist yet, that's okay
		profileCfg = &ProfileConfig{
			Name:       cfg.ActiveProfile,
			BackendURL: "http://localhost:8080",
		}
	}
	cfg.ProfileSettings = profileCfg

	return cfg, nil
}

// LoadProfile loads a specific profile's configuration.
func LoadProfile(name string) (*ProfileConfig, error) {
	configDir := DefaultConfigDir()
	profilePath := filepath.Join(configDir, "profiles", name, "profile.yaml")

	v := viper.New()
	v.SetConfigFile(profilePath)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	profile := &ProfileConfig{}
	if err := v.Unmarshal(profile); err != nil {
		return nil, fmt.Errorf("error parsing profile: %w", err)
	}

	profile.Name = name
	return profile, nil
}

// SaveProfile saves a profile configuration.
func SaveProfile(profile *ProfileConfig) error {
	configDir := DefaultConfigDir()
	profileDir := filepath.Join(configDir, "profiles", profile.Name)

	if err := os.MkdirAll(profileDir, 0700); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	v := viper.New()
	v.Set("name", profile.Name)
	v.Set("backend_url", profile.BackendURL)
	v.Set("webauthn_rp_id", profile.WebAuthnRpID)
	v.Set("token", profile.Token)
	v.Set("user_id", profile.UserID)
	v.Set("display_name", profile.DisplayName)
	v.Set("credential_id", profile.CredentialID)
	v.Set("auto_sync", profile.AutoSync)
	v.Set("sync_interval", profile.SyncInterval)

	profilePath := filepath.Join(profileDir, "profile.yaml")
	if err := v.WriteConfigAs(profilePath); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// ListProfiles returns a list of all profile names.
func ListProfiles() ([]string, error) {
	configDir := DefaultConfigDir()
	profilesDir := filepath.Join(configDir, "profiles")

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read profiles directory: %w", err)
	}

	var profiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			profiles = append(profiles, entry.Name())
		}
	}

	return profiles, nil
}

// EnsureConfigDir creates the configuration directory if it doesn't exist.
func EnsureConfigDir() error {
	configDir := DefaultConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	profilesDir := filepath.Join(configDir, "profiles", "default")
	if err := os.MkdirAll(profilesDir, 0700); err != nil {
		return fmt.Errorf("failed to create default profile directory: %w", err)
	}

	return nil
}
