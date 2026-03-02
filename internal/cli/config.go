package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration commands",
	Long:  `Commands for viewing and modifying wallet-cli configuration.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display all current configuration settings with their values.`,
	RunE:  runConfigShow,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration parameters",
	Long:  `Display all available configuration parameters with descriptions.`,
	RunE:  runConfigList,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value for the current profile.

Available keys:
  backend_url       - Wallet backend server URL
  display_name      - Profile display name
  auto_sync         - Enable automatic sync (true/false)
  sync_interval     - Sync interval (e.g., "5m")
  auth.prefer_native    - Prefer native FIDO2 (true/false)
  auth.browser_fallback - Enable browser fallback (true/false)`,
	Args: cobra.ExactArgs(2),
	RunE: runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Long:  `Get the value of a specific configuration key.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long: `Initialize the wallet-cli configuration directory and default profile.

This creates ~/.wallet-cli/ with default configuration.`,
	RunE: runConfigInit,
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configInitCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg := config.Get()

	fmt.Println("=== Global Settings ===")
	fmt.Printf("  active_profile:         %s\n", cfg.ActiveProfile)
	fmt.Printf("  debug:                  %v\n", cfg.Global.Debug)
	fmt.Printf("  json_output:            %v\n", cfg.Global.JSONOutput)
	fmt.Println("")

	fmt.Println("=== Auth Settings ===")
	fmt.Printf("  auth.prefer_native:     %v\n", cfg.Global.Auth.PreferNative)
	fmt.Printf("  auth.browser_fallback:  %v\n", cfg.Global.Auth.BrowserFallback)
	fmt.Printf("  auth.browser_command:   %s\n", valueOrDefault(cfg.Global.Auth.BrowserCommand, "(default)"))
	fmt.Printf("  auth.callback_timeout:  %s\n", valueOrDefault(cfg.Global.Auth.CallbackTimeout, "30s"))
	fmt.Println("")

	fmt.Println("=== Profile Settings ===")
	fmt.Printf("  name:                   %s\n", cfg.GetProfile().Name)
	fmt.Printf("  tenant_id:              %s\n", valueOrDefault(cfg.GetProfile().TenantID, config.DefaultTenantID))
	fmt.Printf("  backend_url:            %s\n", valueOrDefault(cfg.GetProfile().BackendURL, "(not set)"))
	fmt.Printf("  webauthn_rp_id:         %s\n", valueOrDefault(cfg.GetProfile().WebAuthnRpID, "(not set)"))
	fmt.Printf("  display_name:           %s\n", valueOrDefault(cfg.GetProfile().DisplayName, "(not set)"))
	fmt.Printf("  user_id:                %s\n", valueOrDefault(cfg.GetProfile().UserID, "(not set)"))
	fmt.Printf("  credential_id:          %s\n", truncateString(cfg.GetProfile().CredentialID, 20))
	fmt.Printf("  token:                  %s\n", maskToken(cfg.GetProfile().Token))
	fmt.Printf("  auto_sync:              %v\n", cfg.GetProfile().AutoSync)
	fmt.Printf("  sync_interval:          %s\n", valueOrDefault(cfg.GetProfile().SyncInterval, "5m"))
	fmt.Println("")
	fmt.Println("Use 'wallet-cli config list' to see parameter descriptions.")

	return nil
}

// configParameter describes a configuration parameter
type configParameter struct {
	Key         string
	Description string
	Default     string
	Scope       string // "global" or "profile"
}

var configParameters = []configParameter{
	// Global settings
	{"active_profile", "Currently active profile name", "default", "global"},
	{"debug", "Enable debug logging", "false", "global"},
	{"json_output", "Output in JSON format", "false", "global"},

	// Auth settings
	{"auth.prefer_native", "Prefer native libfido2 over browser WebAuthn", "true", "global"},
	{"auth.browser_fallback", "Fall back to browser if native FIDO2 unavailable", "true", "global"},
	{"auth.browser_command", "Custom browser command (empty = system default)", "", "global"},
	{"auth.callback_timeout", "Timeout for browser WebAuthn callbacks", "30s", "global"},

	// Profile settings
	{"tenant_id", "Tenant identifier for multi-tenant backends", "default", "profile"},
	{"backend_url", "Wallet backend server URL", "http://localhost:8080", "profile"},
	{"webauthn_rp_id", "WebAuthn relying party ID (set by server)", "", "profile"},
	{"display_name", "Human-readable name for this wallet", "", "profile"},
	{"user_id", "User UUID on the backend (set after registration)", "", "profile"},
	{"credential_id", "WebAuthn credential ID (set after registration)", "", "profile"},
	{"token", "Session token (set after login)", "", "profile"},
	{"auto_sync", "Automatically sync credentials with backend", "false", "profile"},
	{"sync_interval", "Interval between automatic syncs", "5m", "profile"},
}

func runConfigList(cmd *cobra.Command, args []string) error {
	fmt.Println("Available configuration parameters:")
	fmt.Println("")

	fmt.Println("=== Global Settings ===")
	fmt.Println("These settings apply across all profiles.")
	fmt.Println("")
	for _, p := range configParameters {
		if p.Scope == "global" {
			printParameter(p)
		}
	}

	fmt.Println("")
	fmt.Println("=== Profile Settings ===")
	fmt.Println("These settings are specific to each profile.")
	fmt.Println("")
	for _, p := range configParameters {
		if p.Scope == "profile" {
			printParameter(p)
		}
	}

	fmt.Println("")
	fmt.Println("To set a value:    wallet-cli config set <key> <value>")
	fmt.Println("To get a value:    wallet-cli config get <key>")
	fmt.Println("To show all:       wallet-cli config show")

	return nil
}

func printParameter(p configParameter) {
	fmt.Printf("  %s\n", p.Key)
	fmt.Printf("      %s\n", p.Description)
	if p.Default != "" {
		fmt.Printf("      Default: %s\n", p.Default)
	}
	fmt.Println("")
}

func valueOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func truncateString(s string, maxLen int) string {
	if s == "" {
		return "(not set)"
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 10 {
		return "****"
	}
	return token[:5] + "..." + token[len(token)-5:]
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	cfg := config.Get()

	// Handle profile-specific settings
	switch key {
	case "tenant_id":
		cfg.GetProfile().TenantID = value
	case "backend_url":
		cfg.GetProfile().BackendURL = value
	case "display_name":
		cfg.GetProfile().DisplayName = value
	case "auto_sync":
		cfg.GetProfile().AutoSync = value == "true"
	case "sync_interval":
		cfg.GetProfile().SyncInterval = value
	default:
		// Try viper for global settings
		viper.Set(key, value)
		fmt.Printf("Set %s = %s\n", key, value)
		fmt.Println("Note: Global config persistence not yet implemented")
		return nil
	}

	// Save profile
	if err := config.SaveProfile(cfg.GetProfile()); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	fmt.Printf("Set %s = %s\n", key, value)
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]
	cfg := config.Get()

	var value interface{}
	switch key {
	case "tenant_id":
		value = cfg.GetProfile().TenantID
	case "backend_url":
		value = cfg.GetProfile().BackendURL
	case "display_name":
		value = cfg.GetProfile().DisplayName
	case "auto_sync":
		value = cfg.GetProfile().AutoSync
	case "sync_interval":
		value = cfg.GetProfile().SyncInterval
	case "active_profile":
		value = cfg.ActiveProfile
	case "auth.prefer_native":
		value = cfg.Global.Auth.PreferNative
	case "auth.browser_fallback":
		value = cfg.Global.Auth.BrowserFallback
	case "auth.callback_timeout":
		value = cfg.Global.Auth.CallbackTimeout
	default:
		// Try viper
		value = viper.Get(key)
		if value == nil {
			return fmt.Errorf("unknown configuration key: %s", key)
		}
	}

	fmt.Println(value)
	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	fmt.Println("Initializing wallet-cli configuration...")

	if err := config.EnsureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create default profile
	defaultProfile := &config.ProfileConfig{
		Name:       "default",
		TenantID:   config.DefaultTenantID,
		BackendURL: "http://localhost:8080",
	}

	if err := config.SaveProfile(defaultProfile); err != nil {
		return fmt.Errorf("failed to create default profile: %w", err)
	}

	configDir := config.DefaultConfigDir()
	fmt.Printf("✓ Created configuration directory: %s\n", configDir)
	fmt.Println("✓ Created default profile")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Println("  1. Set your backend URL:")
	fmt.Println("     wallet-cli config set backend_url https://wallet.example.com")
	fmt.Println("  2. Register your wallet:")
	fmt.Println("     wallet-cli auth register")

	return nil
}
