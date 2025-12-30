package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Profile management commands",
	Long:  `Commands for managing multiple wallet profiles/identities.`,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles",
	Long:  `Display a list of all configured wallet profiles.`,
	RunE:  runProfileList,
}

var profileCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new profile",
	Long: `Create a new wallet profile with the specified name.

A profile allows you to maintain separate wallet identities,
each with their own credentials and backend configuration.`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileCreate,
}

var profileUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Switch to a different profile",
	Long:  `Set the specified profile as the active profile.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileUse,
}

var profileShowCmd = &cobra.Command{
	Use:   "show [name]",
	Short: "Show profile details",
	Long:  `Display detailed information about a profile. Uses current profile if name not specified.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProfileShow,
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a profile",
	Long: `Delete the specified profile and all its data.

This action cannot be undone. The profile's credentials and
session data will be permanently removed.`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileDelete,
}

var (
	profileBackend     string
	profileDisplayName string
)

func init() {
	// Create flags
	profileCreateCmd.Flags().StringVar(&profileBackend, "backend", "", "Backend URL for this profile")
	profileCreateCmd.Flags().StringVar(&profileDisplayName, "display-name", "", "Display name for this profile")

	// Add subcommands
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profileShowCmd)
	profileCmd.AddCommand(profileDeleteCmd)
}

func runProfileList(cmd *cobra.Command, args []string) error {
	cfg := config.Get()

	profiles, err := config.ListProfiles()
	if err != nil {
		return fmt.Errorf("failed to list profiles: %w", err)
	}

	if jsonOutput {
		// TODO: JSON output
		fmt.Println("[]")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tBACKEND\tSTATUS")

	if len(profiles) == 0 {
		profiles = []string{"default"}
	}

	for _, name := range profiles {
		status := ""
		if name == cfg.ActiveProfile {
			status = "active"
		}

		profileCfg, _ := config.LoadProfile(name)
		backend := "(not configured)"
		if profileCfg != nil && profileCfg.BackendURL != "" {
			backend = profileCfg.BackendURL
		}

		fmt.Fprintf(w, "%s\t%s\t%s\n", name, backend, status)
	}

	w.Flush()
	return nil
}

func runProfileCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Check if profile already exists
	profiles, _ := config.ListProfiles()
	for _, p := range profiles {
		if p == name {
			return fmt.Errorf("profile '%s' already exists", name)
		}
	}

	profile := &config.ProfileConfig{
		Name:        name,
		BackendURL:  profileBackend,
		DisplayName: profileDisplayName,
	}

	if err := config.EnsureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := config.SaveProfile(profile); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	fmt.Printf("Created profile '%s'\n", name)
	if profileBackend != "" {
		fmt.Printf("Backend: %s\n", profileBackend)
	}

	return nil
}

func runProfileUse(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Verify profile exists
	_, err := config.LoadProfile(name)
	if err != nil {
		// Create default profile if it doesn't exist
		if name == "default" {
			if err := config.EnsureConfigDir(); err != nil {
				return err
			}
			profile := &config.ProfileConfig{Name: "default"}
			if err := config.SaveProfile(profile); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("profile '%s' not found", name)
		}
	}

	// TODO: Update global config to set active profile
	// For now, just inform the user
	fmt.Printf("Switched to profile '%s'\n", name)
	fmt.Println("Note: Use --profile flag or WALLET_PROFILE env var until config persistence is implemented")

	return nil
}

func runProfileShow(cmd *cobra.Command, args []string) error {
	cfg := config.Get()

	name := cfg.ActiveProfile
	if len(args) > 0 {
		name = args[0]
	}

	profile, err := config.LoadProfile(name)
	if err != nil {
		// Use current config if loading fails
		if name == cfg.ActiveProfile {
			profile = cfg.GetProfile()
		} else {
			return fmt.Errorf("profile '%s' not found", name)
		}
	}

	fmt.Printf("Profile: %s\n", profile.Name)
	if profile.DisplayName != "" {
		fmt.Printf("Display Name: %s\n", profile.DisplayName)
	}
	fmt.Printf("Backend URL: %s\n", profile.BackendURL)
	if profile.CredentialID != "" {
		fmt.Printf("Credential ID: %s\n", profile.CredentialID)
	}
	fmt.Printf("Auto Sync: %v\n", profile.AutoSync)
	if profile.SyncInterval != "" {
		fmt.Printf("Sync Interval: %s\n", profile.SyncInterval)
	}

	return nil
}

func runProfileDelete(cmd *cobra.Command, args []string) error {
	name := args[0]

	if name == "default" {
		return fmt.Errorf("cannot delete the default profile")
	}

	cfg := config.Get()
	if name == cfg.ActiveProfile {
		return fmt.Errorf("cannot delete the active profile; switch to another profile first")
	}

	// TODO: Implement profile deletion
	// 1. Remove profile directory
	// 2. Clear any cached data

	fmt.Printf("Deleting profile '%s'...\n", name)
	fmt.Println("✗ Profile deletion not yet implemented")

	return nil
}
