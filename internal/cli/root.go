// Package cli provides the command-line interface for wallet-cli.package cli

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
	"github.com/sirosfoundation/go-siros-cli/internal/version"
)

var (
	cfgFile    string
	profile    string
	debug      bool
	jsonOutput bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "wallet-cli",
	Short: "A CLI wallet for verifiable credentials",
	Long: `wallet-cli is a command-line interface for managing verifiable credentials.

It supports WebAuthn authentication, credential issuance via OpenID4VCI,
and credential presentation via OpenID4VP.

Examples:
  # Check if your security key is compatible
  wallet-cli device check

  # Register a new wallet
  wallet-cli auth register --display-name "My Wallet"

  # List credentials
  wallet-cli credentials list

  # Present credentials
  wallet-cli present "openid4vp://authorize?..."`,
	Version: fmt.Sprintf("%s (built %s)", version.Version, version.BuildTime),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.wallet-cli/config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "wallet profile to use (default is 'default')")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")

	// Bind flags to viper - note: don't bind 'profile' flag to viper to avoid unmarshal conflicts
	viper.BindPFlag("global.debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("global.json_output", rootCmd.PersistentFlags().Lookup("json"))

	// Add subcommands
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(credentialsCmd)
	rootCmd.AddCommand(issueCmd)
	rootCmd.AddCommand(presentCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(deviceCmd)
}

func initConfig() error {
	cfg, err := config.Load(cfgFile, profile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Store config in context for subcommands
	config.SetGlobal(cfg)

	if debug {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
		fmt.Fprintf(os.Stderr, "Active profile: %s\n", cfg.ActiveProfile)
	}

	return nil
}
