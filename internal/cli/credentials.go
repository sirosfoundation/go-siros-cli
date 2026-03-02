package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
)

var credentialsCmd = &cobra.Command{
	Use:     "credentials",
	Aliases: []string{"cred", "creds"},
	Short:   "Credential management commands",
	Long:    `Commands for listing, viewing, and managing verifiable credentials.`,
}

var credentialsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all credentials",
	Long:  `Display a list of all verifiable credentials stored in the wallet.`,
	RunE:  runCredentialsList,
}

var credentialsShowCmd = &cobra.Command{
	Use:   "show <credential-id>",
	Short: "Show credential details",
	Long: `Display detailed information about a specific credential.

The credential-id can be found using 'credentials list'.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialsShow,
}

var credentialsExportCmd = &cobra.Command{
	Use:   "export <credential-id>",
	Short: "Export a credential",
	Long: `Export a credential in its original format (e.g., SD-JWT, mDL).

This outputs the raw credential that can be imported into another wallet.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialsExport,
}

var credentialsDeleteCmd = &cobra.Command{
	Use:   "delete <credential-id>",
	Short: "Delete a credential",
	Long:  `Delete a credential from the wallet.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runCredentialsDelete,
}

var (
	credType   string
	showAll    bool
	outputFile string
	rawOutput  bool
	force      bool
)

func init() {
	// List flags
	credentialsListCmd.Flags().StringVar(&credType, "type", "", "Filter by credential type")

	// Show flags
	credentialsShowCmd.Flags().BoolVar(&showAll, "show-all", false, "Show all claims including hidden ones")
	credentialsShowCmd.Flags().BoolVar(&rawOutput, "raw", false, "Show raw credential data")

	// Export flags
	credentialsExportCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")

	// Delete flags
	credentialsDeleteCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	// Add subcommands
	credentialsCmd.AddCommand(credentialsListCmd)
	credentialsCmd.AddCommand(credentialsShowCmd)
	credentialsCmd.AddCommand(credentialsExportCmd)
	credentialsCmd.AddCommand(credentialsDeleteCmd)
}

// getAuthenticatedClient creates a backend client with the stored auth token.
func getAuthenticatedClient() (*backend.Client, error) {
	cfg := config.Get()
	profile := cfg.GetProfile()

	if profile.BackendURL == "" {
		return nil, fmt.Errorf("no backend URL configured. Run 'wallet-cli config init' first")
	}

	if profile.Token == "" {
		return nil, fmt.Errorf("not logged in. Run 'wallet-cli auth login' first")
	}

	client := backend.NewClient(profile.BackendURL)
	client.SetTenantID(profile.TenantID)
	client.SetToken(profile.Token)
	return client, nil
}

func runCredentialsList(cmd *cobra.Command, args []string) error {
	client, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	credentials, err := client.GetCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch credentials: %w", err)
	}

	if len(credentials) == 0 {
		if jsonOutput {
			fmt.Println("[]")
		} else {
			fmt.Println("No credentials found.")
			fmt.Println("\nUse 'wallet-cli issue offer <url>' to receive credentials from an issuer.")
		}
		return nil
	}

	// Filter by type if specified
	if credType != "" {
		var filtered []*backend.Credential
		for _, c := range credentials {
			if strings.Contains(strings.ToLower(c.CredentialConfigurationID), strings.ToLower(credType)) {
				filtered = append(filtered, c)
			}
		}
		credentials = filtered
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(credentials, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	// Table format
	fmt.Printf("%-36s  %-30s  %-30s\n", "ID", "TYPE", "ISSUER")
	fmt.Println(strings.Repeat("─", 100))

	for _, cred := range credentials {
		// Truncate long values
		credID := truncate(cred.ID, 36)
		credTypeDisplay := truncate(cred.CredentialConfigurationID, 30)
		issuer := truncate(cred.CredentialIssuerIdentifier, 30)

		fmt.Printf("%-36s  %-30s  %-30s\n", credID, credTypeDisplay, issuer)
	}

	fmt.Printf("\n%d credential(s) found.\n", len(credentials))
	return nil
}

func runCredentialsShow(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	client, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cred, err := client.GetCredential(ctx, credentialID)
	if err != nil {
		return fmt.Errorf("failed to fetch credential: %w", err)
	}

	if jsonOutput || rawOutput {
		output, _ := json.MarshalIndent(cred, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	// Display credential info
	fmt.Println("Credential Details")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("ID:      %s\n", cred.ID)
	fmt.Printf("Format:  %s\n", cred.Format)
	fmt.Printf("Type:    %s\n", cred.CredentialConfigurationID)
	fmt.Printf("Issuer:  %s\n", cred.CredentialIssuerIdentifier)
	fmt.Printf("Holder:  %s\n", cred.HolderDID)

	// Try to decode and display claims from the credential
	if cred.Format == "vc+sd-jwt" || cred.Format == "jwt_vc_json" {
		fmt.Println("\nClaims:")
		fmt.Println(strings.Repeat("─", 60))
		displayJWTClaims(cred.Credential, showAll)
	} else {
		fmt.Println("\nRaw credential (use --raw for full output):")
		fmt.Println(truncate(cred.Credential, 200))
	}

	return nil
}

func runCredentialsExport(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	client, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cred, err := client.GetCredential(ctx, credentialID)
	if err != nil {
		return fmt.Errorf("failed to fetch credential: %w", err)
	}

	var output io.Writer = os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	// Write raw credential
	fmt.Fprintln(output, cred.Credential)

	if outputFile != "" {
		fmt.Fprintf(os.Stderr, "Credential exported to %s\n", outputFile)
	}

	return nil
}

func runCredentialsDelete(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	if !force {
		fmt.Printf("Are you sure you want to delete credential %s? [y/N] ", credentialID)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	client, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.DeleteCredential(ctx, credentialID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	fmt.Printf("Credential %s deleted.\n", credentialID)
	return nil
}

// displayJWTClaims extracts and displays claims from a JWT or SD-JWT credential.
func displayJWTClaims(credential string, showAll bool) {
	// For SD-JWT, the credential has format: header.payload.signature~disclosure1~disclosure2~...
	parts := strings.Split(credential, "~")
	jwtPart := parts[0]

	// Split JWT into parts
	jwtParts := strings.Split(jwtPart, ".")
	if len(jwtParts) < 2 {
		fmt.Println("  (unable to decode JWT)")
		return
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		fmt.Println("  (unable to decode payload)")
		return
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		fmt.Println("  (unable to parse claims)")
		return
	}

	// Display claims
	displayClaims(claims, "  ", showAll)

	// If SD-JWT with disclosures, show them
	if len(parts) > 1 && showAll {
		fmt.Println("\nSelective Disclosures:")
		for i, disclosure := range parts[1:] {
			if disclosure == "" {
				continue
			}
			decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
			if err != nil {
				continue
			}
			var disc []any
			if json.Unmarshal(decoded, &disc) == nil && len(disc) >= 2 {
				fmt.Printf("  [%d] %v: %v\n", i+1, disc[1], disc[2])
			}
		}
	}
}

// displayClaims recursively displays claims.
func displayClaims(claims map[string]any, indent string, showAll bool) {
	// Claims to skip unless showAll
	skipClaims := map[string]bool{
		"_sd":     true,
		"_sd_alg": true,
		"iss":     !showAll,
		"iat":     !showAll,
		"exp":     !showAll,
		"nbf":     !showAll,
		"sub":     !showAll,
		"jti":     !showAll,
		"cnf":     !showAll,
	}

	for key, value := range claims {
		if skipClaims[key] && !showAll {
			continue
		}

		switch v := value.(type) {
		case map[string]any:
			fmt.Printf("%s%s:\n", indent, key)
			displayClaims(v, indent+"  ", showAll)
		case []any:
			fmt.Printf("%s%s: [%d items]\n", indent, key, len(v))
		default:
			fmt.Printf("%s%s: %v\n", indent, key, value)
		}
	}
}

// truncate truncates a string to maxLen, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
