package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/oid4vci"
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Credential issuance commands",
	Long:  `Commands for receiving verifiable credentials via OpenID4VCI.`,
}

var issueStartCmd = &cobra.Command{
	Use:   "start <issuer-url>",
	Short: "Start credential issuance from an issuer",
	Long: `Start the credential issuance process with a known issuer.

This initiates the OpenID4VCI flow with the specified issuer.
You may be redirected to a browser for authentication.`,
	Args: cobra.ExactArgs(1),
	RunE: runIssueStart,
}

var issueOfferCmd = &cobra.Command{
	Use:   "offer <credential-offer-url>",
	Short: "Handle a credential offer",
	Long: `Process a credential offer URL (e.g., from a QR code).

The URL should be in the format:
  openid-credential-offer://issuer.example.com?credential_offer=...

Or a HTTPS URL:
  https://issuer.example.com/credential-offer?credential_offer=...`,
	Args: cobra.ExactArgs(1),
	RunE: runIssueOffer,
}

var issueListIssuersCmd = &cobra.Command{
	Use:   "issuers",
	Short: "List known credential issuers",
	Long:  `Display a list of known credential issuers from the wallet backend.`,
	RunE:  runIssueListIssuers,
}

var (
	issueCredType string
	issuePin      string
	issueAccept   bool
)

func init() {
	// Start flags
	issueStartCmd.Flags().StringVar(&issueCredType, "type", "", "Credential type to request")

	// Offer flags
	issueOfferCmd.Flags().StringVar(&issuePin, "pin", "", "PIN/tx_code for pre-authorized code (if required)")
	issueOfferCmd.Flags().BoolVarP(&issueAccept, "accept", "y", false, "Accept offer without prompting")

	// Add subcommands
	issueCmd.AddCommand(issueStartCmd)
	issueCmd.AddCommand(issueOfferCmd)
	issueCmd.AddCommand(issueListIssuersCmd)
}

func runIssueStart(cmd *cobra.Command, args []string) error {
	issuerURL := args[0]

	client := oid4vci.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("Fetching issuer metadata from %s...\n", issuerURL)

	metadata, err := client.GetIssuerMetadata(ctx, issuerURL)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}

	fmt.Printf("\nIssuer: %s\n", metadata.CredentialIssuer)
	if len(metadata.Display) > 0 {
		fmt.Printf("Name: %s\n", metadata.Display[0].Name)
	}

	fmt.Printf("\nAvailable credential types:\n")
	for configID, config := range metadata.CredentialConfigurationsSupported {
		fmt.Printf("  - %s (format: %s)\n", configID, config.Format)
		if len(config.Display) > 0 {
			fmt.Printf("    %s\n", config.Display[0].Name)
		}
	}

	fmt.Println("\nTo receive credentials, use:")
	fmt.Printf("  wallet-cli issue offer <credential-offer-url>\n")
	fmt.Println("\nNote: Authorization code flow requires browser interaction,")
	fmt.Println("which is not yet supported in CLI mode. Use pre-authorized offers.")

	return nil
}

func runIssueOffer(cmd *cobra.Command, args []string) error {
	offerURL := args[0]

	// Get authenticated backend client
	backendClient, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	oidClient := oid4vci.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Parse credential offer
	fmt.Print("Parsing credential offer... ")
	offer, err := oidClient.ParseCredentialOfferURL(offerURL)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to parse credential offer: %w", err)
	}
	fmt.Println("✓")

	// 2. Fetch issuer metadata
	fmt.Print("Fetching issuer metadata... ")
	metadata, err := oidClient.GetIssuerMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	fmt.Println("✓")

	// Display offer details
	fmt.Printf("\nCredential Offer from: %s\n", offer.CredentialIssuer)
	if len(metadata.Display) > 0 {
		fmt.Printf("Issuer Name: %s\n", metadata.Display[0].Name)
	}

	fmt.Println("\nOffered credentials:")
	for _, configID := range offer.CredentialConfigurationIDs {
		config, ok := metadata.CredentialConfigurationsSupported[configID]
		if ok {
			name := configID
			if len(config.Display) > 0 && config.Display[0].Name != "" {
				name = config.Display[0].Name
			}
			fmt.Printf("  - %s (%s)\n", name, config.Format)
		} else {
			fmt.Printf("  - %s (unknown configuration)\n", configID)
		}
	}

	// Check grant type
	isPreAuthorized := offer.Grants != nil && offer.Grants.PreAuthorizedCode != nil
	if isPreAuthorized {
		fmt.Println("\nGrant type: Pre-authorized code")
		if offer.Grants.PreAuthorizedCode.TxCode != nil {
			fmt.Printf("Transaction code required: %s\n", offer.Grants.PreAuthorizedCode.TxCode.Description)
		}
	} else if offer.Grants != nil && offer.Grants.AuthorizationCode != nil {
		fmt.Println("\nGrant type: Authorization code (requires browser)")
		return fmt.Errorf("authorization code flow not yet supported in CLI. Use browser wallet or pre-authorized offers")
	}

	// Confirm with user
	if !issueAccept {
		fmt.Print("\nAccept this credential offer? [y/N] ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	if !isPreAuthorized {
		return fmt.Errorf("only pre-authorized code flow is currently supported")
	}

	// 3. Get tx_code if required
	txCode := issuePin
	if offer.Grants.PreAuthorizedCode.TxCode != nil && txCode == "" {
		fmt.Print("Enter transaction code: ")
		fmt.Scanln(&txCode)
	}

	// 4. Determine token endpoint
	tokenEndpoint := ""
	if offer.Grants.PreAuthorizedCode.AuthorizationServer != "" {
		oauthMetadata, err := oidClient.GetOAuthServerMetadata(ctx, offer.Grants.PreAuthorizedCode.AuthorizationServer)
		if err != nil {
			return fmt.Errorf("failed to fetch OAuth server metadata: %w", err)
		}
		tokenEndpoint = oauthMetadata.TokenEndpoint
	} else if len(metadata.AuthorizationServers) > 0 {
		oauthMetadata, err := oidClient.GetOAuthServerMetadata(ctx, metadata.AuthorizationServers[0])
		if err != nil {
			return fmt.Errorf("failed to fetch OAuth server metadata: %w", err)
		}
		tokenEndpoint = oauthMetadata.TokenEndpoint
	} else {
		// Try issuer as authorization server
		oauthMetadata, err := oidClient.GetOAuthServerMetadata(ctx, offer.CredentialIssuer)
		if err != nil {
			// Fallback: construct token endpoint from issuer
			tokenEndpoint = strings.TrimSuffix(offer.CredentialIssuer, "/") + "/token"
		} else {
			tokenEndpoint = oauthMetadata.TokenEndpoint
		}
	}

	// 5. Exchange pre-authorized code for access token
	fmt.Print("Exchanging pre-authorized code... ")
	tokenResp, err := oidClient.ExchangePreAuthorizedCode(ctx, tokenEndpoint, offer.Grants.PreAuthorizedCode.PreAuthorizedCode, txCode, "")
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to exchange pre-authorized code: %w", err)
	}
	fmt.Println("✓")

	// 6. Request credentials
	var receivedCredentials []*backend.Credential

	// Get keystore for proof generation if c_nonce is present
	var proofGenerator *oid4vci.ProofGenerator
	if tokenResp.CNonce != "" {
		fmt.Println("\nProof of possession required, authenticating...")
		ks, err := getUnlockedKeystoreWithTimeout(60 * time.Second)
		if err != nil {
			return fmt.Errorf("failed to unlock keystore for proof generation: %w", err)
		}
		defer ks.Lock()

		// Get the first available key
		keys, err := ks.ListKeys()
		if err != nil || len(keys) == 0 {
			return fmt.Errorf("no keys available for proof generation")
		}

		key := keys[0]
		privateKey, err := ks.GetPrivateKey(key.KeyID)
		if err != nil {
			return fmt.Errorf("failed to get private key: %w", err)
		}

		proofGenerator = oid4vci.NewProofGenerator(key.KeyID, privateKey, key.PublicKey, key.Algorithm)
	}

	for _, configID := range offer.CredentialConfigurationIDs {
		config, ok := metadata.CredentialConfigurationsSupported[configID]
		if !ok {
			fmt.Printf("Warning: Unknown credential configuration %s, skipping\n", configID)
			continue
		}

		fmt.Printf("Requesting %s... ", configID)

		// Build credential request
		credReq := &oid4vci.CredentialRequest{
			CredentialConfigurationID: configID,
		}

		// Add proof if required (c_nonce indicates proof is needed)
		if proofGenerator != nil && tokenResp.CNonce != "" {
			proof, err := proofGenerator.CreateProof(offer.CredentialIssuer, tokenResp.CNonce, "")
			if err != nil {
				fmt.Println("✗")
				fmt.Printf("  Error generating proof: %v\n", err)
				continue
			}
			credReq.Proof = proof
		}

		credResp, err := oidClient.RequestCredential(ctx, metadata.CredentialEndpoint, tokenResp.AccessToken, credReq)
		if err != nil {
			fmt.Println("✗")
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		fmt.Println("✓")

		// Handle deferred issuance
		if credResp.TransactionID != "" {
			fmt.Printf("  Credential issuance deferred (transaction_id: %s)\n", credResp.TransactionID)
			// TODO: Implement deferred credential polling
			continue
		}

		// Extract credential
		var credentialStr string
		switch cred := credResp.Credential.(type) {
		case string:
			credentialStr = cred
		case map[string]any:
			credBytes, _ := json.Marshal(cred)
			credentialStr = string(credBytes)
		default:
			fmt.Printf("  Warning: Unexpected credential format\n")
			continue
		}

		// Generate credential identifier
		credID := generateCredentialID()

		receivedCredentials = append(receivedCredentials, &backend.Credential{
			ID:                         credID,
			Credential:                 credentialStr,
			Format:                     config.Format,
			CredentialConfigurationID:  configID,
			CredentialIssuerIdentifier: offer.CredentialIssuer,
		})
	}

	if len(receivedCredentials) == 0 {
		return fmt.Errorf("no credentials were received")
	}

	// 7. Store credentials
	fmt.Print("\nStoring credentials... ")
	if err := backendClient.StoreCredentials(ctx, receivedCredentials); err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to store credentials: %w", err)
	}
	fmt.Println("✓")

	fmt.Printf("\n✅ Successfully received %d credential(s)!\n", len(receivedCredentials))
	fmt.Println("\nUse 'wallet-cli credentials list' to view your credentials.")

	return nil
}

func runIssueListIssuers(cmd *cobra.Command, args []string) error {
	client, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	issuers, err := client.GetIssuers(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch issuers: %w", err)
	}

	if len(issuers) == 0 {
		fmt.Println("No known issuers configured.")
		return nil
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(issuers, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("%-5s  %-60s  %-8s\n", "ID", "ISSUER", "VISIBLE")
	fmt.Println(strings.Repeat("─", 80))

	for _, issuer := range issuers {
		visible := "No"
		if issuer.Visible {
			visible = "Yes"
		}
		fmt.Printf("%-5d  %-60s  %-8s\n", issuer.ID, truncate(issuer.CredentialIssuerIdentifier, 60), visible)
	}

	return nil
}

// generateCredentialID generates a unique credential identifier.
func generateCredentialID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
