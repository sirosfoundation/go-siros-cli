package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/pkg/oid4vp"
)

var presentCmd = &cobra.Command{
	Use:   "present <authorization-request-url>",
	Short: "Present credentials to a verifier",
	Long: `Handle an OpenID4VP authorization request and present credentials.

The URL can be in several formats:
  openid4vp://authorize?request_uri=...
  https://verifier.example.com/authorize?request_uri=...

The command will:
1. Parse the authorization request
2. Find matching credentials in your wallet
3. Ask for approval (unless --auto-approve is used)
4. Create and submit the presentation`,
	Args: cobra.ExactArgs(1),
	RunE: runPresent,
}

var (
	autoApprove  bool
	selectCredID string
)

func init() {
	presentCmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "Automatically approve without prompting")
	presentCmd.Flags().StringVar(&selectCredID, "credential", "", "Specific credential ID to present")
}

func runPresent(cmd *cobra.Command, args []string) error {
	requestURL := args[0]
	ctx := context.Background()

	// Get authenticated backend client
	backendClient, err := getAuthenticatedClient()
	if err != nil {
		return err
	}

	// Create OID4VP client
	vpClient := oid4vp.NewClient(nil)

	// Parse the authorization request URL
	fmt.Println("Processing authorization request...")
	authReq, err := vpClient.ParseAuthorizationRequestURL(requestURL)
	if err != nil {
		return fmt.Errorf("failed to parse authorization request: %w", err)
	}

	// Resolve any URIs (request_uri, presentation_definition_uri, etc.)
	authReq, err = vpClient.ResolveAuthorizationRequest(authReq)
	if err != nil {
		return fmt.Errorf("failed to resolve authorization request: %w", err)
	}

	// Validate the request
	if err := vpClient.ValidateAuthorizationRequest(authReq); err != nil {
		return fmt.Errorf("invalid authorization request: %w", err)
	}

	// Get verifier information
	verifierDomain := vpClient.GetVerifierDomain(authReq)
	fmt.Printf("Verifier: %s\n", verifierDomain)

	if authReq.PresentationDefinition == nil {
		return fmt.Errorf("no presentation definition in request (DCQL not yet supported)")
	}

	// Display what's being requested
	fmt.Printf("\nPresentation Request: %s\n", authReq.PresentationDefinition.Name)
	if authReq.PresentationDefinition.Purpose != "" {
		fmt.Printf("Purpose: %s\n", authReq.PresentationDefinition.Purpose)
	}

	fmt.Println("\nRequested credentials:")
	for _, descriptor := range authReq.PresentationDefinition.InputDescriptors {
		fmt.Printf("  • %s", descriptor.ID)
		if descriptor.Name != "" {
			fmt.Printf(" (%s)", descriptor.Name)
		}
		fmt.Println()

		if descriptor.Purpose != "" {
			fmt.Printf("    Purpose: %s\n", descriptor.Purpose)
		}

		if descriptor.Constraints != nil && len(descriptor.Constraints.Fields) > 0 {
			fmt.Println("    Requested fields:")
			for _, field := range descriptor.Constraints.Fields {
				name := field.Name
				if name == "" && len(field.Path) > 0 {
					parts := strings.Split(field.Path[0], ".")
					name = parts[len(parts)-1]
				}
				fmt.Printf("      - %s", name)
				if field.IntentToRetain {
					fmt.Print(" (will be retained)")
				}
				fmt.Println()
			}
		}
	}
	fmt.Println()

	// Fetch credentials from backend to find matches
	credentials, err := backendClient.GetCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch credentials: %w", err)
	}

	if len(credentials) == 0 {
		return fmt.Errorf("no credentials in wallet. Issue some credentials first")
	}

	// TODO: Implement proper credential matching against presentation definition
	// For now, list available credentials
	fmt.Println("Available credentials:")
	for i, cred := range credentials {
		fmt.Printf("  [%d] %s (format: %s)\n", i+1, cred.ID, cred.Format)
	}

	// Prompt for approval
	if !autoApprove {
		fmt.Println("\nDisclose the requested information?")
		fmt.Print("[a]pprove / [d]eny / [s]elect credential? ")

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		switch input {
		case "a", "approve", "y", "yes":
			// Continue
		case "s", "select":
			fmt.Print("Enter credential number: ")
			// TODO: Handle credential selection
			return fmt.Errorf("credential selection not yet fully implemented")
		default:
			fmt.Println("✗ Presentation denied")
			return nil
		}
	}

	// Get an unlocked keystore for signing
	fmt.Println("\nPreparing to sign presentation...")
	ks, err := getUnlockedKeystoreWithTimeout(60 * time.Second)
	if err != nil {
		return fmt.Errorf("failed to unlock keystore: %w", err)
	}
	defer ks.Lock()

	// Get the first available key
	keys, err := ks.ListKeys()
	if err != nil || len(keys) == 0 {
		return fmt.Errorf("no keys available for signing")
	}

	key := keys[0]
	privateKey, err := ks.GetPrivateKey(key.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}

	// Create VP generator
	vpGenerator := oid4vp.NewVPGenerator(
		key.KeyID,
		privateKey,
		key.PublicKey,
		key.Algorithm,
		key.DID,
	)

	// For now, use the first credential
	// TODO: Implement proper credential matching against presentation definition
	selectedCred := credentials[0]

	// Determine if it's an SD-JWT (contains ~) or regular JWT
	var vpToken string
	isSDJWT := strings.Contains(selectedCred.Credential, "~")

	responseEndpoint := vpClient.GetResponseEndpoint(authReq)

	if isSDJWT {
		fmt.Print("Creating SD-JWT presentation... ")
		vpToken, err = vpGenerator.CreateSDJWTPresentation(
			selectedCred.Credential,
			authReq.Nonce,
			authReq.ClientID,
		)
	} else {
		fmt.Print("Creating VP token... ")
		vpToken, err = vpGenerator.CreateVPToken(
			[]string{selectedCred.Credential},
			authReq.Nonce,
			authReq.ClientID,
		)
	}

	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to create presentation: %w", err)
	}
	fmt.Println("✓")

	// Build presentation submission
	matches := []oid4vp.CredentialMatch{
		{
			DescriptorID: authReq.PresentationDefinition.InputDescriptors[0].ID,
			CredentialID: selectedCred.ID,
			Format:       selectedCred.Format,
		},
	}
	presentationSubmission := vpClient.BuildPresentationSubmission(
		authReq.PresentationDefinition.ID,
		matches,
	)

	// Submit to verifier
	fmt.Print("Submitting presentation to verifier... ")
	result, err := vpClient.SubmitAuthorizationResponse(
		responseEndpoint,
		vpToken,
		presentationSubmission,
		authReq.State,
	)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to submit presentation: %w", err)
	}
	fmt.Println("✓")

	fmt.Println("\n✅ Presentation submitted successfully!")
	if result != nil && result.RedirectURI != "" {
		fmt.Printf("Redirect URI: %s\n", result.RedirectURI)
	}

	return nil
}
