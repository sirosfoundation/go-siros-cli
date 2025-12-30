package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

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

	// TODO: Implement VP creation and submission
	// 1. Select matching credentials
	// 2. Apply selective disclosure based on requested fields
	// 3. Create VP token (JWT or SD-JWT presentation)
	// 4. Sign with holder's key
	// 5. Submit to verifier

	fmt.Println("\n⚠ VP creation and submission not yet fully implemented")
	fmt.Println("  Would submit to:", vpClient.GetResponseEndpoint(authReq))
	if authReq.State != "" {
		fmt.Println("  State:", authReq.State)
	}

	return nil
}
