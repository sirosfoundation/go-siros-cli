package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
	"github.com/sirosfoundation/go-siros-cli/pkg/pinentry"
)

// taggedBinary creates a tagged binary object {"$b64u": "base64url-encoded-data"}
// This format is used by the wallet-backend to represent binary data in JSON.
func taggedBinary(data []byte) map[string]string {
	return map[string]string{"$b64u": base64.RawURLEncoding.EncodeToString(data)}
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication commands",
	Long:  `Commands for WebAuthn authentication including registration and login.`,
}

var authRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new wallet with WebAuthn",
	Long: `Register a new wallet identity using a FIDO2 hardware authenticator (e.g., YubiKey).

This creates a new user account on the wallet backend and registers your
hardware authenticator for future logins.

Requirements:
  - A FIDO2-compatible hardware security key (YubiKey 5, SoloKey, etc.)
  - The libfido2 library installed on your system
  - Use 'wallet-cli device check' to verify compatibility`,
	RunE: runAuthRegister,
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login with an existing WebAuthn credential",
	Long: `Authenticate with the wallet backend using your registered FIDO2 credential.

This establishes a session that allows you to access your credentials and
perform wallet operations.

You will be prompted to touch your hardware security key to authenticate.`,
	RunE: runAuthLogin,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check authentication status",
	Long:  `Check if you are currently logged in and display session information.`,
	RunE:  runAuthStatus,
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout and clear session",
	Long:  `Clear the current session and remove cached credentials.`,
	RunE:  runAuthLogout,
}

var (
	displayName string
	useBrowser  bool
	pinMethod   string
	pinProgram  string
	pinValue    string
)

func init() {
	// Register command flags
	authRegisterCmd.Flags().StringVar(&displayName, "display-name", "", "Display name for the wallet")

	// PIN entry flags for both register and login
	for _, cmd := range []*cobra.Command{authRegisterCmd, authLoginCmd} {
		cmd.Flags().StringVar(&pinMethod, "pin-method", "", "PIN entry method: pinentry, terminal, stdin, or arg (default: pinentry)")
		cmd.Flags().StringVar(&pinProgram, "pinentry-program", "", "Path to pinentry program")
		cmd.Flags().StringVar(&pinValue, "pin", "", "FIDO2 PIN (insecure, use for scripting only)")
	}

	// Browser fallback flags - hidden because they only work with localhost backends
	// due to WebAuthn RP ID origin restrictions. Kept for development/testing.
	authRegisterCmd.Flags().BoolVar(&useBrowser, "browser", false, "Use browser for WebAuthn (development only)")
	authRegisterCmd.Flags().MarkHidden("browser")
	authLoginCmd.Flags().BoolVar(&useBrowser, "browser", false, "Use browser for WebAuthn (development only)")
	authLoginCmd.Flags().MarkHidden("browser")

	// Add subcommands
	authCmd.AddCommand(authRegisterCmd)
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authLogoutCmd)
}

// getFIDO2Provider returns the appropriate FIDO2 provider based on flags and availability.
func getFIDO2Provider() fido2.Provider {
	if useBrowser {
		return fido2.NewBrowserProvider()
	}

	// Try native first, fall back to browser
	native, err := fido2.NewNativeProvider()
	if err != nil {
		return fido2.NewBrowserProvider()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	devices, err := native.ListDevices(ctx)
	if err == nil && len(devices) > 0 {
		return native
	}

	// Fall back to browser
	return fido2.NewBrowserProvider()
}

func runAuthRegister(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	profile := cfg.GetProfile()

	if profile.BackendURL == "" {
		return fmt.Errorf("no backend URL configured. Run 'siros config init' first")
	}

	fmt.Printf("Registering new wallet on %s...\n", profile.BackendURL)

	// Use display name from flag or generate one
	name := displayName
	if name == "" {
		hostname, _ := os.Hostname()
		name = fmt.Sprintf("CLI Wallet - %s", hostname)
	}
	fmt.Printf("Display name: %s\n", name)

	// Create backend client
	client := backend.NewClient(profile.BackendURL)
	client.SetTenantID(profile.TenantID)
	ctx := context.Background()

	// 1. Start registration
	fmt.Print("\nStarting registration... ")
	startResp, err := client.StartRegistration(ctx, name)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to start registration: %w", err)
	}
	fmt.Println("✓")

	// 2. Extract WebAuthn options from response
	// The options are nested under createOptions.publicKey
	createOptions := startResp.CreateOptions
	publicKey, ok := createOptions["publicKey"].(map[string]interface{})
	if !ok {
		// Fallback if publicKey is not nested
		publicKey = createOptions
	}

	// Parse challenge (handle tagged binary format {"$b64u": "..."})
	challenge, err := extractTaggedBinary(publicKey, "challenge")
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Parse RP info
	rp, _ := publicKey["rp"].(map[string]interface{})
	rpID, _ := rp["id"].(string)
	rpName, _ := rp["name"].(string)
	if rpID == "" {
		rpID = "siros.org" // Default
	}

	// Parse user info (handle tagged binary format for id)
	user, _ := publicKey["user"].(map[string]interface{})
	userID, err := extractTaggedBinary(user, "id")
	if err != nil {
		return fmt.Errorf("failed to decode user id: %w", err)
	}
	userName, _ := user["name"].(string)
	if userName == "" {
		userName = name
	}

	// 3. Perform WebAuthn ceremony
	provider := getFIDO2Provider()

	// Check if device requires PIN and prompt if needed
	var pin string
	if !useBrowser && deviceRequiresPIN() {
		pin, err = promptForPIN("Enter your FIDO2 device PIN: ")
		if err != nil {
			return fmt.Errorf("failed to get PIN: %w", err)
		}
	}

	// Generate PRF salt for keystore initialization
	prfSalt := make([]byte, 32)
	if _, err := rand.Read(prfSalt); err != nil {
		return fmt.Errorf("failed to generate PRF salt: %w", err)
	}

	fmt.Println("\n[Touch your security key to register...]")

	regResult, err := provider.Register(ctx, &fido2.RegisterOptions{
		RPID:             rpID,
		RPName:           rpName,
		UserID:           userID,
		UserName:         userName,
		UserDisplayName:  name,
		Challenge:        challenge,
		ResidentKey:      true,
		UserVerification: fido2.UVPreferred,
		EnablePRF:        true,
		PRFSalt:          prfSalt,
		PIN:              pin,
	})
	if err != nil {
		return fmt.Errorf("WebAuthn registration failed: %w", err)
	}
	fmt.Println("✓ Security key registered")

	// 4. Initialize the keystore using PRF
	// After registration, we need to do an assertion with PRF to get the PRF output
	var privateData []byte
	if regResult.PRFSupported {
		fmt.Print("Initializing encrypted keystore... ")

		// Generate a dummy challenge for the PRF assertion
		prfChallenge := make([]byte, 32)
		if _, err := rand.Read(prfChallenge); err != nil {
			return fmt.Errorf("failed to generate PRF challenge: %w", err)
		}

		fmt.Print("[Touch your security key again...] ")
		prfResult, err := provider.Authenticate(ctx, &fido2.AuthenticateOptions{
			RPID:             rpID,
			Challenge:        prfChallenge,
			AllowCredentials: []fido2.CredentialID{regResult.CredentialID},
			UserVerification: fido2.UVPreferred,
			PRFSalt1:         prfSalt,
			PIN:              pin,
		})
		if err != nil {
			fmt.Printf("\n⚠ Warning: Failed to get PRF output: %v\n", err)
			fmt.Println("  Continuing without keystore encryption...")
			privateData = []byte("{}")
		} else if prfResult.PRFOutput == nil || len(prfResult.PRFOutput.First) == 0 {
			fmt.Println("\n⚠ Warning: Device did not return PRF output")
			fmt.Println("  Continuing without keystore encryption...")
			privateData = []byte("{}")
		} else {
			// Initialize the keystore with PRF output
			initResult, err := keystore.InitPRF(
				regResult.CredentialID,
				prfResult.PRFOutput.First,
				prfSalt,
				[]string{"usb"},
			)
			if err != nil {
				fmt.Printf("\n⚠ Warning: Failed to initialize keystore: %v\n", err)
				fmt.Println("  Continuing without keystore encryption...")
				privateData = []byte("{}")
			} else {
				privateData = initResult.EncryptedContainer
				fmt.Println("✓")
			}
		}
	} else {
		fmt.Println("Note: Device does not support PRF extension, keystore will not be encrypted")
		privateData = []byte("{}")
	}

	// 5. Finish registration with backend
	// Use tagged binary format {"$b64u": "..."} expected by wallet-backend
	credential := map[string]interface{}{
		"id":    base64.RawURLEncoding.EncodeToString(regResult.CredentialID),
		"rawId": taggedBinary(regResult.CredentialID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"attestationObject": taggedBinary(regResult.AttestationObject),
			"clientDataJSON":    taggedBinary(regResult.ClientDataJSON),
			"transports":        []string{"usb"}, // FIDO2 hardware key
		},
		"authenticatorAttachment": "cross-platform",
		"clientExtensionResults":  map[string]interface{}{},
	}

	// Send privateData as tagged binary
	privateDataTagged := taggedBinary(privateData)

	if debug {
		reqBody := &backend.RegistrationFinishRequest{
			ChallengeID: startResp.ChallengeID,
			Credential:  credential,
			DisplayName: name,
			PrivateData: privateDataTagged,
		}
		jsonBody, _ := json.MarshalIndent(reqBody, "", "  ")
		fmt.Fprintf(os.Stderr, "\nDEBUG: Request body:\n%s\n", string(jsonBody))
	}

	finishResp, err := client.FinishRegistration(ctx, &backend.RegistrationFinishRequest{
		ChallengeID: startResp.ChallengeID,
		Credential:  credential,
		DisplayName: name,
		PrivateData: privateDataTagged,
	})
	if err != nil {
		return fmt.Errorf("failed to complete registration: %w", err)
	}

	// 6. Save profile data
	profile.Token = finishResp.Token
	profile.WebAuthnRpID = finishResp.WebauthnRpId
	profile.UserID = finishResp.UUID
	profile.DisplayName = finishResp.DisplayName
	profile.CredentialID = base64.RawURLEncoding.EncodeToString(regResult.CredentialID)

	if err := saveProfileToFile(cfg); err != nil {
		fmt.Printf("Warning: failed to save profile: %v\n", err)
	}

	fmt.Printf("\n✓ Registration complete!\n")
	fmt.Printf("  User ID: %s\n", finishResp.UUID)
	fmt.Printf("  Display name: %s\n", finishResp.DisplayName)
	if regResult.PRFSupported {
		fmt.Printf("  PRF extension: supported\n")
		if len(privateData) > 2 { // More than just "{}"
			fmt.Printf("  Keystore: initialized with PRF encryption\n")
		}
	}

	return nil
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	profile := cfg.GetProfile()

	if profile.BackendURL == "" {
		return fmt.Errorf("no backend URL configured. Run 'siros config init' first")
	}

	fmt.Printf("Logging in to %s...\n", profile.BackendURL)

	// Create backend client
	client := backend.NewClient(profile.BackendURL)
	client.SetTenantID(profile.TenantID)
	ctx := context.Background()

	// 1. Start login
	fmt.Print("\nStarting login... ")
	startResp, err := client.StartLogin(ctx)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to start login: %w", err)
	}
	fmt.Println("✓")

	// 2. Extract WebAuthn options
	// The options may be nested under getOptions.publicKey
	getOptions := startResp.GetOptions
	publicKey, ok := getOptions["publicKey"].(map[string]interface{})
	if !ok {
		// Fallback if publicKey is not nested
		publicKey = getOptions
	}

	// Parse challenge (handle tagged binary format)
	challenge, err := extractTaggedBinary(publicKey, "challenge")
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Parse RP ID
	rpID, _ := publicKey["rpId"].(string)
	if rpID == "" {
		rpID = profile.WebAuthnRpID
	}
	if rpID == "" {
		rpID = "siros.org"
	}

	// Parse allowed credentials (handle tagged binary format for id)
	var allowCredentials []fido2.CredentialID
	if allowCreds, ok := publicKey["allowCredentials"].([]interface{}); ok {
		for _, cred := range allowCreds {
			if credMap, ok := cred.(map[string]interface{}); ok {
				credID, err := extractTaggedBinary(credMap, "id")
				if err == nil {
					allowCredentials = append(allowCredentials, credID)
				}
			}
		}
	}

	// Generate PRF salt
	prfSalt := make([]byte, 32)
	if _, err := rand.Read(prfSalt); err != nil {
		return fmt.Errorf("failed to generate PRF salt: %w", err)
	}

	// 3. Perform WebAuthn authentication
	provider := getFIDO2Provider()

	// Check if device requires PIN and prompt if needed
	var pin string
	if !useBrowser && deviceRequiresPIN() {
		pin, err = promptForPIN("Enter your FIDO2 device PIN: ")
		if err != nil {
			return fmt.Errorf("failed to get PIN: %w", err)
		}
	}

	fmt.Println("\n[Touch your security key to login...]")

	authResult, err := provider.Authenticate(ctx, &fido2.AuthenticateOptions{
		RPID:             rpID,
		Challenge:        challenge,
		AllowCredentials: allowCredentials,
		UserVerification: fido2.UVPreferred,
		PRFSalt1:         prfSalt,
		PIN:              pin,
	})
	if err != nil {
		return fmt.Errorf("WebAuthn authentication failed: %w", err)
	}
	fmt.Println("✓ Authentication successful")

	// 4. Finish login with backend
	// Use tagged binary format {"$b64u": "..."} expected by wallet-backend
	credential := map[string]interface{}{
		"id":    base64.RawURLEncoding.EncodeToString(authResult.CredentialID),
		"rawId": taggedBinary(authResult.CredentialID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"authenticatorData": taggedBinary(authResult.AuthData),
			"signature":         taggedBinary(authResult.Signature),
			"clientDataJSON":    taggedBinary(authResult.ClientDataJSON),
		},
		"authenticatorAttachment": "cross-platform",
		"clientExtensionResults":  map[string]interface{}{},
	}
	if authResult.UserHandle != nil {
		credential["response"].(map[string]interface{})["userHandle"] = taggedBinary(authResult.UserHandle)
	}

	finishResp, err := client.FinishLogin(ctx, &backend.LoginFinishRequest{
		ChallengeID: startResp.ChallengeID,
		Credential:  credential,
	})
	if err != nil {
		return fmt.Errorf("failed to complete login: %w", err)
	}

	// 5. Save session
	profile.Token = finishResp.Token
	profile.WebAuthnRpID = finishResp.WebauthnRpId
	profile.UserID = finishResp.UUID
	profile.DisplayName = finishResp.DisplayName
	profile.CredentialID = base64.RawURLEncoding.EncodeToString(authResult.CredentialID)

	if err := saveProfileToFile(cfg); err != nil {
		fmt.Printf("Warning: failed to save profile: %v\n", err)
	}

	// 6. If we got PRF output, try to unlock the keystore
	// Handle privateData as tagged binary {"$b64u": "..."}
	var privateDataBytes []byte
	if pdMap, ok := finishResp.PrivateData.(map[string]interface{}); ok {
		if b64u, ok := pdMap["$b64u"].(string); ok {
			privateDataBytes, _ = base64.RawURLEncoding.DecodeString(b64u)
		}
	}
	if authResult.PRFOutput != nil && len(privateDataBytes) > 0 {
		fmt.Print("\nUnlocking keystore... ")
		ks := keystore.NewManager()
		err := ks.Unlock(ctx, authResult.CredentialID, authResult.PRFOutput.First, privateDataBytes)
		if err != nil {
			fmt.Printf("✗ (%v)\n", err)
		} else {
			fmt.Println("✓")
			keys, _ := ks.ListKeys()
			fmt.Printf("  %d key(s) available\n", len(keys))
		}
	}

	fmt.Printf("\n✓ Login complete!\n")
	fmt.Printf("  User ID: %s\n", finishResp.UUID)
	fmt.Printf("  Display name: %s\n", finishResp.DisplayName)

	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	profile := cfg.GetProfile()

	fmt.Printf("Profile: %s\n", cfg.ActiveProfile)
	fmt.Printf("Backend: %s\n", profile.BackendURL)

	if profile.Token == "" {
		fmt.Println("\nStatus: Not logged in")
		return nil
	}

	// Check if token is valid by calling backend
	client := backend.NewClient(profile.BackendURL)
	client.SetTenantID(profile.TenantID)
	client.SetToken(profile.Token)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		fmt.Printf("\nStatus: Token invalid or expired\n")
		fmt.Printf("Error: %v\n", err)
		return nil
	}

	fmt.Printf("\nStatus: Logged in\n")
	fmt.Printf("  Backend: %s\n", status.Service)
	fmt.Printf("  User ID: %s\n", profile.UserID)
	fmt.Printf("  Display name: %s\n", profile.DisplayName)

	return nil
}

func runAuthLogout(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	profile := cfg.GetProfile()

	fmt.Printf("Logging out from profile '%s'...\n", cfg.ActiveProfile)

	// Clear session data
	profile.Token = ""

	if err := saveProfileToFile(cfg); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	fmt.Println("✓ Logged out")
	return nil
}

// saveProfileToFile saves the current config to the profile file.
func saveProfileToFile(cfg *config.Config) error {
	profile := cfg.GetProfile()
	profile.Name = cfg.ActiveProfile
	return config.SaveProfile(profile)
}

// extractTaggedBinary extracts a binary value from a map, handling the tagged format {"$b64u": "..."}
func extractTaggedBinary(m map[string]interface{}, key string) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("map is nil")
	}

	val, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}

	// Handle tagged binary format {"$b64u": "..."}
	if tagged, ok := val.(map[string]interface{}); ok {
		if b64u, ok := tagged["$b64u"].(string); ok {
			return base64.RawURLEncoding.DecodeString(b64u)
		}
	}

	// Handle plain base64url string
	if str, ok := val.(string); ok {
		return base64.RawURLEncoding.DecodeString(str)
	}

	// Handle []byte directly
	if bytes, ok := val.([]byte); ok {
		return bytes, nil
	}

	return nil, fmt.Errorf("unsupported value type for key %q: %T", key, val)
}

// getPinentryConfig builds a pinentry configuration from flags and config.
func getPinentryConfig(description string) *pinentry.Config {
	cfg := config.Get()

	pcfg := pinentry.DefaultConfig()
	pcfg.Description = description

	// Determine PIN method: command-line flag > config > default
	method := pinMethod
	if method == "" && cfg != nil {
		method = cfg.Global.Auth.PinMethod
	}
	if method == "" {
		method = "pinentry"
	}

	switch method {
	case "pinentry":
		pcfg.Method = pinentry.MethodPinentry
	case "terminal":
		pcfg.Method = pinentry.MethodTerminal
	case "stdin":
		pcfg.Method = pinentry.MethodStdin
	case "arg":
		pcfg.Method = pinentry.MethodArg
		pcfg.PIN = pinValue
	default:
		pcfg.Method = pinentry.MethodPinentry
	}

	// Pinentry program: command-line flag > config > auto-detect
	program := pinProgram
	if program == "" && cfg != nil {
		program = cfg.Global.Auth.PinentryProgram
	}
	if program != "" {
		pcfg.Program = program
	}

	return pcfg
}

// promptForPIN prompts the user to enter their FIDO2 device PIN.
// It uses the configured pinentry method (pinentry program, terminal, stdin, or arg).
func promptForPIN(description string) (string, error) {
	pcfg := getPinentryConfig(description)
	return pinentry.GetPIN(pcfg)
}

// deviceRequiresPIN checks if the connected FIDO2 device requires a PIN.
func deviceRequiresPIN() bool {
	provider, err := fido2.NewNativeProvider()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devices, err := provider.ListDevices(ctx)
	if err != nil {
		return false
	}

	// Check if any FIDO2 device has a PIN set
	for _, dev := range devices {
		if dev.IsFIDO2 && dev.HasPIN {
			return true
		}
	}
	return false
}
