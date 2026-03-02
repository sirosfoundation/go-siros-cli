package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
	"github.com/sirosfoundation/go-siros-cli/internal/daemon"
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
)

// getKeystoreInterface returns a KeystoreInterface that can be used for signing.
// It first tries to connect to the daemon (if running and unlocked), then falls back
// to direct FIDO2 PRF authentication.
func getKeystoreInterface(ctx context.Context) (daemon.KeystoreInterface, error) {
	// Try daemon first
	if daemon.IsDaemonRunning() {
		client, err := daemon.ConnectToDaemon()
		if err == nil {
			// Check if daemon is unlocked
			status, err := client.Status(ctx)
			if err == nil && status.Unlocked {
				fmt.Println("Using daemon keystore (already unlocked)")
				return daemon.WrapDaemonAsKeystore(client), nil
			}
			// Daemon is running but locked - close this connection
			client.Close()
		}
	}

	// Fall back to direct FIDO2 authentication
	ks, err := getUnlockedKeystore(ctx)
	if err != nil {
		return nil, err
	}

	// Wrap the keystore manager as KeystoreInterface
	return &directKeystore{manager: ks.(*keystore.DefaultManager)}, nil
}

// directKeystore wraps a keystore.DefaultManager to implement daemon.KeystoreInterface.
type directKeystore struct {
	manager *keystore.DefaultManager
}

func (d *directKeystore) IsUnlocked() bool {
	return !d.manager.IsLocked()
}

func (d *directKeystore) ListKeys() ([]keystore.KeyInfo, error) {
	return d.manager.ListKeys()
}

func (d *directKeystore) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	return d.manager.GetPrivateKey(keyID)
}

func (d *directKeystore) SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error) {
	return d.manager.SignJWT(ctx, keyID, claims)
}

func (d *directKeystore) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	return d.manager.Sign(ctx, keyID, data)
}

func (d *directKeystore) Lock() error {
	return d.manager.Lock()
}

// getUnlockedKeystore performs FIDO2 authentication with PRF and returns an unlocked keystore.
// This is used when the daemon is not running or not unlocked.
func getUnlockedKeystore(ctx context.Context) (keystore.Manager, error) {
	cfg := config.Get()
	profile := cfg.GetProfile()

	if profile.BackendURL == "" {
		return nil, fmt.Errorf("no backend URL configured")
	}

	if profile.Token == "" {
		return nil, fmt.Errorf("not logged in")
	}

	if profile.CredentialID == "" {
		return nil, fmt.Errorf("no credential ID stored - login required")
	}

	// Get backend client
	client := backend.NewClient(profile.BackendURL)
	client.SetTenantID(profile.TenantID)
	client.SetToken(profile.Token)

	// Get account info which includes privateData (encrypted keystore)
	fmt.Print("Fetching keystore data... ")
	accountInfo, err := client.GetAccountInfo(ctx)
	if err != nil {
		fmt.Println("✗")
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}
	fmt.Println("✓")

	// Extract private data
	var privateDataBytes []byte
	if pdMap, ok := accountInfo.PrivateData.(map[string]interface{}); ok {
		if b64u, ok := pdMap["$b64u"].(string); ok {
			privateDataBytes, _ = base64.RawURLEncoding.DecodeString(b64u)
		}
	}

	if len(privateDataBytes) == 0 {
		return nil, fmt.Errorf("no keystore data found - register with PRF-enabled authenticator required")
	}

	// Get PRF key info from the encrypted container
	ks := keystore.NewManager()
	prfKeyInfos, err := ks.GetPRFKeyInfos(privateDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keystore: %w", err)
	}

	if len(prfKeyInfos) == 0 {
		return nil, fmt.Errorf("no PRF keys configured in keystore")
	}

	// Find matching PRF key for our stored credential ID
	storedCredID, err := base64.RawURLEncoding.DecodeString(profile.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("invalid credential ID: %w", err)
	}

	var matchingPRFKey *keystore.PRFKeyInfo
	for i, pkInfo := range prfKeyInfos {
		if bytesEqual(pkInfo.CredentialID, storedCredID) {
			matchingPRFKey = &prfKeyInfos[i]
			break
		}
	}

	if matchingPRFKey == nil {
		return nil, fmt.Errorf("no matching PRF key for stored credential")
	}

	// Generate a random challenge for the assertion
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get RP ID
	rpID := profile.WebAuthnRpID
	if rpID == "" {
		rpID = "siros.org" // Default fallback
	}

	// Perform FIDO2 authentication with PRF
	fmt.Println("\n[Touch your security key to unlock keystore...]")
	provider := getFIDO2Provider()

	// Check if device requires PIN
	var pin string
	if deviceRequiresPIN() {
		var err error
		pin, err = promptForPIN("Enter your FIDO2 device PIN: ")
		if err != nil {
			return nil, fmt.Errorf("failed to get PIN: %w", err)
		}
	}

	authResult, err := provider.Authenticate(ctx, &fido2.AuthenticateOptions{
		RPID:             rpID,
		Challenge:        challenge,
		AllowCredentials: []fido2.CredentialID{matchingPRFKey.CredentialID},
		UserVerification: fido2.UVPreferred,
		PRFSalt1:         matchingPRFKey.PRFSalt,
		PIN:              pin,
	})
	if err != nil {
		return nil, fmt.Errorf("FIDO2 authentication failed: %w", err)
	}

	if authResult.PRFOutput == nil {
		return nil, fmt.Errorf("PRF output not available from authenticator")
	}

	fmt.Print("Unlocking keystore... ")
	err = ks.Unlock(ctx, authResult.CredentialID, authResult.PRFOutput.First, privateDataBytes)
	if err != nil {
		fmt.Println("✗")
		return nil, fmt.Errorf("failed to unlock keystore: %w", err)
	}
	fmt.Println("✓")

	return ks, nil
}

// getUnlockedKeystoreWithTimeout wraps getUnlockedKeystore with a timeout.
func getUnlockedKeystoreWithTimeout(timeout time.Duration) (keystore.Manager, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return getUnlockedKeystore(ctx)
}

// getKeystoreInterfaceWithTimeout returns a KeystoreInterface (daemon or direct) with timeout.
func getKeystoreInterfaceWithTimeout(timeout time.Duration) (daemon.KeystoreInterface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return getKeystoreInterface(ctx)
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
