//go:build sdk

// Package sdk provides integration with the go-wallet-backend native SDK.
package sdk

import (
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
	native "github.com/sirosfoundation/go-wallet-backend/sdk/native"
)

// BuildClient creates a fully configured native.Client using go-siros-cli components.
// This is the primary entry point for CLI integration with the SDK.
func BuildClient(
	config *native.Config,
	backendClient *backend.Client,
	fido2Provider fido2.Provider,
	keystoreManager *keystore.DefaultManager,
) *native.Client {
	client := native.NewClient(config)

	// Set up all adapters
	client.SetBackendConnection(NewBackendAdapter(backendClient))
	client.SetAuthProvider(NewAuthProviderAdapter(fido2Provider))
	client.SetKeystore(NewKeystoreAdapter(keystoreManager))

	return client
}

// QuickClient creates a native.Client with minimal configuration.
// It creates the backend.Client from the URL and uses the provided
// FIDO2 provider and a new keystore manager. Uses default tenant ID.
func QuickClient(backendURL string, fido2Provider fido2.Provider) (*native.Client, error) {
	return QuickClientWithTenant(backendURL, "", fido2Provider)
}

// QuickClientWithTenant creates a native.Client with tenant support.
// If tenantID is empty, uses backend.DefaultTenantID.
func QuickClientWithTenant(backendURL string, tenantID string, fido2Provider fido2.Provider) (*native.Client, error) {
	config := &native.Config{
		BackendURL: backendURL,
		Platform:   "cli",
	}

	backendClient := backend.NewClient(backendURL)
	backendClient.SetTenantID(tenantID)
	keystoreManager := keystore.NewManager()

	return BuildClient(config, backendClient, fido2Provider, keystoreManager), nil
}
