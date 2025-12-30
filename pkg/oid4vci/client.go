// Package oid4vci implements the OpenID for Verifiable Credential Issuance (OID4VCI) protocol.
// See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client handles OpenID4VCI protocol operations.
type Client struct {
	httpClient *http.Client
}

// NewClient creates a new OID4VCI client.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CredentialOffer represents an OpenID4VCI credential offer.
type CredentialOffer struct {
	CredentialIssuer           string                 `json:"credential_issuer"`
	CredentialConfigurationIDs []string               `json:"credential_configuration_ids"`
	Grants                     *CredentialOfferGrants `json:"grants,omitempty"`
}

// CredentialOfferGrants represents the grants in a credential offer.
type CredentialOfferGrants struct {
	AuthorizationCode *AuthorizationCodeGrant `json:"authorization_code,omitempty"`
	PreAuthorizedCode *PreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

// AuthorizationCodeGrant represents authorization code grant parameters.
type AuthorizationCodeGrant struct {
	IssuerState string `json:"issuer_state,omitempty"`
}

// PreAuthorizedCodeGrant represents pre-authorized code grant parameters.
type PreAuthorizedCodeGrant struct {
	PreAuthorizedCode   string  `json:"pre-authorized_code"`
	TxCode              *TxCode `json:"tx_code,omitempty"`
	AuthorizationServer string  `json:"authorization_server,omitempty"`
}

// TxCode represents transaction code requirements.
type TxCode struct {
	InputMode   string `json:"input_mode,omitempty"` // "numeric" or "text"
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

// IssuerMetadata represents the credential issuer's metadata.
type IssuerMetadata struct {
	CredentialIssuer                  string                             `json:"credential_issuer"`
	AuthorizationServers              []string                           `json:"authorization_servers,omitempty"`
	CredentialEndpoint                string                             `json:"credential_endpoint"`
	BatchCredentialEndpoint           string                             `json:"batch_credential_endpoint,omitempty"`
	DeferredCredentialEndpoint        string                             `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              string                             `json:"notification_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported"`
	Display                           []IssuerDisplay                    `json:"display,omitempty"`
}

// IssuerDisplay contains issuer display information.
type IssuerDisplay struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
	Logo   *Logo  `json:"logo,omitempty"`
}

// Logo represents logo information.
type Logo struct {
	URI     string `json:"uri,omitempty"`
	AltText string `json:"alt_text,omitempty"`
}

// CredentialConfiguration describes a supported credential type.
type CredentialConfiguration struct {
	Format                      string               `json:"format"`
	Scope                       string               `json:"scope,omitempty"`
	CryptographicBindingMethods []string             `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValues  []string             `json:"credential_signing_alg_values_supported,omitempty"`
	ProofTypesSupported         map[string]ProofType `json:"proof_types_supported,omitempty"`
	Display                     []CredentialDisplay  `json:"display,omitempty"`
	// SD-JWT specific
	VCT    string                 `json:"vct,omitempty"`
	Claims map[string]ClaimConfig `json:"claims,omitempty"`
	// mDL specific
	Doctype string `json:"doctype,omitempty"`
}

// ProofType describes supported proof types.
type ProofType struct {
	ProofSigningAlgValues []string `json:"proof_signing_alg_values_supported,omitempty"`
}

// CredentialDisplay contains credential display information.
type CredentialDisplay struct {
	Name            string `json:"name,omitempty"`
	Locale          string `json:"locale,omitempty"`
	Description     string `json:"description,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
	Logo            *Logo  `json:"logo,omitempty"`
}

// ClaimConfig describes a credential claim.
type ClaimConfig struct {
	Display   []ClaimDisplay `json:"display,omitempty"`
	Mandatory bool           `json:"mandatory,omitempty"`
	ValueType string         `json:"value_type,omitempty"`
}

// ClaimDisplay contains claim display information.
type ClaimDisplay struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
}

// OAuthServerMetadata represents OAuth 2.0 Authorization Server metadata.
type OAuthServerMetadata struct {
	Issuer                             string   `json:"issuer"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint,omitempty"`
	RegistrationEndpoint               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported             []string `json:"response_types_supported,omitempty"`
	CodeChallengeMethodsSupported      []string `json:"code_challenge_methods_supported,omitempty"`
	DPoPSigningAlgValuesSupported      []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// TokenResponse represents the token endpoint response.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// CredentialRequest represents a credential request.
type CredentialRequest struct {
	Format                    string  `json:"format,omitempty"`
	CredentialConfigurationID string  `json:"credential_configuration_id,omitempty"`
	Proof                     *Proof  `json:"proof,omitempty"`
	Proofs                    *Proofs `json:"proofs,omitempty"`
}

// Proof represents a proof of possession.
type Proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt,omitempty"`
}

// Proofs represents multiple proofs.
type Proofs struct {
	JWTProofs []string `json:"jwt,omitempty"`
}

// CredentialResponse represents the credential endpoint response.
type CredentialResponse struct {
	Credential      any    `json:"credential,omitempty"`     // Can be string or object
	Credentials     []any  `json:"credentials,omitempty"`    // For batch
	TransactionID   string `json:"transaction_id,omitempty"` // For deferred
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
	NotificationID  string `json:"notification_id,omitempty"`
}

// ParseCredentialOfferURL parses an OpenID4VCI credential offer URL.
func (c *Client) ParseCredentialOfferURL(offerURL string) (*CredentialOffer, error) {
	// Parse URL
	u, err := url.Parse(offerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Check scheme
	if u.Scheme != "openid-credential-offer" && u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}

	// Get credential_offer or credential_offer_uri parameter
	query := u.Query()

	// Direct credential offer in URL
	if credentialOffer := query.Get("credential_offer"); credentialOffer != "" {
		var offer CredentialOffer
		if err := json.Unmarshal([]byte(credentialOffer), &offer); err != nil {
			return nil, fmt.Errorf("failed to parse credential_offer: %w", err)
		}
		return &offer, nil
	}

	// Credential offer URI - need to fetch it
	if credentialOfferURI := query.Get("credential_offer_uri"); credentialOfferURI != "" {
		return c.fetchCredentialOffer(context.Background(), credentialOfferURI)
	}

	return nil, fmt.Errorf("no credential_offer or credential_offer_uri found in URL")
}

// fetchCredentialOffer fetches a credential offer from a URI.
func (c *Client) fetchCredentialOffer(ctx context.Context, uri string) (*CredentialOffer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential offer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("credential offer fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var offer CredentialOffer
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, fmt.Errorf("failed to decode credential offer: %w", err)
	}

	return &offer, nil
}

// GetIssuerMetadata fetches the credential issuer's metadata.
func (c *Client) GetIssuerMetadata(ctx context.Context, issuerURL string) (*IssuerMetadata, error) {
	// Construct well-known URL
	metadataURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-credential-issuer"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer metadata fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var metadata IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode issuer metadata: %w", err)
	}

	return &metadata, nil
}

// GetOAuthServerMetadata fetches the OAuth 2.0 authorization server metadata.
func (c *Client) GetOAuthServerMetadata(ctx context.Context, serverURL string) (*OAuthServerMetadata, error) {
	// Construct well-known URL
	metadataURL := strings.TrimSuffix(serverURL, "/") + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OAuth server metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OAuth server metadata fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var metadata OAuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode OAuth server metadata: %w", err)
	}

	return &metadata, nil
}

// ExchangePreAuthorizedCode exchanges a pre-authorized code for tokens.
func (c *Client) ExchangePreAuthorizedCode(ctx context.Context, tokenEndpoint string, preAuthCode string, txCode string, clientID string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	data.Set("pre-authorized_code", preAuthCode)
	if txCode != "" {
		data.Set("tx_code", txCode)
	}
	if clientID != "" {
		data.Set("client_id", clientID)
	}

	return c.doTokenRequest(ctx, tokenEndpoint, data)
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
func (c *Client) ExchangeAuthorizationCode(ctx context.Context, tokenEndpoint string, code string, redirectURI string, clientID string, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	if clientID != "" {
		data.Set("client_id", clientID)
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	return c.doTokenRequest(ctx, tokenEndpoint, data)
}

func (c *Client) doTokenRequest(ctx context.Context, tokenEndpoint string, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// RequestCredential requests a credential from the issuer.
func (c *Client) RequestCredential(ctx context.Context, credentialEndpoint string, accessToken string, credReq *CredentialRequest) (*CredentialResponse, error) {
	body, err := json.Marshal(credReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create credential request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("credential request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var credResp CredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
		return nil, fmt.Errorf("failed to decode credential response: %w", err)
	}

	return &credResp, nil
}
