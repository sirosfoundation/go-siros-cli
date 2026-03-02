// Package backend provides a client for the go-wallet-backend API.package backend

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the wallet backend API client.
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	tenantID   string
}

// TenantIDHeader is the HTTP header name for tenant identification.
const TenantIDHeader = "X-Tenant-ID"

// DefaultTenantID is the default tenant identifier for backward compatibility.
const DefaultTenantID = "default"

// NewClient creates a new backend client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		tenantID: DefaultTenantID,
	}
}

// SetToken sets the authentication token.
func (c *Client) SetToken(token string) {
	c.token = token
}

// GetToken returns the current authentication token.
func (c *Client) GetToken() string {
	return c.token
}

// SetTenantID sets the tenant identifier for API requests.
// This will be sent as the X-Tenant-ID header on all requests.
func (c *Client) SetTenantID(tenantID string) {
	if tenantID != "" {
		c.tenantID = tenantID
	} else {
		c.tenantID = DefaultTenantID
	}
}

// GetTenantID returns the current tenant identifier.
func (c *Client) GetTenantID() string {
	return c.tenantID
}

// Status checks the backend status.
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.get(ctx, "/status", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StatusResponse represents the /status endpoint response.
type StatusResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// --- WebAuthn ---

// StartRegistration begins WebAuthn registration for a new user.
func (c *Client) StartRegistration(ctx context.Context, displayName string) (*RegistrationStartResponse, error) {
	req := map[string]string{"displayName": displayName}
	var resp RegistrationStartResponse
	if err := c.post(ctx, "/user/register-webauthn-begin", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RegistrationStartResponse represents the registration start response.
type RegistrationStartResponse struct {
	ChallengeID   string                 `json:"challengeId"`
	CreateOptions map[string]interface{} `json:"createOptions"`
}

// FinishRegistration completes WebAuthn registration for a new user.
func (c *Client) FinishRegistration(ctx context.Context, req *RegistrationFinishRequest) (*RegistrationFinishResponse, error) {
	var resp RegistrationFinishResponse
	if err := c.post(ctx, "/user/register-webauthn-finish", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RegistrationFinishRequest represents the registration finish request.
type RegistrationFinishRequest struct {
	ChallengeID string                 `json:"challengeId"`
	Credential  map[string]interface{} `json:"credential"`
	DisplayName string                 `json:"displayName,omitempty"`
	Nickname    string                 `json:"nickname,omitempty"`
	Keys        interface{}            `json:"keys,omitempty"`
	PrivateData interface{}            `json:"privateData,omitempty"`
}

// RegistrationFinishResponse represents the registration finish response.
type RegistrationFinishResponse struct {
	UUID         string      `json:"uuid"`
	Token        string      `json:"appToken"`
	DisplayName  string      `json:"displayName"`
	Username     string      `json:"username,omitempty"`
	PrivateData  interface{} `json:"privateData,omitempty"`
	WebauthnRpId string      `json:"webauthnRpId"`
}

// StartLogin begins WebAuthn login.
func (c *Client) StartLogin(ctx context.Context) (*LoginStartResponse, error) {
	var resp LoginStartResponse
	if err := c.post(ctx, "/user/login-webauthn-begin", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LoginStartResponse represents the login start response.
type LoginStartResponse struct {
	ChallengeID string                 `json:"challengeId"`
	GetOptions  map[string]interface{} `json:"getOptions"`
}

// FinishLogin completes WebAuthn login.
func (c *Client) FinishLogin(ctx context.Context, req *LoginFinishRequest) (*LoginFinishResponse, error) {
	var resp LoginFinishResponse
	if err := c.post(ctx, "/user/login-webauthn-finish", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LoginFinishRequest represents the login finish request.
type LoginFinishRequest struct {
	ChallengeID string                 `json:"challengeId"`
	Credential  map[string]interface{} `json:"credential"`
}

// LoginFinishResponse represents the login finish response.
type LoginFinishResponse struct {
	UUID         string      `json:"uuid"`
	Token        string      `json:"appToken"`
	DisplayName  string      `json:"displayName"`
	Username     string      `json:"username,omitempty"`
	PrivateData  interface{} `json:"privateData,omitempty"`
	WebauthnRpId string      `json:"webauthnRpId"`
}

// --- Account Info ---

// GetAccountInfo retrieves account information for the current user.
func (c *Client) GetAccountInfo(ctx context.Context) (*AccountInfoResponse, error) {
	var resp AccountInfoResponse
	if err := c.get(ctx, "/session/account-info", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AccountInfoResponse represents the account info response.
type AccountInfoResponse struct {
	UUID        string      `json:"uuid"`
	DisplayName string      `json:"displayName"`
	Username    string      `json:"username,omitempty"`
	PrivateData interface{} `json:"privateData,omitempty"`
}

// --- Credentials ---

// GetCredentials retrieves all credentials.
func (c *Client) GetCredentials(ctx context.Context) ([]*Credential, error) {
	var resp CredentialsResponse
	if err := c.get(ctx, "/storage/vc", &resp); err != nil {
		return nil, err
	}
	return resp.Credentials, nil
}

// GetCredential retrieves a single credential by ID.
func (c *Client) GetCredential(ctx context.Context, credentialID string) (*Credential, error) {
	var cred Credential
	if err := c.get(ctx, "/storage/vc/"+credentialID, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// DeleteCredential deletes a credential by ID.
func (c *Client) DeleteCredential(ctx context.Context, credentialID string) error {
	return c.delete(ctx, "/storage/vc/"+credentialID)
}

// CredentialsResponse represents the credentials list response.
type CredentialsResponse struct {
	Credentials []*Credential `json:"vc_list"`
}

// Credential represents a verifiable credential.
type Credential struct {
	ID                         string `json:"credentialIdentifier"`
	HolderDID                  string `json:"holderDID"`
	Credential                 string `json:"credential"`
	Format                     string `json:"format"`
	CredentialConfigurationID  string `json:"credentialConfigurationId"`
	CredentialIssuerIdentifier string `json:"credentialIssuerIdentifier"`
	InstanceID                 string `json:"instanceId,omitempty"`
}

// StoreCredential stores a credential.
func (c *Client) StoreCredential(ctx context.Context, cred *Credential) error {
	return c.post(ctx, "/storage/vc", cred, nil)
}

// StoreCredentials stores multiple credentials.
func (c *Client) StoreCredentials(ctx context.Context, creds []*Credential) error {
	req := map[string]any{"credentials": creds}
	return c.post(ctx, "/storage/vc", req, nil)
}

// --- Presentations ---

// GetPresentations retrieves all presentations.
func (c *Client) GetPresentations(ctx context.Context) ([]*Presentation, error) {
	var resp PresentationsResponse
	if err := c.get(ctx, "/storage/vp", &resp); err != nil {
		return nil, err
	}
	return resp.Presentations, nil
}

// PresentationsResponse represents the presentations list response.
type PresentationsResponse struct {
	Presentations []*Presentation `json:"vp_list"`
}

// Presentation represents a verifiable presentation.
type Presentation struct {
	ID            string   `json:"presentationIdentifier"`
	HolderDID     string   `json:"holderDID"`
	Presentation  string   `json:"presentation"`
	Format        string   `json:"format"`
	CredentialIDs []string `json:"includedCredentials"`
}

// --- Issuers ---

// GetIssuers retrieves all issuers.
func (c *Client) GetIssuers(ctx context.Context) ([]*Issuer, error) {
	var resp []*Issuer
	if err := c.get(ctx, "/issuer/all", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Issuer represents a credential issuer.
type Issuer struct {
	ID                         int64  `json:"id"`
	CredentialIssuerIdentifier string `json:"credentialIssuerIdentifier"`
	Visible                    bool   `json:"visible"`
}

// --- Verifiers ---

// GetVerifiers retrieves all verifiers.
func (c *Client) GetVerifiers(ctx context.Context) ([]*Verifier, error) {
	var resp []*Verifier
	if err := c.get(ctx, "/verifier/all", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Verifier represents a credential verifier.
type Verifier struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// --- HTTP helpers ---

func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	return c.doRequest(req, result)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.doRequest(req, result)
}

func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	return c.doRequest(req, nil)
}

func (c *Client) doRequest(req *http.Request, result interface{}) error {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	// Always set X-Tenant-ID header for multi-tenant support
	if c.tenantID != "" {
		req.Header.Set(TenantIDHeader, c.tenantID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}
