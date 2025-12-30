// Package oid4vp implements the OpenID for Verifiable Presentations (OID4VP) protocol
// for presenting credentials to verifiers.
package oid4vp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client handles OpenID4VP authorization requests.
type Client struct {
	httpClient *http.Client
}

// AuthorizationRequest represents a parsed OID4VP authorization request.
type AuthorizationRequest struct {
	ClientID                  string                  `json:"client_id"`
	ResponseURI               string                  `json:"response_uri"`
	RedirectURI               string                  `json:"redirect_uri"`
	Nonce                     string                  `json:"nonce"`
	State                     string                  `json:"state"`
	ResponseType              string                  `json:"response_type"`
	ResponseMode              ResponseMode            `json:"response_mode"`
	PresentationDefinition    *PresentationDefinition `json:"presentation_definition,omitempty"`
	PresentationDefinitionURI string                  `json:"presentation_definition_uri,omitempty"`
	ClientMetadata            *ClientMetadata         `json:"client_metadata,omitempty"`
	ClientMetadataURI         string                  `json:"client_metadata_uri,omitempty"`
	RequestURI                string                  `json:"request_uri,omitempty"`
	DCQLQuery                 json.RawMessage         `json:"dcql_query,omitempty"`
	TransactionData           []string                `json:"transaction_data,omitempty"`
	ClientIDScheme            string                  `json:"client_id_scheme,omitempty"`
}

// ResponseMode defines how the authorization response should be sent.
type ResponseMode string

const (
	ResponseModeDirectPost    ResponseMode = "direct_post"
	ResponseModeDirectPostJWT ResponseMode = "direct_post.jwt"
	ResponseModeFragment      ResponseMode = "fragment"
	ResponseModeQuery         ResponseMode = "query"
)

// ClientMetadata contains verifier metadata for response encryption.
type ClientMetadata struct {
	JWKS                              *JWKS  `json:"jwks,omitempty"`
	JWKSURI                           string `json:"jwks_uri,omitempty"`
	AuthorizationEncryptedResponseAlg string `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string `json:"authorization_encrypted_response_enc,omitempty"`
	VPFormats                         any    `json:"vp_formats,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []json.RawMessage `json:"keys"`
}

// PresentationDefinition defines what credentials are being requested.
type PresentationDefinition struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

// InputDescriptor describes a single credential requirement.
type InputDescriptor struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Format      map[string]interface{} `json:"format,omitempty"`
	Constraints *Constraints           `json:"constraints,omitempty"`
}

// Constraints defines field constraints for credential matching.
type Constraints struct {
	LimitDisclosure string  `json:"limit_disclosure,omitempty"`
	Fields          []Field `json:"fields,omitempty"`
}

// Field defines a single field constraint.
type Field struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Path           []string `json:"path"`
	Purpose        string   `json:"purpose,omitempty"`
	Filter         any      `json:"filter,omitempty"`
	IntentToRetain bool     `json:"intent_to_retain,omitempty"`
}

// PresentationSubmission describes how the VP maps to the presentation definition.
type PresentationSubmission struct {
	ID            string              `json:"id"`
	DefinitionID  string              `json:"definition_id"`
	DescriptorMap []DescriptorMapItem `json:"descriptor_map"`
}

// DescriptorMapItem maps an input descriptor to a VP path.
type DescriptorMapItem struct {
	ID         string             `json:"id"`
	Format     string             `json:"format"`
	Path       string             `json:"path"`
	PathNested *DescriptorMapItem `json:"path_nested,omitempty"`
}

// AuthorizationResponse is sent back to the verifier.
type AuthorizationResponse struct {
	VPToken                string                  `json:"vp_token"`
	PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty"`
	State                  string                  `json:"state,omitempty"`
	IDToken                string                  `json:"id_token,omitempty"`
}

// VerifierResponse is the response from submitting the authorization response.
type VerifierResponse struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// CredentialMatch represents a credential that matches an input descriptor.
type CredentialMatch struct {
	DescriptorID   string
	CredentialID   string
	CredentialData string
	Format         string
	MatchedFields  []MatchedField
}

// MatchedField represents a field that was matched.
type MatchedField struct {
	Name    string
	Path    string
	Purpose string
}

// NewClient creates a new OID4VP client.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return &Client{
		httpClient: httpClient,
	}
}

// ParseAuthorizationRequestURL parses an OpenID4VP authorization request URL.
// Supports formats:
//   - openid4vp://authorize?...
//   - https://verifier.example.com/authorize?...
func (c *Client) ParseAuthorizationRequestURL(requestURL string) (*AuthorizationRequest, error) {
	// Handle openid4vp:// scheme
	if strings.HasPrefix(requestURL, "openid4vp://") {
		// Convert to parseable URL by replacing scheme
		requestURL = "https://openid4vp" + strings.TrimPrefix(requestURL, "openid4vp:/")
	}

	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	params := parsedURL.Query()

	req := &AuthorizationRequest{
		ClientID:                  params.Get("client_id"),
		ResponseURI:               params.Get("response_uri"),
		RedirectURI:               params.Get("redirect_uri"),
		Nonce:                     params.Get("nonce"),
		State:                     params.Get("state"),
		ResponseType:              params.Get("response_type"),
		ResponseMode:              ResponseMode(params.Get("response_mode")),
		RequestURI:                params.Get("request_uri"),
		PresentationDefinitionURI: params.Get("presentation_definition_uri"),
		ClientMetadataURI:         params.Get("client_metadata_uri"),
		ClientIDScheme:            params.Get("client_id_scheme"),
	}

	// Parse presentation_definition if present
	if pdStr := params.Get("presentation_definition"); pdStr != "" {
		var pd PresentationDefinition
		if err := json.Unmarshal([]byte(pdStr), &pd); err != nil {
			return nil, fmt.Errorf("failed to parse presentation_definition: %w", err)
		}
		req.PresentationDefinition = &pd
	}

	// Parse client_metadata if present
	if cmStr := params.Get("client_metadata"); cmStr != "" {
		var cm ClientMetadata
		if err := json.Unmarshal([]byte(cmStr), &cm); err != nil {
			return nil, fmt.Errorf("failed to parse client_metadata: %w", err)
		}
		req.ClientMetadata = &cm
	}

	// Parse dcql_query if present
	if dcqlStr := params.Get("dcql_query"); dcqlStr != "" {
		req.DCQLQuery = json.RawMessage(dcqlStr)
	}

	// Parse transaction_data if present
	if tdStr := params.Get("transaction_data"); tdStr != "" {
		var td []string
		if err := json.Unmarshal([]byte(tdStr), &td); err != nil {
			return nil, fmt.Errorf("failed to parse transaction_data: %w", err)
		}
		req.TransactionData = td
	}

	return req, nil
}

// FetchRequestObject fetches the request object from request_uri.
func (c *Client) FetchRequestObject(requestURI string) (*AuthorizationRequest, error) {
	resp, err := c.httpClient.Get(requestURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch request_uri: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request_uri returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request_uri response: %w", err)
	}

	// The response is a JWT - parse payload
	// For now, we'll try to parse as JSON if it's not a JWT
	jwt := string(body)

	// Check if it's a JWT (has three parts separated by dots)
	parts := strings.Split(jwt, ".")
	if len(parts) == 3 {
		// Decode the payload (second part)
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
		}

		var req AuthorizationRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("failed to parse request object: %w", err)
		}
		return &req, nil
	}

	// Try parsing as JSON directly
	var req AuthorizationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("failed to parse request object: %w", err)
	}
	return &req, nil
}

// FetchPresentationDefinition fetches presentation definition from URI.
func (c *Client) FetchPresentationDefinition(uri string) (*PresentationDefinition, error) {
	resp, err := c.httpClient.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch presentation_definition_uri: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("presentation_definition_uri returned status %d", resp.StatusCode)
	}

	var pd PresentationDefinition
	if err := json.NewDecoder(resp.Body).Decode(&pd); err != nil {
		return nil, fmt.Errorf("failed to decode presentation definition: %w", err)
	}

	return &pd, nil
}

// FetchClientMetadata fetches client metadata from URI.
func (c *Client) FetchClientMetadata(uri string) (*ClientMetadata, error) {
	resp, err := c.httpClient.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client_metadata_uri: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client_metadata_uri returned status %d", resp.StatusCode)
	}

	var cm ClientMetadata
	if err := json.NewDecoder(resp.Body).Decode(&cm); err != nil {
		return nil, fmt.Errorf("failed to decode client metadata: %w", err)
	}

	return &cm, nil
}

// ResolveAuthorizationRequest resolves all references in the authorization request.
// This fetches request_uri, presentation_definition_uri, and client_metadata_uri if present.
func (c *Client) ResolveAuthorizationRequest(req *AuthorizationRequest) (*AuthorizationRequest, error) {
	resolved := *req // Copy

	// If request_uri is present, fetch and use that
	if req.RequestURI != "" {
		fetched, err := c.FetchRequestObject(req.RequestURI)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve request_uri: %w", err)
		}
		resolved = *fetched
		// Preserve state from original request if not in fetched
		if resolved.State == "" && req.State != "" {
			resolved.State = req.State
		}
	}

	// Fetch presentation definition if URI is provided
	if resolved.PresentationDefinition == nil && resolved.PresentationDefinitionURI != "" {
		pd, err := c.FetchPresentationDefinition(resolved.PresentationDefinitionURI)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve presentation_definition_uri: %w", err)
		}
		resolved.PresentationDefinition = pd
	}

	// Fetch client metadata if URI is provided
	if resolved.ClientMetadata == nil && resolved.ClientMetadataURI != "" {
		cm, err := c.FetchClientMetadata(resolved.ClientMetadataURI)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve client_metadata_uri: %w", err)
		}
		resolved.ClientMetadata = cm
	}

	return &resolved, nil
}

// GetVerifierDomain extracts the verifier domain from the authorization request.
func (c *Client) GetVerifierDomain(req *AuthorizationRequest) string {
	// Try response_uri first
	if req.ResponseURI != "" {
		if u, err := url.Parse(req.ResponseURI); err == nil {
			return u.Host
		}
	}
	// Try redirect_uri
	if req.RedirectURI != "" {
		if u, err := url.Parse(req.RedirectURI); err == nil {
			return u.Host
		}
	}
	// Try client_id if it's a URL
	if strings.HasPrefix(req.ClientID, "http") {
		if u, err := url.Parse(req.ClientID); err == nil {
			return u.Host
		}
	}
	return req.ClientID
}

// GetRequestedFields extracts the list of requested fields from presentation definition.
func (c *Client) GetRequestedFields(pd *PresentationDefinition) []MatchedField {
	var fields []MatchedField

	for _, descriptor := range pd.InputDescriptors {
		purpose := descriptor.Purpose
		if purpose == "" && pd.Purpose != "" {
			purpose = pd.Purpose
		}

		if descriptor.Constraints != nil {
			for _, field := range descriptor.Constraints.Fields {
				path := ""
				if len(field.Path) > 0 {
					path = field.Path[0]
				}
				name := field.Name
				if name == "" && path != "" {
					// Extract name from path like $.credentialSubject.name
					parts := strings.Split(path, ".")
					if len(parts) > 0 {
						name = parts[len(parts)-1]
					}
				}

				fieldPurpose := field.Purpose
				if fieldPurpose == "" {
					fieldPurpose = purpose
				}

				fields = append(fields, MatchedField{
					Name:    name,
					Path:    path,
					Purpose: fieldPurpose,
				})
			}
		}
	}

	return fields
}

// SubmitAuthorizationResponse sends the VP token to the verifier.
func (c *Client) SubmitAuthorizationResponse(
	responseURI string,
	vpToken string,
	presentationSubmission *PresentationSubmission,
	state string,
) (*VerifierResponse, error) {
	// Build form data
	formData := url.Values{}
	formData.Set("vp_token", vpToken)

	if presentationSubmission != nil {
		psJSON, err := json.Marshal(presentationSubmission)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal presentation_submission: %w", err)
		}
		formData.Set("presentation_submission", string(psJSON))
	}

	if state != "" {
		formData.Set("state", state)
	}

	req, err := http.NewRequest("POST", responseURI, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit authorization response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for error response
	if resp.StatusCode >= 400 {
		var verifierResp VerifierResponse
		if json.Unmarshal(body, &verifierResp) == nil && verifierResp.Error != "" {
			return &verifierResp, fmt.Errorf("verifier error: %s - %s", verifierResp.Error, verifierResp.ErrorDesc)
		}
		return nil, fmt.Errorf("verifier returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse successful response
	var verifierResp VerifierResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &verifierResp); err != nil {
			// Response might be a redirect URI directly
			verifierResp.RedirectURI = string(body)
		}
	}

	return &verifierResp, nil
}

// BuildPresentationSubmission creates a presentation submission for the given credentials.
func (c *Client) BuildPresentationSubmission(
	definitionID string,
	matches []CredentialMatch,
) *PresentationSubmission {
	id := generateID()

	descriptorMap := make([]DescriptorMapItem, len(matches))
	for i, match := range matches {
		path := "$"
		if len(matches) > 1 {
			path = fmt.Sprintf("$[%d]", i)
		}
		descriptorMap[i] = DescriptorMapItem{
			ID:     match.DescriptorID,
			Format: match.Format,
			Path:   path,
		}
	}

	return &PresentationSubmission{
		ID:            id,
		DefinitionID:  definitionID,
		DescriptorMap: descriptorMap,
	}
}

// ValidateAuthorizationRequest performs basic validation on the request.
func (c *Client) ValidateAuthorizationRequest(req *AuthorizationRequest) error {
	if req.ClientID == "" {
		return errors.New("missing client_id")
	}

	// Must have either response_uri or redirect_uri
	if req.ResponseURI == "" && req.RedirectURI == "" {
		return errors.New("missing response_uri or redirect_uri")
	}

	// Must have presentation_definition or dcql_query
	if req.PresentationDefinition == nil &&
		req.PresentationDefinitionURI == "" &&
		len(req.DCQLQuery) == 0 {
		return errors.New("missing presentation_definition or dcql_query")
	}

	// Validate response_mode if present
	switch req.ResponseMode {
	case "", ResponseModeDirectPost, ResponseModeDirectPostJWT, ResponseModeFragment, ResponseModeQuery:
		// Valid
	default:
		return fmt.Errorf("unsupported response_mode: %s", req.ResponseMode)
	}

	return nil
}

// GetResponseEndpoint returns the URI to send the response to.
func (c *Client) GetResponseEndpoint(req *AuthorizationRequest) string {
	if req.ResponseURI != "" {
		return req.ResponseURI
	}
	return req.RedirectURI
}

// generateID generates a random identifier.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
