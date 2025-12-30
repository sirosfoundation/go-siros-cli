package oid4vp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	t.Run("with nil http client", func(t *testing.T) {
		client := NewClient(nil)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if client.httpClient == nil {
			t.Error("expected non-nil http client")
		}
	})

	t.Run("with custom http client", func(t *testing.T) {
		customHTTP := &http.Client{}
		client := NewClient(customHTTP)
		if client.httpClient != customHTTP {
			t.Error("expected custom http client to be used")
		}
	})
}

func TestParseAuthorizationRequestURL_OpenID4VPScheme(t *testing.T) {
	client := NewClient(nil)

	requestURL := "openid4vp://authorize?client_id=https://verifier.example.com&response_uri=https://verifier.example.com/callback&nonce=abc123&state=state456&response_mode=direct_post"

	req, err := client.ParseAuthorizationRequestURL(requestURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.ClientID != "https://verifier.example.com" {
		t.Errorf("expected client_id 'https://verifier.example.com', got %q", req.ClientID)
	}
	if req.ResponseURI != "https://verifier.example.com/callback" {
		t.Errorf("expected response_uri, got %q", req.ResponseURI)
	}
	if req.Nonce != "abc123" {
		t.Errorf("expected nonce 'abc123', got %q", req.Nonce)
	}
	if req.State != "state456" {
		t.Errorf("expected state 'state456', got %q", req.State)
	}
	if req.ResponseMode != ResponseModeDirectPost {
		t.Errorf("expected response_mode 'direct_post', got %q", req.ResponseMode)
	}
}

func TestParseAuthorizationRequestURL_HTTPSScheme(t *testing.T) {
	client := NewClient(nil)

	requestURL := "https://verifier.example.com/authorize?client_id=client123&redirect_uri=https://verifier.example.com/redirect&nonce=nonce789"

	req, err := client.ParseAuthorizationRequestURL(requestURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.ClientID != "client123" {
		t.Errorf("expected client_id 'client123', got %q", req.ClientID)
	}
	if req.RedirectURI != "https://verifier.example.com/redirect" {
		t.Errorf("expected redirect_uri, got %q", req.RedirectURI)
	}
}

func TestParseAuthorizationRequestURL_WithPresentationDefinition(t *testing.T) {
	client := NewClient(nil)

	pd := `{"id":"test-pd","input_descriptors":[{"id":"pid","constraints":{"fields":[{"path":["$.name"]}]}}]}`
	requestURL := "openid4vp://authorize?client_id=verifier&response_uri=https://example.com/callback&presentation_definition=" + pd

	req, err := client.ParseAuthorizationRequestURL(requestURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.PresentationDefinition == nil {
		t.Fatal("expected presentation_definition to be parsed")
	}
	if req.PresentationDefinition.ID != "test-pd" {
		t.Errorf("expected id 'test-pd', got %q", req.PresentationDefinition.ID)
	}
	if len(req.PresentationDefinition.InputDescriptors) != 1 {
		t.Fatalf("expected 1 input descriptor, got %d", len(req.PresentationDefinition.InputDescriptors))
	}
	if req.PresentationDefinition.InputDescriptors[0].ID != "pid" {
		t.Errorf("expected descriptor id 'pid', got %q", req.PresentationDefinition.InputDescriptors[0].ID)
	}
}

func TestParseAuthorizationRequestURL_WithClientMetadata(t *testing.T) {
	client := NewClient(nil)

	cm := `{"authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM"}`
	requestURL := "openid4vp://authorize?client_id=verifier&response_uri=https://example.com/callback&client_metadata=" + cm

	req, err := client.ParseAuthorizationRequestURL(requestURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.ClientMetadata == nil {
		t.Fatal("expected client_metadata to be parsed")
	}
	if req.ClientMetadata.AuthorizationEncryptedResponseAlg != "ECDH-ES" {
		t.Errorf("expected alg 'ECDH-ES', got %q", req.ClientMetadata.AuthorizationEncryptedResponseAlg)
	}
}

func TestParseAuthorizationRequestURL_InvalidURL(t *testing.T) {
	client := NewClient(nil)

	_, err := client.ParseAuthorizationRequestURL("not a valid url %$#@")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestFetchRequestObject(t *testing.T) {
	// Create a mock server that returns a JWT
	reqObject := AuthorizationRequest{
		ClientID:    "test-client",
		ResponseURI: "https://verifier.example.com/callback",
		Nonce:       "test-nonce",
	}
	payload, _ := json.Marshal(reqObject)
	// Create a simple "JWT" (base64 encoded parts)
	jwt := "eyJhbGciOiJFUzI1NiJ9." + base64URLEncode(payload) + ".signature"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(jwt))
	}))
	defer server.Close()

	client := NewClient(nil)
	req, err := client.FetchRequestObject(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.ClientID != "test-client" {
		t.Errorf("expected client_id 'test-client', got %q", req.ClientID)
	}
	if req.Nonce != "test-nonce" {
		t.Errorf("expected nonce 'test-nonce', got %q", req.Nonce)
	}
}

func TestFetchPresentationDefinition(t *testing.T) {
	pd := PresentationDefinition{
		ID:      "test-pd",
		Name:    "Test Presentation",
		Purpose: "Testing",
		InputDescriptors: []InputDescriptor{
			{
				ID:   "descriptor1",
				Name: "Test Descriptor",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pd)
	}))
	defer server.Close()

	client := NewClient(nil)
	result, err := client.FetchPresentationDefinition(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "test-pd" {
		t.Errorf("expected id 'test-pd', got %q", result.ID)
	}
	if len(result.InputDescriptors) != 1 {
		t.Fatalf("expected 1 descriptor, got %d", len(result.InputDescriptors))
	}
}

func TestFetchClientMetadata(t *testing.T) {
	cm := ClientMetadata{
		AuthorizationEncryptedResponseAlg: "ECDH-ES",
		AuthorizationEncryptedResponseEnc: "A256GCM",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cm)
	}))
	defer server.Close()

	client := NewClient(nil)
	result, err := client.FetchClientMetadata(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AuthorizationEncryptedResponseAlg != "ECDH-ES" {
		t.Errorf("expected alg 'ECDH-ES', got %q", result.AuthorizationEncryptedResponseAlg)
	}
}

func TestResolveAuthorizationRequest_WithPresentationDefinitionURI(t *testing.T) {
	pd := PresentationDefinition{
		ID:   "resolved-pd",
		Name: "Resolved Presentation",
	}

	pdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pd)
	}))
	defer pdServer.Close()

	client := NewClient(nil)
	req := &AuthorizationRequest{
		ClientID:                  "client123",
		ResponseURI:               "https://verifier.example.com/callback",
		PresentationDefinitionURI: pdServer.URL,
	}

	resolved, err := client.ResolveAuthorizationRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolved.PresentationDefinition == nil {
		t.Fatal("expected presentation_definition to be resolved")
	}
	if resolved.PresentationDefinition.ID != "resolved-pd" {
		t.Errorf("expected id 'resolved-pd', got %q", resolved.PresentationDefinition.ID)
	}
}

func TestGetVerifierDomain(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name     string
		req      *AuthorizationRequest
		expected string
	}{
		{
			name: "from response_uri",
			req: &AuthorizationRequest{
				ResponseURI: "https://verifier.example.com/callback",
			},
			expected: "verifier.example.com",
		},
		{
			name: "from redirect_uri",
			req: &AuthorizationRequest{
				RedirectURI: "https://other.example.com/redirect",
			},
			expected: "other.example.com",
		},
		{
			name: "from client_id URL",
			req: &AuthorizationRequest{
				ClientID: "https://client.example.com",
			},
			expected: "client.example.com",
		},
		{
			name: "from client_id non-URL",
			req: &AuthorizationRequest{
				ClientID: "simple-client-id",
			},
			expected: "simple-client-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.GetVerifierDomain(tt.req)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetRequestedFields(t *testing.T) {
	client := NewClient(nil)

	pd := &PresentationDefinition{
		ID:      "test-pd",
		Purpose: "Default purpose",
		InputDescriptors: []InputDescriptor{
			{
				ID:      "desc1",
				Purpose: "Descriptor purpose",
				Constraints: &Constraints{
					Fields: []Field{
						{
							Name:    "Given Name",
							Path:    []string{"$.credentialSubject.given_name"},
							Purpose: "Field purpose",
						},
						{
							Path: []string{"$.credentialSubject.family_name"},
						},
					},
				},
			},
		},
	}

	fields := client.GetRequestedFields(pd)

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}

	if fields[0].Name != "Given Name" {
		t.Errorf("expected name 'Given Name', got %q", fields[0].Name)
	}
	if fields[0].Purpose != "Field purpose" {
		t.Errorf("expected purpose 'Field purpose', got %q", fields[0].Purpose)
	}

	// Second field should extract name from path
	if fields[1].Name != "family_name" {
		t.Errorf("expected name 'family_name', got %q", fields[1].Name)
	}
}

func TestSubmitAuthorizationResponse(t *testing.T) {
	var receivedVPToken string
	var receivedState string
	var receivedPS string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %q", ct)
		}

		r.ParseForm()
		receivedVPToken = r.FormValue("vp_token")
		receivedState = r.FormValue("state")
		receivedPS = r.FormValue("presentation_submission")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"redirect_uri": "https://verifier.example.com/success",
		})
	}))
	defer server.Close()

	client := NewClient(nil)

	ps := &PresentationSubmission{
		ID:           "ps-123",
		DefinitionID: "pd-456",
		DescriptorMap: []DescriptorMapItem{
			{ID: "desc1", Format: "vc+sd-jwt", Path: "$"},
		},
	}

	resp, err := client.SubmitAuthorizationResponse(server.URL, "vp-token-here", ps, "state-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedVPToken != "vp-token-here" {
		t.Errorf("expected vp_token 'vp-token-here', got %q", receivedVPToken)
	}
	if receivedState != "state-xyz" {
		t.Errorf("expected state 'state-xyz', got %q", receivedState)
	}
	if receivedPS == "" {
		t.Error("expected presentation_submission to be sent")
	}
	if resp.RedirectURI != "https://verifier.example.com/success" {
		t.Errorf("expected redirect_uri, got %q", resp.RedirectURI)
	}
}

func TestSubmitAuthorizationResponse_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing vp_token",
		})
	}))
	defer server.Close()

	client := NewClient(nil)
	_, err := client.SubmitAuthorizationResponse(server.URL, "", nil, "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid_request") {
		t.Errorf("expected error to contain 'invalid_request', got %q", err.Error())
	}
}

func TestBuildPresentationSubmission(t *testing.T) {
	client := NewClient(nil)

	matches := []CredentialMatch{
		{DescriptorID: "desc1", Format: "vc+sd-jwt"},
		{DescriptorID: "desc2", Format: "mso_mdoc"},
	}

	ps := client.BuildPresentationSubmission("pd-123", matches)

	if ps.ID == "" {
		t.Error("expected non-empty id")
	}
	if ps.DefinitionID != "pd-123" {
		t.Errorf("expected definition_id 'pd-123', got %q", ps.DefinitionID)
	}
	if len(ps.DescriptorMap) != 2 {
		t.Fatalf("expected 2 descriptor map items, got %d", len(ps.DescriptorMap))
	}

	// Check paths for multiple credentials
	if ps.DescriptorMap[0].Path != "$[0]" {
		t.Errorf("expected path '$[0]', got %q", ps.DescriptorMap[0].Path)
	}
	if ps.DescriptorMap[1].Path != "$[1]" {
		t.Errorf("expected path '$[1]', got %q", ps.DescriptorMap[1].Path)
	}
}

func TestBuildPresentationSubmission_SingleCredential(t *testing.T) {
	client := NewClient(nil)

	matches := []CredentialMatch{
		{DescriptorID: "desc1", Format: "vc+sd-jwt"},
	}

	ps := client.BuildPresentationSubmission("pd-123", matches)

	if len(ps.DescriptorMap) != 1 {
		t.Fatalf("expected 1 descriptor map item, got %d", len(ps.DescriptorMap))
	}

	// Single credential should use $ not $[0]
	if ps.DescriptorMap[0].Path != "$" {
		t.Errorf("expected path '$', got %q", ps.DescriptorMap[0].Path)
	}
}

func TestValidateAuthorizationRequest(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name        string
		req         *AuthorizationRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing client_id",
			req:         &AuthorizationRequest{ResponseURI: "https://example.com"},
			expectError: true,
			errorMsg:    "missing client_id",
		},
		{
			name:        "missing response endpoints",
			req:         &AuthorizationRequest{ClientID: "client123"},
			expectError: true,
			errorMsg:    "missing response_uri or redirect_uri",
		},
		{
			name: "missing presentation definition",
			req: &AuthorizationRequest{
				ClientID:    "client123",
				ResponseURI: "https://example.com",
			},
			expectError: true,
			errorMsg:    "missing presentation_definition",
		},
		{
			name: "unsupported response_mode",
			req: &AuthorizationRequest{
				ClientID:               "client123",
				ResponseURI:            "https://example.com",
				PresentationDefinition: &PresentationDefinition{ID: "test"},
				ResponseMode:           "unsupported_mode",
			},
			expectError: true,
			errorMsg:    "unsupported response_mode",
		},
		{
			name: "valid request with presentation_definition",
			req: &AuthorizationRequest{
				ClientID:               "client123",
				ResponseURI:            "https://example.com",
				PresentationDefinition: &PresentationDefinition{ID: "test"},
			},
			expectError: false,
		},
		{
			name: "valid request with presentation_definition_uri",
			req: &AuthorizationRequest{
				ClientID:                  "client123",
				ResponseURI:               "https://example.com",
				PresentationDefinitionURI: "https://example.com/pd",
			},
			expectError: false,
		},
		{
			name: "valid request with dcql_query",
			req: &AuthorizationRequest{
				ClientID:    "client123",
				ResponseURI: "https://example.com",
				DCQLQuery:   json.RawMessage(`{"credentials":[]}`),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ValidateAuthorizationRequest(tt.req)
			if tt.expectError {
				if err == nil {
					t.Error("expected error")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetResponseEndpoint(t *testing.T) {
	client := NewClient(nil)

	t.Run("prefers response_uri", func(t *testing.T) {
		req := &AuthorizationRequest{
			ResponseURI: "https://response.example.com",
			RedirectURI: "https://redirect.example.com",
		}
		if endpoint := client.GetResponseEndpoint(req); endpoint != "https://response.example.com" {
			t.Errorf("expected response_uri, got %q", endpoint)
		}
	})

	t.Run("falls back to redirect_uri", func(t *testing.T) {
		req := &AuthorizationRequest{
			RedirectURI: "https://redirect.example.com",
		}
		if endpoint := client.GetResponseEndpoint(req); endpoint != "https://redirect.example.com" {
			t.Errorf("expected redirect_uri, got %q", endpoint)
		}
	})
}

// Helper function for base64url encoding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
