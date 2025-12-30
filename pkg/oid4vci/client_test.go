package oid4vci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

func TestParseCredentialOfferURL_DirectOffer(t *testing.T) {
	client := NewClient()

	offer := CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"PersonIdentificationData"},
		Grants: &CredentialOfferGrants{
			PreAuthorizedCode: &PreAuthorizedCodeGrant{
				PreAuthorizedCode: "test-code-123",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)

	offerURL := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	parsed, err := client.ParseCredentialOfferURL(offerURL)
	if err != nil {
		t.Fatalf("ParseCredentialOfferURL failed: %v", err)
	}

	if parsed.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("expected issuer https://issuer.example.com, got %s", parsed.CredentialIssuer)
	}
	if len(parsed.CredentialConfigurationIDs) != 1 || parsed.CredentialConfigurationIDs[0] != "PersonIdentificationData" {
		t.Errorf("unexpected credential configuration IDs: %v", parsed.CredentialConfigurationIDs)
	}
	if parsed.Grants == nil || parsed.Grants.PreAuthorizedCode == nil {
		t.Error("expected pre-authorized code grant")
	}
	if parsed.Grants.PreAuthorizedCode.PreAuthorizedCode != "test-code-123" {
		t.Errorf("expected pre-authorized code test-code-123, got %s", parsed.Grants.PreAuthorizedCode.PreAuthorizedCode)
	}
}

func TestParseCredentialOfferURL_HTTPSOffer(t *testing.T) {
	client := NewClient()

	offer := CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"VerifiableId"},
	}
	offerJSON, _ := json.Marshal(offer)

	offerURL := "https://issuer.example.com/offer?credential_offer=" + url.QueryEscape(string(offerJSON))

	parsed, err := client.ParseCredentialOfferURL(offerURL)
	if err != nil {
		t.Fatalf("ParseCredentialOfferURL failed: %v", err)
	}

	if parsed.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("expected issuer https://issuer.example.com, got %s", parsed.CredentialIssuer)
	}
}

func TestParseCredentialOfferURL_OfferURI(t *testing.T) {
	// Set up mock server for credential offer
	offer := CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"PersonIdentificationData"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(offer)
	}))
	defer server.Close()

	client := NewClient()

	offerURL := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(server.URL)

	parsed, err := client.ParseCredentialOfferURL(offerURL)
	if err != nil {
		t.Fatalf("ParseCredentialOfferURL failed: %v", err)
	}

	if parsed.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("expected issuer https://issuer.example.com, got %s", parsed.CredentialIssuer)
	}
}

func TestParseCredentialOfferURL_InvalidURL(t *testing.T) {
	client := NewClient()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "invalid scheme",
			url:     "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "no offer or uri",
			url:     "openid-credential-offer://",
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			url:     "openid-credential-offer://?credential_offer={invalid}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ParseCredentialOfferURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialOfferURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetIssuerMetadata(t *testing.T) {
	metadata := IssuerMetadata{
		CredentialIssuer:   "https://issuer.example.com",
		CredentialEndpoint: "https://issuer.example.com/credential",
		CredentialConfigurationsSupported: map[string]CredentialConfiguration{
			"PersonIdentificationData": {
				Format: "vc+sd-jwt",
				VCT:    "urn:credential:PersonIdentificationData",
				Display: []CredentialDisplay{
					{Name: "Person ID", Locale: "en"},
				},
			},
		},
		Display: []IssuerDisplay{
			{Name: "Example Issuer", Locale: "en"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			t.Errorf("expected path /.well-known/openid-credential-issuer, got %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.GetIssuerMetadata(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetIssuerMetadata failed: %v", err)
	}

	if result.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("expected issuer https://issuer.example.com, got %s", result.CredentialIssuer)
	}
	if result.CredentialEndpoint != "https://issuer.example.com/credential" {
		t.Errorf("expected credential endpoint https://issuer.example.com/credential, got %s", result.CredentialEndpoint)
	}
	if _, ok := result.CredentialConfigurationsSupported["PersonIdentificationData"]; !ok {
		t.Error("expected PersonIdentificationData in supported configurations")
	}
}

func TestGetIssuerMetadata_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("Not found"))
	}))
	defer server.Close()

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetIssuerMetadata(ctx, server.URL)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestGetOAuthServerMetadata(t *testing.T) {
	metadata := OAuthServerMetadata{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			t.Errorf("expected path /.well-known/oauth-authorization-server, got %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.GetOAuthServerMetadata(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetOAuthServerMetadata failed: %v", err)
	}

	if result.TokenEndpoint != "https://auth.example.com/token" {
		t.Errorf("expected token endpoint https://auth.example.com/token, got %s", result.TokenEndpoint)
	}
}

func TestExchangePreAuthorizedCode(t *testing.T) {
	tokenResp := TokenResponse{
		AccessToken:     "access-token-123",
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		CNonce:          "c-nonce-456",
		CNonceExpiresIn: 300,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
		}

		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
			t.Errorf("expected grant_type pre-authorized_code, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("pre-authorized_code") != "pre-auth-code-789" {
			t.Errorf("expected pre-authorized_code pre-auth-code-789, got %s", r.Form.Get("pre-authorized_code"))
		}
		if r.Form.Get("tx_code") != "1234" {
			t.Errorf("expected tx_code 1234, got %s", r.Form.Get("tx_code"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	}))
	defer server.Close()

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.ExchangePreAuthorizedCode(ctx, server.URL, "pre-auth-code-789", "1234", "")
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode failed: %v", err)
	}

	if result.AccessToken != "access-token-123" {
		t.Errorf("expected access token access-token-123, got %s", result.AccessToken)
	}
	if result.CNonce != "c-nonce-456" {
		t.Errorf("expected c_nonce c-nonce-456, got %s", result.CNonce)
	}
}

func TestExchangeAuthorizationCode(t *testing.T) {
	tokenResp := TokenResponse{
		AccessToken: "access-token-from-auth",
		TokenType:   "Bearer",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
		}

		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type authorization_code, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "auth-code-xyz" {
			t.Errorf("expected code auth-code-xyz, got %s", r.Form.Get("code"))
		}
		if r.Form.Get("redirect_uri") != "https://wallet.example.com/callback" {
			t.Errorf("expected redirect_uri, got %s", r.Form.Get("redirect_uri"))
		}
		if r.Form.Get("code_verifier") != "verifier-123" {
			t.Errorf("expected code_verifier verifier-123, got %s", r.Form.Get("code_verifier"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	}))
	defer server.Close()

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.ExchangeAuthorizationCode(ctx, server.URL, "auth-code-xyz", "https://wallet.example.com/callback", "client-id", "verifier-123")
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode failed: %v", err)
	}

	if result.AccessToken != "access-token-from-auth" {
		t.Errorf("expected access token access-token-from-auth, got %s", result.AccessToken)
	}
}

func TestRequestCredential(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse any
		statusCode     int
		wantErr        bool
	}{
		{
			name: "successful credential (string)",
			serverResponse: map[string]any{
				"credential": "eyJ0eXAiOiJ2YytzZC1qd3QiLC...",
				"c_nonce":    "new-nonce",
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name: "deferred issuance",
			serverResponse: map[string]any{
				"transaction_id": "tx-123",
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:       "unauthorized",
			statusCode: 401,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.Header.Get("Authorization") != "Bearer test-access-token" {
					t.Errorf("expected Authorization header")
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type application/json")
				}

				w.WriteHeader(tt.statusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewClient()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			credReq := &CredentialRequest{
				CredentialConfigurationID: "PersonIdentificationData",
			}

			result, err := client.RequestCredential(ctx, server.URL, "test-access-token", credReq)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequestCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.name == "successful credential (string)" {
				if cred, ok := result.Credential.(string); !ok || cred == "" {
					t.Error("expected credential string in response")
				}
			}
			if !tt.wantErr && tt.name == "deferred issuance" {
				if result.TransactionID != "tx-123" {
					t.Errorf("expected transaction_id tx-123, got %s", result.TransactionID)
				}
			}
		})
	}
}

func TestCredentialOfferWithTxCode(t *testing.T) {
	client := NewClient()

	offer := CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"PersonIdentificationData"},
		Grants: &CredentialOfferGrants{
			PreAuthorizedCode: &PreAuthorizedCodeGrant{
				PreAuthorizedCode: "test-code",
				TxCode: &TxCode{
					InputMode:   "numeric",
					Length:      4,
					Description: "Please enter the 4-digit code from your email",
				},
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)

	offerURL := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	parsed, err := client.ParseCredentialOfferURL(offerURL)
	if err != nil {
		t.Fatalf("ParseCredentialOfferURL failed: %v", err)
	}

	if parsed.Grants.PreAuthorizedCode.TxCode == nil {
		t.Fatal("expected tx_code in grant")
	}
	if parsed.Grants.PreAuthorizedCode.TxCode.InputMode != "numeric" {
		t.Errorf("expected input_mode numeric, got %s", parsed.Grants.PreAuthorizedCode.TxCode.InputMode)
	}
	if parsed.Grants.PreAuthorizedCode.TxCode.Length != 4 {
		t.Errorf("expected length 4, got %d", parsed.Grants.PreAuthorizedCode.TxCode.Length)
	}
}
