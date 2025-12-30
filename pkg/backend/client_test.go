package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://example.com")
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.baseURL != "https://example.com" {
		t.Errorf("expected baseURL https://example.com, got %s", client.baseURL)
	}
}

func TestClient_SetToken(t *testing.T) {
	client := NewClient("https://example.com")
	client.SetToken("test-token")
	if client.GetToken() != "test-token" {
		t.Errorf("expected token test-token, got %s", client.GetToken())
	}
}

func TestClient_GetCredentials(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse any
		statusCode     int
		wantErr        bool
		wantCount      int
	}{
		{
			name: "successful response with credentials",
			serverResponse: map[string]any{
				"vc_list": []map[string]any{
					{
						"credentialIdentifier":       "cred-1",
						"holderDID":                  "did:example:holder",
						"credential":                 "eyJ...",
						"format":                     "vc+sd-jwt",
						"credentialConfigurationId":  "PersonIdentificationData",
						"credentialIssuerIdentifier": "https://issuer.example.com",
					},
					{
						"credentialIdentifier":       "cred-2",
						"holderDID":                  "did:example:holder",
						"credential":                 "eyJ...",
						"format":                     "jwt_vc_json",
						"credentialConfigurationId":  "VerifiableId",
						"credentialIssuerIdentifier": "https://issuer2.example.com",
					},
				},
			},
			statusCode: 200,
			wantErr:    false,
			wantCount:  2,
		},
		{
			name: "empty credentials list",
			serverResponse: map[string]any{
				"vc_list": []any{},
			},
			statusCode: 200,
			wantErr:    false,
			wantCount:  0,
		},
		{
			name:       "server error",
			statusCode: 500,
			wantErr:    true,
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
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if r.URL.Path != "/storage/vc" {
					t.Errorf("expected /storage/vc, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL)
			client.SetToken("test-token")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			creds, err := client.GetCredentials(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(creds) != tt.wantCount {
				t.Errorf("GetCredentials() got %d credentials, want %d", len(creds), tt.wantCount)
			}
		})
	}
}

func TestClient_GetCredential(t *testing.T) {
	tests := []struct {
		name           string
		credentialID   string
		serverResponse any
		statusCode     int
		wantErr        bool
	}{
		{
			name:         "successful response",
			credentialID: "cred-123",
			serverResponse: map[string]any{
				"credentialIdentifier":       "cred-123",
				"holderDID":                  "did:example:holder",
				"credential":                 "eyJ...",
				"format":                     "vc+sd-jwt",
				"credentialConfigurationId":  "PersonIdentificationData",
				"credentialIssuerIdentifier": "https://issuer.example.com",
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:         "not found",
			credentialID: "nonexistent",
			statusCode:   404,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/storage/vc/" + tt.credentialID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL)
			client.SetToken("test-token")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cred, err := client.GetCredential(ctx, tt.credentialID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cred.ID != tt.credentialID {
				t.Errorf("GetCredential() got ID %s, want %s", cred.ID, tt.credentialID)
			}
		})
	}
}

func TestClient_DeleteCredential(t *testing.T) {
	tests := []struct {
		name         string
		credentialID string
		statusCode   int
		wantErr      bool
	}{
		{
			name:         "successful delete",
			credentialID: "cred-123",
			statusCode:   200,
			wantErr:      false,
		},
		{
			name:         "not found",
			credentialID: "nonexistent",
			statusCode:   404,
			wantErr:      true,
		},
		{
			name:         "unauthorized",
			credentialID: "cred-123",
			statusCode:   401,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE, got %s", r.Method)
				}
				expectedPath := "/storage/vc/" + tt.credentialID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := NewClient(server.URL)
			client.SetToken("test-token")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := client.DeleteCredential(ctx, tt.credentialID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteCredential() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_StoreCredentials(t *testing.T) {
	tests := []struct {
		name       string
		creds      []*Credential
		statusCode int
		wantErr    bool
	}{
		{
			name: "successful store",
			creds: []*Credential{
				{
					ID:                         "cred-1",
					HolderDID:                  "did:example:holder",
					Credential:                 "eyJ...",
					Format:                     "vc+sd-jwt",
					CredentialConfigurationID:  "PersonIdentificationData",
					CredentialIssuerIdentifier: "https://issuer.example.com",
				},
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:       "server error",
			creds:      []*Credential{},
			statusCode: 500,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/storage/vc" {
					t.Errorf("expected /storage/vc, got %s", r.URL.Path)
				}

				// Verify request body
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if _, ok := body["credentials"]; !ok {
					t.Error("request body missing 'credentials' field")
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte("{}"))
			}))
			defer server.Close()

			client := NewClient(server.URL)
			client.SetToken("test-token")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := client.StoreCredentials(ctx, tt.creds)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_Authorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-secret-token" {
			t.Errorf("expected Authorization header 'Bearer my-secret-token', got '%s'", auth)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"vc_list":[]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.SetToken("my-secret-token")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetCredentials(ctx)
	if err != nil {
		t.Errorf("GetCredentials() error = %v", err)
	}
}

func TestClient_StartRegistration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/user/register-webauthn-begin" {
			t.Errorf("expected /user/register-webauthn-begin, got %s", r.URL.Path)
		}

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["displayName"] != "Test Wallet" {
			t.Errorf("expected displayName 'Test Wallet', got '%s'", body["displayName"])
		}

		resp := map[string]any{
			"challengeId": "challenge-123",
			"createOptions": map[string]any{
				"publicKey": map[string]any{
					"challenge": "dGVzdC1jaGFsbGVuZ2U",
					"rp": map[string]any{
						"id":   "example.com",
						"name": "Example",
					},
				},
			},
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.StartRegistration(ctx, "Test Wallet")
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	if resp.ChallengeID != "challenge-123" {
		t.Errorf("expected challengeId 'challenge-123', got '%s'", resp.ChallengeID)
	}
}

func TestClient_StartLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/user/login-webauthn-begin" {
			t.Errorf("expected /user/login-webauthn-begin, got %s", r.URL.Path)
		}

		resp := map[string]any{
			"challengeId": "login-challenge-456",
			"getOptions": map[string]any{
				"publicKey": map[string]any{
					"challenge": "bG9naW4tY2hhbGxlbmdl",
				},
			},
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.StartLogin(ctx)
	if err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if resp.ChallengeID != "login-challenge-456" {
		t.Errorf("expected challengeId 'login-challenge-456', got '%s'", resp.ChallengeID)
	}
}
