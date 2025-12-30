package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Status(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse any
		statusCode     int
		wantErr        bool
		wantStatus     string
		wantService    string
	}{
		{
			name: "successful response",
			serverResponse: map[string]any{
				"status":  "ok",
				"service": "go-wallet-backend",
			},
			statusCode:  200,
			wantErr:     false,
			wantStatus:  "ok",
			wantService: "go-wallet-backend",
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
				if r.URL.Path != "/status" {
					t.Errorf("expected /status, got %s", r.URL.Path)
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

			resp, err := client.Status(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Status() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if resp.Status != tt.wantStatus {
					t.Errorf("Status().Status = %q, want %q", resp.Status, tt.wantStatus)
				}
				if resp.Service != tt.wantService {
					t.Errorf("Status().Service = %q, want %q", resp.Service, tt.wantService)
				}
			}
		})
	}
}

func TestClient_FinishRegistration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/user/register-webauthn-finish" {
			t.Errorf("expected /user/register-webauthn-finish, got %s", r.URL.Path)
		}

		var body RegistrationFinishRequest
		json.NewDecoder(r.Body).Decode(&body)
		if body.ChallengeID != "challenge-123" {
			t.Errorf("expected challengeId 'challenge-123', got '%s'", body.ChallengeID)
		}
		if body.DisplayName != "Test User" {
			t.Errorf("expected displayName 'Test User', got '%s'", body.DisplayName)
		}

		resp := RegistrationFinishResponse{
			UUID:         "user-uuid-123",
			Token:        "session-token-abc",
			DisplayName:  "Test User",
			WebauthnRpId: "example.com",
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.FinishRegistration(ctx, &RegistrationFinishRequest{
		ChallengeID: "challenge-123",
		DisplayName: "Test User",
		Credential: map[string]interface{}{
			"id":   "cred-id",
			"type": "public-key",
		},
	})
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if resp.UUID != "user-uuid-123" {
		t.Errorf("UUID = %q, want %q", resp.UUID, "user-uuid-123")
	}
	if resp.Token != "session-token-abc" {
		t.Errorf("Token = %q, want %q", resp.Token, "session-token-abc")
	}
}

func TestClient_FinishLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/user/login-webauthn-finish" {
			t.Errorf("expected /user/login-webauthn-finish, got %s", r.URL.Path)
		}

		var body LoginFinishRequest
		json.NewDecoder(r.Body).Decode(&body)
		if body.ChallengeID != "login-challenge-456" {
			t.Errorf("expected challengeId 'login-challenge-456', got '%s'", body.ChallengeID)
		}

		resp := LoginFinishResponse{
			UUID:         "user-uuid-123",
			Token:        "new-session-token",
			DisplayName:  "Test User",
			WebauthnRpId: "example.com",
			PrivateData: map[string]interface{}{
				"$b64u": "ZW5jcnlwdGVkLWRhdGE",
			},
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.FinishLogin(ctx, &LoginFinishRequest{
		ChallengeID: "login-challenge-456",
		Credential: map[string]interface{}{
			"id":   "cred-id",
			"type": "public-key",
		},
	})
	if err != nil {
		t.Fatalf("FinishLogin() error = %v", err)
	}
	if resp.UUID != "user-uuid-123" {
		t.Errorf("UUID = %q, want %q", resp.UUID, "user-uuid-123")
	}
	if resp.Token != "new-session-token" {
		t.Errorf("Token = %q, want %q", resp.Token, "new-session-token")
	}
}

func TestClient_GetPresentations(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse any
		statusCode     int
		wantErr        bool
		wantCount      int
	}{
		{
			name: "successful response with presentations",
			serverResponse: map[string]any{
				"vp_list": []map[string]any{
					{
						"presentationIdentifier": "vp-1",
						"holderDID":              "did:example:holder",
						"presentation":           "eyJ...",
						"format":                 "jwt_vp_json",
						"includedCredentials":    []string{"cred-1", "cred-2"},
					},
				},
			},
			statusCode: 200,
			wantErr:    false,
			wantCount:  1,
		},
		{
			name: "empty presentations list",
			serverResponse: map[string]any{
				"vp_list": []any{},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/storage/vp" {
					t.Errorf("expected /storage/vp, got %s", r.URL.Path)
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

			resp, err := client.GetPresentations(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPresentations() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(resp) != tt.wantCount {
				t.Errorf("GetPresentations() got %d, want %d", len(resp), tt.wantCount)
			}
		})
	}
}

func TestClient_GetIssuers(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse any
		statusCode     int
		wantErr        bool
		wantCount      int
	}{
		{
			name: "successful response with issuers",
			serverResponse: []map[string]any{
				{
					"id":                         1,
					"credentialIssuerIdentifier": "https://issuer1.example.com",
					"visible":                    true,
				},
				{
					"id":                         2,
					"credentialIssuerIdentifier": "https://issuer2.example.com",
					"visible":                    false,
				},
			},
			statusCode: 200,
			wantErr:    false,
			wantCount:  2,
		},
		{
			name:           "empty issuers list",
			serverResponse: []any{},
			statusCode:     200,
			wantErr:        false,
			wantCount:      0,
		},
		{
			name:       "server error",
			statusCode: 500,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/issuer/all" {
					t.Errorf("expected /issuer/all, got %s", r.URL.Path)
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

			resp, err := client.GetIssuers(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIssuers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(resp) != tt.wantCount {
				t.Errorf("GetIssuers() got %d, want %d", len(resp), tt.wantCount)
			}
		})
	}
}

func TestClient_GetVerifiers(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse any
		statusCode     int
		wantErr        bool
		wantCount      int
	}{
		{
			name: "successful response with verifiers",
			serverResponse: []map[string]any{
				{
					"id":   1,
					"name": "Test Verifier",
					"url":  "https://verifier.example.com",
				},
			},
			statusCode: 200,
			wantErr:    false,
			wantCount:  1,
		},
		{
			name:           "empty verifiers list",
			serverResponse: []any{},
			statusCode:     200,
			wantErr:        false,
			wantCount:      0,
		},
		{
			name:       "server error",
			statusCode: 500,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/verifier/all" {
					t.Errorf("expected /verifier/all, got %s", r.URL.Path)
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

			resp, err := client.GetVerifiers(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVerifiers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(resp) != tt.wantCount {
				t.Errorf("GetVerifiers() got %d, want %d", len(resp), tt.wantCount)
			}
		})
	}
}

func TestClient_StoreCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/storage/vc" {
			t.Errorf("expected /storage/vc, got %s", r.URL.Path)
		}

		var body Credential
		json.NewDecoder(r.Body).Decode(&body)
		if body.ID != "cred-123" {
			t.Errorf("expected ID 'cred-123', got '%s'", body.ID)
		}

		w.WriteHeader(200)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.SetToken("test-token")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.StoreCredential(ctx, &Credential{
		ID:                         "cred-123",
		HolderDID:                  "did:example:holder",
		Credential:                 "eyJ...",
		Format:                     "vc+sd-jwt",
		CredentialConfigurationID:  "PersonIdentificationData",
		CredentialIssuerIdentifier: "https://issuer.example.com",
	})
	if err != nil {
		t.Errorf("StoreCredential() error = %v", err)
	}
}

func TestClient_ErrorResponses(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		wantErrSubstr string
	}{
		{
			name:          "bad request with message",
			statusCode:    400,
			responseBody:  `{"error": "invalid input"}`,
			wantErrSubstr: "400",
		},
		{
			name:          "internal server error",
			statusCode:    500,
			responseBody:  `{"error": "internal error"}`,
			wantErrSubstr: "500",
		},
		{
			name:          "not found",
			statusCode:    404,
			responseBody:  `{"error": "not found"}`,
			wantErrSubstr: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client := NewClient(server.URL)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := client.Status(ctx)
			if err == nil {
				t.Errorf("expected error, got nil")
				return
			}
			if !containsSubstring(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestClient_NoToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("expected no Authorization header, got '%s'", auth)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok","service":"test"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	// Don't set token

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Status(ctx)
	if err != nil {
		t.Errorf("Status() error = %v", err)
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
