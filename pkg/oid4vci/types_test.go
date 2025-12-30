package oid4vci

import (
	"encoding/json"
	"testing"
)

func TestCredentialOffer_JSON(t *testing.T) {
	offer := &CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"PersonIdentificationData", "VerifiableId"},
	}

	data, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CredentialOffer
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("CredentialIssuer = %q, want %q", parsed.CredentialIssuer, "https://issuer.example.com")
	}
	if len(parsed.CredentialConfigurationIDs) != 2 {
		t.Errorf("CredentialConfigurationIDs length = %d, want 2", len(parsed.CredentialConfigurationIDs))
	}
}

func TestCredentialOfferGrants_PreAuthorized(t *testing.T) {
	grants := &CredentialOfferGrants{
		PreAuthorizedCode: &PreAuthorizedCodeGrant{
			PreAuthorizedCode:   "test-pre-auth-code",
			AuthorizationServer: "https://auth.example.com",
			TxCode: &TxCode{
				InputMode:   "numeric",
				Length:      6,
				Description: "Enter the 6-digit code",
			},
		},
	}

	data, err := json.Marshal(grants)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CredentialOfferGrants
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.PreAuthorizedCode == nil {
		t.Fatal("PreAuthorizedCode should not be nil")
	}
	if parsed.PreAuthorizedCode.PreAuthorizedCode != "test-pre-auth-code" {
		t.Errorf("PreAuthorizedCode = %q, want %q", parsed.PreAuthorizedCode.PreAuthorizedCode, "test-pre-auth-code")
	}
	if parsed.PreAuthorizedCode.TxCode.Length != 6 {
		t.Errorf("TxCode.Length = %d, want 6", parsed.PreAuthorizedCode.TxCode.Length)
	}
}

func TestCredentialOfferGrants_AuthorizationCode(t *testing.T) {
	grants := &CredentialOfferGrants{
		AuthorizationCode: &AuthorizationCodeGrant{
			IssuerState: "state-123",
		},
	}

	data, err := json.Marshal(grants)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CredentialOfferGrants
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.AuthorizationCode == nil {
		t.Fatal("AuthorizationCode should not be nil")
	}
	if parsed.AuthorizationCode.IssuerState != "state-123" {
		t.Errorf("IssuerState = %q, want %q", parsed.AuthorizationCode.IssuerState, "state-123")
	}
}

func TestIssuerMetadata_JSON(t *testing.T) {
	metadata := &IssuerMetadata{
		CredentialIssuer:        "https://issuer.example.com",
		AuthorizationServers:    []string{"https://auth.example.com"},
		CredentialEndpoint:      "https://issuer.example.com/credential",
		BatchCredentialEndpoint: "https://issuer.example.com/batch",
		CredentialConfigurationsSupported: map[string]CredentialConfiguration{
			"PersonId": {
				Format: "vc+sd-jwt",
				Scope:  "person_id",
				VCT:    "PersonIdentificationData",
			},
		},
		Display: []IssuerDisplay{
			{
				Name:   "Example Issuer",
				Locale: "en",
			},
		},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed IssuerMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("CredentialIssuer = %q", parsed.CredentialIssuer)
	}
	if len(parsed.CredentialConfigurationsSupported) != 1 {
		t.Errorf("CredentialConfigurationsSupported length = %d, want 1", len(parsed.CredentialConfigurationsSupported))
	}
}

func TestCredentialConfiguration_JSON(t *testing.T) {
	config := &CredentialConfiguration{
		Format:                      "vc+sd-jwt",
		Scope:                       "person_id",
		CryptographicBindingMethods: []string{"jwk"},
		CredentialSigningAlgValues:  []string{"ES256", "ES384"},
		ProofTypesSupported: map[string]ProofType{
			"jwt": {ProofSigningAlgValues: []string{"ES256"}},
		},
		VCT:     "PersonIdentificationData",
		Doctype: "",
		Display: []CredentialDisplay{
			{
				Name:            "Person ID",
				Locale:          "en",
				Description:     "Personal identification credential",
				BackgroundColor: "#FFFFFF",
				TextColor:       "#000000",
			},
		},
		Claims: map[string]ClaimConfig{
			"given_name": {
				Mandatory: true,
				ValueType: "string",
				Display: []ClaimDisplay{
					{Name: "Given Name", Locale: "en"},
				},
			},
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CredentialConfiguration
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Format != "vc+sd-jwt" {
		t.Errorf("Format = %q, want %q", parsed.Format, "vc+sd-jwt")
	}
	if len(parsed.Claims) != 1 {
		t.Errorf("Claims length = %d, want 1", len(parsed.Claims))
	}
	if !parsed.Claims["given_name"].Mandatory {
		t.Error("given_name claim should be mandatory")
	}
}

func TestTokenResponse_JSON(t *testing.T) {
	resp := &TokenResponse{
		AccessToken:     "access-token-123",
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		CNonce:          "nonce-456",
		CNonceExpiresIn: 86400,
		RefreshToken:    "refresh-token-789",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed TokenResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %q", parsed.AccessToken)
	}
	if parsed.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", parsed.ExpiresIn)
	}
}

func TestCredentialRequest_JSON(t *testing.T) {
	req := &CredentialRequest{
		Format:                    "vc+sd-jwt",
		CredentialConfigurationID: "PersonId",
		Proof: &Proof{
			ProofType: "jwt",
			JWT:       "eyJ...",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CredentialRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Format != "vc+sd-jwt" {
		t.Errorf("Format = %q", parsed.Format)
	}
	if parsed.Proof == nil {
		t.Fatal("Proof should not be nil")
	}
	if parsed.Proof.ProofType != "jwt" {
		t.Errorf("ProofType = %q", parsed.Proof.ProofType)
	}
}

func TestCredentialResponse_JSON(t *testing.T) {
	tests := []struct {
		name string
		resp CredentialResponse
	}{
		{
			name: "with credential string",
			resp: CredentialResponse{
				Credential:     "eyJ...",
				CNonce:         "nonce-123",
				NotificationID: "notif-456",
			},
		},
		{
			name: "with transaction_id (deferred)",
			resp: CredentialResponse{
				TransactionID: "tx-789",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var parsed CredentialResponse
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
		})
	}
}

func TestOAuthServerMetadata_JSON(t *testing.T) {
	metadata := &OAuthServerMetadata{
		Issuer:                             "https://auth.example.com",
		AuthorizationEndpoint:              "https://auth.example.com/authorize",
		TokenEndpoint:                      "https://auth.example.com/token",
		PushedAuthorizationRequestEndpoint: "https://auth.example.com/par",
		ScopesSupported:                    []string{"openid", "person_id"},
		ResponseTypesSupported:             []string{"code"},
		CodeChallengeMethodsSupported:      []string{"S256"},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed OAuthServerMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q", parsed.Issuer)
	}
	if len(parsed.ScopesSupported) != 2 {
		t.Errorf("ScopesSupported length = %d, want 2", len(parsed.ScopesSupported))
	}
}
