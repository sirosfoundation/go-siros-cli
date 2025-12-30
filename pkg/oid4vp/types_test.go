package oid4vp

import (
	"encoding/json"
	"testing"
)

func TestResponseModeConstants(t *testing.T) {
	tests := []struct {
		mode ResponseMode
		want string
	}{
		{ResponseModeDirectPost, "direct_post"},
		{ResponseModeDirectPostJWT, "direct_post.jwt"},
		{ResponseModeFragment, "fragment"},
		{ResponseModeQuery, "query"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("ResponseMode %v = %q, want %q", tt.mode, tt.mode, tt.want)
		}
	}
}

func TestAuthorizationRequest_JSON(t *testing.T) {
	req := &AuthorizationRequest{
		ClientID:     "client-123",
		ResponseURI:  "https://verifier.example.com/callback",
		Nonce:        "nonce-456",
		State:        "state-789",
		ResponseType: "vp_token",
		ResponseMode: ResponseModeDirectPost,
		PresentationDefinition: &PresentationDefinition{
			ID:   "pd-1",
			Name: "Test Presentation",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed AuthorizationRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ClientID != "client-123" {
		t.Errorf("ClientID = %q", parsed.ClientID)
	}
	if parsed.ResponseMode != ResponseModeDirectPost {
		t.Errorf("ResponseMode = %q", parsed.ResponseMode)
	}
}

func TestPresentationDefinition_JSON(t *testing.T) {
	pd := &PresentationDefinition{
		ID:      "pd-123",
		Name:    "ID Verification",
		Purpose: "Verify your identity",
		InputDescriptors: []InputDescriptor{
			{
				ID:      "desc-1",
				Name:    "Person ID",
				Purpose: "We need to verify your identity",
				Format: map[string]interface{}{
					"vc+sd-jwt": map[string]interface{}{
						"alg": []string{"ES256"},
					},
				},
				Constraints: &Constraints{
					LimitDisclosure: "required",
					Fields: []Field{
						{
							ID:             "field-1",
							Name:           "Given Name",
							Path:           []string{"$.credentialSubject.given_name", "$.vc.given_name"},
							Purpose:        "To verify your first name",
							IntentToRetain: true,
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(pd)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed PresentationDefinition
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ID != "pd-123" {
		t.Errorf("ID = %q", parsed.ID)
	}
	if len(parsed.InputDescriptors) != 1 {
		t.Fatalf("InputDescriptors length = %d, want 1", len(parsed.InputDescriptors))
	}
	if parsed.InputDescriptors[0].Constraints == nil {
		t.Fatal("Constraints should not be nil")
	}
	if len(parsed.InputDescriptors[0].Constraints.Fields) != 1 {
		t.Errorf("Fields length = %d, want 1", len(parsed.InputDescriptors[0].Constraints.Fields))
	}
}

func TestPresentationSubmission_JSON(t *testing.T) {
	ps := &PresentationSubmission{
		ID:           "ps-123",
		DefinitionID: "pd-456",
		DescriptorMap: []DescriptorMapItem{
			{
				ID:     "desc-1",
				Format: "vc+sd-jwt",
				Path:   "$",
			},
			{
				ID:     "desc-2",
				Format: "jwt_vp_json",
				Path:   "$[0]",
				PathNested: &DescriptorMapItem{
					ID:     "nested-1",
					Format: "jwt_vc_json",
					Path:   "$.verifiableCredential[0]",
				},
			},
		},
	}

	data, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed PresentationSubmission
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ID != "ps-123" {
		t.Errorf("ID = %q", parsed.ID)
	}
	if len(parsed.DescriptorMap) != 2 {
		t.Fatalf("DescriptorMap length = %d, want 2", len(parsed.DescriptorMap))
	}
	if parsed.DescriptorMap[1].PathNested == nil {
		t.Error("PathNested should not be nil")
	}
}

func TestClientMetadata_JSON(t *testing.T) {
	cm := &ClientMetadata{
		JWKS: &JWKS{
			Keys: []json.RawMessage{
				json.RawMessage(`{"kty":"EC","crv":"P-256"}`),
			},
		},
		AuthorizationEncryptedResponseAlg: "ECDH-ES",
		AuthorizationEncryptedResponseEnc: "A256GCM",
	}

	data, err := json.Marshal(cm)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ClientMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.AuthorizationEncryptedResponseAlg != "ECDH-ES" {
		t.Errorf("AuthorizationEncryptedResponseAlg = %q", parsed.AuthorizationEncryptedResponseAlg)
	}
	if parsed.JWKS == nil || len(parsed.JWKS.Keys) != 1 {
		t.Error("JWKS.Keys should have 1 element")
	}
}

func TestVerifierResponse_JSON(t *testing.T) {
	tests := []struct {
		name string
		resp VerifierResponse
	}{
		{
			name: "success with redirect",
			resp: VerifierResponse{
				RedirectURI: "https://verifier.example.com/success",
			},
		},
		{
			name: "error response",
			resp: VerifierResponse{
				Error:     "invalid_request",
				ErrorDesc: "Missing required parameter",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var parsed VerifierResponse
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
		})
	}
}

func TestCredentialMatch_Fields(t *testing.T) {
	match := CredentialMatch{
		DescriptorID:   "desc-1",
		CredentialID:   "cred-123",
		CredentialData: "eyJ...",
		Format:         "vc+sd-jwt",
		MatchedFields: []MatchedField{
			{
				Name:    "given_name",
				Path:    "$.credentialSubject.given_name",
				Purpose: "Identity verification",
			},
		},
	}

	if match.DescriptorID != "desc-1" {
		t.Errorf("DescriptorID = %q", match.DescriptorID)
	}
	if len(match.MatchedFields) != 1 {
		t.Errorf("MatchedFields length = %d, want 1", len(match.MatchedFields))
	}
	if match.MatchedFields[0].Name != "given_name" {
		t.Errorf("MatchedField.Name = %q", match.MatchedFields[0].Name)
	}
}

func TestInputDescriptor_EmptyConstraints(t *testing.T) {
	desc := InputDescriptor{
		ID:   "desc-no-constraints",
		Name: "Simple descriptor",
	}

	data, err := json.Marshal(desc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed InputDescriptor
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Constraints != nil {
		t.Error("Constraints should be nil")
	}
}

func TestField_WithFilter(t *testing.T) {
	field := Field{
		Path:   []string{"$.type"},
		Filter: map[string]interface{}{"const": "PersonIdentificationData"},
	}

	data, err := json.Marshal(field)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Field
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Filter == nil {
		t.Error("Filter should not be nil")
	}
}
