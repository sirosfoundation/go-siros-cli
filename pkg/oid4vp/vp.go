package oid4vp

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// VPGenerator creates Verifiable Presentation tokens.
type VPGenerator struct {
	keyID      string
	privateKey *ecdsa.PrivateKey
	publicJWK  map[string]interface{}
	algorithm  string
	holderDID  string
}

// NewVPGenerator creates a new VP generator.
func NewVPGenerator(keyID string, privateKey *ecdsa.PrivateKey, publicJWK map[string]interface{}, algorithm string, holderDID string) *VPGenerator {
	if algorithm == "" {
		algorithm = "ES256"
	}
	return &VPGenerator{
		keyID:      keyID,
		privateKey: privateKey,
		publicJWK:  publicJWK,
		algorithm:  algorithm,
		holderDID:  holderDID,
	}
}

// CreateVPToken creates a VP token containing the given credentials.
// This creates a JWT-based VP for credentials in jwt_vc or jwt_vc_json format.
// For SD-JWT credentials, use CreateSDJWTPresentation instead.
func (g *VPGenerator) CreateVPToken(credentials []string, nonce string, audience string) (string, error) {
	// Create signer with JWT type
	opts := &jose.SignerOptions{}
	opts.WithType("vp+jwt")
	opts.WithHeader("kid", g.keyID)

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(g.algorithm),
			Key:       g.privateKey,
		},
		opts,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Build VP claims
	// See: https://www.w3.org/TR/vc-data-model/#presentations-0
	now := time.Now()
	vpClaims := map[string]interface{}{
		"iss":   g.holderDID,
		"aud":   audience,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(), // Short-lived VP
		"nonce": nonce,
		"vp": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": credentials,
		},
	}

	// If holder DID is available, add holder claim to VP
	if g.holderDID != "" {
		vpClaims["vp"].(map[string]interface{})["holder"] = g.holderDID
	}

	// Encode claims
	payload, err := json.Marshal(vpClaims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal VP claims: %w", err)
	}

	// Sign
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign VP: %w", err)
	}

	return jws.CompactSerialize()
}

// CreateSDJWTPresentation creates a presentation for SD-JWT credentials.
// The presentation includes the SD-JWT credential and an optional key binding JWT.
// The format is: <sd-jwt>~<key-binding-jwt>
func (g *VPGenerator) CreateSDJWTPresentation(sdjwt string, nonce string, audience string) (string, error) {
	// For SD-JWT, the presentation format is:
	// <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>
	// where KB-JWT (Key Binding JWT) proves holder possession

	// Create key binding JWT
	kbOpts := &jose.SignerOptions{}
	kbOpts.WithType("kb+jwt")

	kbSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(g.algorithm),
			Key:       g.privateKey,
		},
		kbOpts,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create KB signer: %w", err)
	}

	// Key binding JWT claims
	now := time.Now()
	kbClaims := map[string]interface{}{
		"iat":   now.Unix(),
		"aud":   audience,
		"nonce": nonce,
	}

	// Encode and sign key binding JWT
	kbPayload, err := json.Marshal(kbClaims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal KB claims: %w", err)
	}

	kbJWS, err := kbSigner.Sign(kbPayload)
	if err != nil {
		return "", fmt.Errorf("failed to sign KB JWT: %w", err)
	}

	kbJWT, err := kbJWS.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize KB JWT: %w", err)
	}

	// Append key binding JWT to SD-JWT
	// If SD-JWT already ends with ~, just append the KB-JWT
	// Otherwise, add ~ and append
	presentation := sdjwt
	if len(presentation) > 0 && presentation[len(presentation)-1] != '~' {
		presentation += "~"
	}
	presentation += kbJWT

	return presentation, nil
}
