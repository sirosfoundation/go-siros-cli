package oid4vci

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ProofGenerator generates JWT proofs for credential requests.
type ProofGenerator struct {
	keyID      string
	privateKey *ecdsa.PrivateKey
	publicJWK  map[string]interface{}
	algorithm  string
}

// NewProofGenerator creates a new proof generator.
func NewProofGenerator(keyID string, privateKey *ecdsa.PrivateKey, publicJWK map[string]interface{}, algorithm string) *ProofGenerator {
	if algorithm == "" {
		algorithm = "ES256"
	}
	return &ProofGenerator{
		keyID:      keyID,
		privateKey: privateKey,
		publicJWK:  publicJWK,
		algorithm:  algorithm,
	}
}

// GenerateProofJWT creates a JWT proof for OID4VCI credential requests.
// See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1
func (g *ProofGenerator) GenerateProofJWT(credentialIssuer string, cNonce string, clientID string) (string, error) {
	// For OID4VCI, the JWT header must include:
	// - typ: openid4vci-proof+jwt
	// - alg: the signing algorithm
	// - jwk: the public key (required when not using did or x5c)

	// Create signer with custom type header
	opts := &jose.SignerOptions{}
	opts.WithType("openid4vci-proof+jwt")

	// The JWK embedded in the header proves possession of the key
	opts.WithHeader("jwk", g.publicJWK)

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

	// Build proof claims
	// Required claims per OID4VCI spec:
	// - aud: credential issuer identifier
	// - iat: issuance time
	// - nonce: c_nonce value from the issuer
	// Optional:
	// - iss: client_id if available
	claims := map[string]interface{}{
		"aud":   credentialIssuer,
		"iat":   time.Now().Unix(),
		"nonce": cNonce,
	}

	// Include client_id as issuer if provided
	// This is optional but recommended
	if clientID != "" {
		claims["iss"] = clientID
	}

	// Encode claims
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Sign
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign proof JWT: %w", err)
	}

	return jws.CompactSerialize()
}

// CreateProof creates a Proof structure ready for use in a CredentialRequest.
func (g *ProofGenerator) CreateProof(credentialIssuer string, cNonce string, clientID string) (*Proof, error) {
	jwt, err := g.GenerateProofJWT(credentialIssuer, cNonce, clientID)
	if err != nil {
		return nil, err
	}

	return &Proof{
		ProofType: "jwt",
		JWT:       jwt,
	}, nil
}
