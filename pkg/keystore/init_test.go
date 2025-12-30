package keystore

import (
	"encoding/json"
	"testing"
)

func TestInitPRF_InvalidInputs(t *testing.T) {
	// Test with empty credential ID - should still work
	_, err := InitPRF([]byte{}, []byte("prf-output-32-bytes-long--------"), []byte("salt"), []string{"usb"})
	if err != nil {
		t.Errorf("InitPRF with empty credentialID should work, got: %v", err)
	}
}

func TestWalletStateContainer_Empty(t *testing.T) {
	container := &WalletStateContainer{
		S: WalletState{
			Keypairs: []StoredKeypair{},
		},
	}

	if len(container.S.Keypairs) != 0 {
		t.Error("Expected empty keypairs")
	}
}

func TestWalletStateContainer_WithKeypairs(t *testing.T) {
	container := &WalletStateContainer{
		S: WalletState{
			Keypairs: []StoredKeypair{
				{
					KID: "key-1",
					Keypair: KeypairData{
						DID:       "did:example:1",
						Algorithm: "ES256",
						PublicKey: map[string]interface{}{
							"kty": "EC",
							"crv": "P-256",
						},
					},
				},
				{
					KID: "key-2",
					Keypair: KeypairData{
						DID:       "did:example:2",
						Algorithm: "ES384",
						PublicKey: map[string]interface{}{
							"kty": "EC",
							"crv": "P-384",
						},
					},
				},
			},
		},
	}

	if len(container.S.Keypairs) != 2 {
		t.Errorf("Expected 2 keypairs, got %d", len(container.S.Keypairs))
	}
	if container.S.Keypairs[0].KID != "key-1" {
		t.Errorf("Expected KID 'key-1', got '%s'", container.S.Keypairs[0].KID)
	}
}

func TestEncryptedContainer_JSON(t *testing.T) {
	container := &EncryptedContainer{
		JWE: "test-jwe-string",
	}

	// Marshal
	data, err := json.Marshal(container)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal
	var parsed EncryptedContainer
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.JWE != "test-jwe-string" {
		t.Errorf("JWE = %q, want %q", parsed.JWE, "test-jwe-string")
	}
}

func TestTaggedBinary_Empty(t *testing.T) {
	tb := TaggedBinary([]byte{})

	data, err := json.Marshal(tb)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Should produce {"$b64u":""}
	var parsed map[string]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed["$b64u"] != "" {
		t.Errorf("Expected empty string, got %q", parsed["$b64u"])
	}
}

func TestTaggedBinary_BinaryData(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0xff}
	tb := TaggedBinary(data)

	marshaled, err := json.Marshal(tb)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed TaggedBinary
	if err := json.Unmarshal(marshaled, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !BytesEqual(parsed, data) {
		t.Errorf("Roundtrip failed: got %v, want %v", parsed, data)
	}
}

func TestAesKeyGenParams_JSON(t *testing.T) {
	params := AesKeyGenParams{
		Name:   "AES-GCM",
		Length: 256,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed AesKeyGenParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Name != "AES-GCM" {
		t.Errorf("Name = %q, want %q", parsed.Name, "AES-GCM")
	}
	if parsed.Length != 256 {
		t.Errorf("Length = %d, want %d", parsed.Length, 256)
	}
}

func TestEcKeyAlgorithm_JSON(t *testing.T) {
	algo := EcKeyAlgorithm{
		Name:       "ECDH",
		NamedCurve: "P-256",
	}

	data, err := json.Marshal(algo)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed EcKeyAlgorithm
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Name != "ECDH" {
		t.Errorf("Name = %q, want %q", parsed.Name, "ECDH")
	}
	if parsed.NamedCurve != "P-256" {
		t.Errorf("NamedCurve = %q, want %q", parsed.NamedCurve, "P-256")
	}
}

func TestAesGcmParams_JSON(t *testing.T) {
	params := AesGcmParams{
		Name: "AES-GCM",
		IV:   TaggedBinary([]byte("test-iv")),
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed AesGcmParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Name != "AES-GCM" {
		t.Errorf("Name = %q, want %q", parsed.Name, "AES-GCM")
	}
}

func TestImportKeyInfo_JSON(t *testing.T) {
	info := ImportKeyInfo{
		Format:  "raw",
		KeyData: TaggedBinary([]byte("key-data")),
		Algorithm: EcKeyAlgorithm{
			Name:       "ECDH",
			NamedCurve: "P-256",
		},
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ImportKeyInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Format != "raw" {
		t.Errorf("Format = %q, want %q", parsed.Format, "raw")
	}
}

func TestKeypairData_JSON(t *testing.T) {
	kp := KeypairData{
		DID:       "did:example:123",
		Algorithm: "ES256",
		PublicKey: map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "base64url-x",
			"y":   "base64url-y",
		},
		PrivateKey: map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "base64url-x",
			"y":   "base64url-y",
			"d":   "base64url-d",
		},
	}

	data, err := json.Marshal(kp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed KeypairData
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.DID != "did:example:123" {
		t.Errorf("DID = %q, want %q", parsed.DID, "did:example:123")
	}
	if parsed.Algorithm != "ES256" {
		t.Errorf("Algorithm = %q, want %q", parsed.Algorithm, "ES256")
	}
}

func TestStoredKeypair_JSON(t *testing.T) {
	kp := StoredKeypair{
		KID: "key-id-123",
		Keypair: KeypairData{
			DID:       "did:example:abc",
			Algorithm: "ES256",
		},
	}

	data, err := json.Marshal(kp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed StoredKeypair
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.KID != "key-id-123" {
		t.Errorf("KID = %q, want %q", parsed.KID, "key-id-123")
	}
}

func TestWalletState_JSON(t *testing.T) {
	state := WalletState{
		Keypairs: []StoredKeypair{
			{
				KID: "key-1",
				Keypair: KeypairData{
					DID:       "did:example:1",
					Algorithm: "ES256",
				},
			},
		},
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed WalletState
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Keypairs) != 1 {
		t.Errorf("Keypairs length = %d, want 1", len(parsed.Keypairs))
	}
}

func TestByteEquals(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []byte{}, []byte{}, true},
		{"equal", []byte("hello"), []byte("hello"), true},
		{"different length", []byte("hello"), []byte("hi"), false},
		{"different content", []byte("hello"), []byte("world"), false},
		{"one nil", nil, []byte("hi"), false},
		{"other nil", []byte("hi"), nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BytesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("BytesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
