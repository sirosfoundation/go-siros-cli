package keystore

import (
	"encoding/json"
	"testing"
)

func TestTaggedBinaryUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "tagged format",
			input:    `{"$b64u": "SGVsbG8gV29ybGQ"}`,
			expected: []byte("Hello World"),
		},
		{
			name:     "plain base64url string",
			input:    `"SGVsbG8gV29ybGQ"`,
			expected: []byte("Hello World"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tb TaggedBinary
			if err := json.Unmarshal([]byte(tt.input), &tb); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if !BytesEqual(tb, tt.expected) {
				t.Errorf("got %q, want %q", tb, tt.expected)
			}
		})
	}
}

func TestTaggedBinaryMarshal(t *testing.T) {
	tb := TaggedBinary([]byte("Hello World"))

	data, err := json.Marshal(tb)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	expected := `{"$b64u":"SGVsbG8gV29ybGQ"}`
	if string(data) != expected {
		t.Errorf("got %s, want %s", data, expected)
	}
}

func TestEncryptedContainerParse(t *testing.T) {
	// Sample container JSON with tagged binary
	containerJSON := `{
		"jwe": "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJUZXN0SVYiLCJ0YWciOiJUZXN0VGFnIn0.key.iv.ciphertext.tag",
		"mainKey": {
			"publicKey": {
				"importKey": {
					"format": "raw",
					"keyData": {"$b64u": "BFRleHRQdWJsaWNLZXk"},
					"algorithm": {"name": "ECDH", "namedCurve": "P-256"}
				}
			},
			"unwrapKey": {
				"format": "raw",
				"unwrapAlgo": "AES-KW",
				"unwrappedKeyAlgo": {"name": "AES-GCM", "length": 256}
			}
		},
		"prfKeys": [
			{
				"credentialId": {"$b64u": "Y3JlZGVudGlhbC0x"},
				"prfSalt": {"$b64u": "c2FsdDE"},
				"hkdfSalt": {"$b64u": "aGtkZnNhbHQx"},
				"hkdfInfo": {"$b64u": "aGtkZmluZm8x"},
				"keypair": {
					"publicKey": {
						"importKey": {
							"format": "raw",
							"keyData": {"$b64u": "cHVibGljMQ"},
							"algorithm": {"name": "ECDH", "namedCurve": "P-256"}
						}
					},
					"privateKey": {
						"unwrapKey": {
							"format": "jwk",
							"wrappedKey": {"$b64u": "d3JhcHBlZDE"},
							"unwrapAlgo": {"name": "AES-GCM", "iv": {"$b64u": "aXYx"}},
							"unwrappedKeyAlgo": {"name": "ECDH", "namedCurve": "P-256"}
						}
					}
				},
				"unwrapKey": {
					"wrappedKey": {"$b64u": "bWFpbndyYXBwZWQx"},
					"unwrappingKey": {
						"deriveKey": {
							"algorithm": {"name": "ECDH"},
							"derivedKeyAlgorithm": {"name": "AES-KW", "length": 256}
						}
					}
				}
			}
		]
	}`

	container, err := ParseEncryptedContainer([]byte(containerJSON))
	if err != nil {
		t.Fatalf("ParseEncryptedContainer failed: %v", err)
	}

	// Verify the container was parsed correctly
	if len(container.PRFKeys) != 1 {
		t.Errorf("expected 1 PRF key, got %d", len(container.PRFKeys))
	}

	// Check credential ID
	expectedCredID := []byte("credential-1")
	if !BytesEqual([]byte(container.PRFKeys[0].CredentialID), expectedCredID) {
		t.Errorf("credentialId mismatch: got %q, want %q", container.PRFKeys[0].CredentialID, expectedCredID)
	}

	// Test FindPRFKeyByCredentialID
	found := container.FindPRFKeyByCredentialID(expectedCredID)
	if found == nil {
		t.Error("FindPRFKeyByCredentialID returned nil")
	}

	// Test GetPRFKeyInfos
	infos := container.GetPRFKeyInfos()
	if len(infos) != 1 {
		t.Errorf("expected 1 PRF key info, got %d", len(infos))
	}
}

func TestAESKeyUnwrap(t *testing.T) {
	// Test vector from RFC 3394
	// KEK = 000102030405060708090A0B0C0D0E0F
	// Key = 00112233445566778899AABBCCDDEEFF
	// Wrapped = 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5

	kek := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	wrapped := []byte{0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5}
	expectedKey := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap failed: %v", err)
	}

	if !BytesEqual(unwrapped, expectedKey) {
		t.Errorf("unwrapped key mismatch: got %x, want %x", unwrapped, expectedKey)
	}
}

func TestAESKeyUnwrap256(t *testing.T) {
	// Test vector from RFC 3394 for 256-bit KEK
	// KEK = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
	// Key = 00112233445566778899AABBCCDDEEFF
	// Wrapped = 64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7

	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}
	wrapped := []byte{
		0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
		0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
		0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
	}
	expectedKey := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap failed: %v", err)
	}

	if !BytesEqual(unwrapped, expectedKey) {
		t.Errorf("unwrapped key mismatch: got %x, want %x", unwrapped, expectedKey)
	}
}
