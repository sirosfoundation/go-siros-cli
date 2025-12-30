package cli

import (
	"encoding/base64"
	"testing"
)

func TestTaggedBinary(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "simple bytes",
			input: []byte("hello"),
			want:  "aGVsbG8",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0xff},
			want:  "AAEC_w",
		},
		{
			name:  "challenge-like data",
			input: []byte("test-challenge-1234567890"),
			want:  "dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := taggedBinary(tt.input)

			b64u, ok := result["$b64u"]
			if !ok {
				t.Fatalf("taggedBinary() result missing $b64u key")
			}

			if b64u != tt.want {
				t.Errorf("taggedBinary() = %q, want %q", b64u, tt.want)
			}

			// Verify the base64url can be decoded back
			decoded, err := base64.RawURLEncoding.DecodeString(b64u)
			if err != nil {
				t.Errorf("taggedBinary() produced invalid base64url: %v", err)
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("taggedBinary() roundtrip failed: got %q, want %q", decoded, tt.input)
			}
		})
	}
}

func TestExtractTaggedBinary(t *testing.T) {
	tests := []struct {
		name    string
		m       map[string]interface{}
		key     string
		want    []byte
		wantErr bool
	}{
		{
			name: "tagged binary format",
			m: map[string]interface{}{
				"challenge": map[string]interface{}{
					"$b64u": "dGVzdC1jaGFsbGVuZ2U",
				},
			},
			key:     "challenge",
			want:    []byte("test-challenge"),
			wantErr: false,
		},
		{
			name: "plain base64url string",
			m: map[string]interface{}{
				"challenge": "dGVzdC1jaGFsbGVuZ2U",
			},
			key:     "challenge",
			want:    []byte("test-challenge"),
			wantErr: false,
		},
		{
			name: "byte slice directly",
			m: map[string]interface{}{
				"data": []byte("direct-bytes"),
			},
			key:     "data",
			want:    []byte("direct-bytes"),
			wantErr: false,
		},
		{
			name:    "nil map",
			m:       nil,
			key:     "challenge",
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing key",
			m: map[string]interface{}{
				"other": "value",
			},
			key:     "challenge",
			want:    nil,
			wantErr: true,
		},
		{
			name: "unsupported type",
			m: map[string]interface{}{
				"challenge": 12345,
			},
			key:     "challenge",
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty tagged binary",
			m: map[string]interface{}{
				"challenge": map[string]interface{}{
					"$b64u": "",
				},
			},
			key:     "challenge",
			want:    []byte{},
			wantErr: false,
		},
		{
			name: "binary data with special chars",
			m: map[string]interface{}{
				"id": map[string]interface{}{
					"$b64u": "AAEC_w", // {0x00, 0x01, 0x02, 0xff}
				},
			},
			key:     "id",
			want:    []byte{0x00, 0x01, 0x02, 0xff},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractTaggedBinary(tt.m, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractTaggedBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if string(got) != string(tt.want) {
					t.Errorf("extractTaggedBinary() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestExtractTaggedBinary_ComplexPublicKey(t *testing.T) {
	// Simulate real WebAuthn response structure
	publicKey := map[string]interface{}{
		"challenge": map[string]interface{}{
			"$b64u": "cmFuZG9tLWNoYWxsZW5nZS1ieXRlcw",
		},
		"rp": map[string]interface{}{
			"id":   "siros.org",
			"name": "SIROS Wallet",
		},
		"user": map[string]interface{}{
			"id": map[string]interface{}{
				"$b64u": "dXNlci1pZC0xMjM0NQ",
			},
			"name":        "user@example.com",
			"displayName": "Test User",
		},
		"pubKeyCredParams": []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  -7,
			},
		},
	}

	// Extract challenge
	challenge, err := extractTaggedBinary(publicKey, "challenge")
	if err != nil {
		t.Fatalf("failed to extract challenge: %v", err)
	}
	if string(challenge) != "random-challenge-bytes" {
		t.Errorf("challenge = %q, want %q", challenge, "random-challenge-bytes")
	}

	// Extract user.id
	user, ok := publicKey["user"].(map[string]interface{})
	if !ok {
		t.Fatal("user is not a map")
	}
	userID, err := extractTaggedBinary(user, "id")
	if err != nil {
		t.Fatalf("failed to extract user id: %v", err)
	}
	if string(userID) != "user-id-12345" {
		t.Errorf("userID = %q, want %q", userID, "user-id-12345")
	}
}

func TestExtractTaggedBinary_AllowCredentials(t *testing.T) {
	// Simulate allowCredentials from login response
	allowCredentials := []interface{}{
		map[string]interface{}{
			"id": map[string]interface{}{
				"$b64u": "Y3JlZC0x",
			},
			"type":       "public-key",
			"transports": []string{"usb"},
		},
		map[string]interface{}{
			"id": map[string]interface{}{
				"$b64u": "Y3JlZC0y",
			},
			"type":       "public-key",
			"transports": []string{"internal"},
		},
	}

	expectedIDs := []string{"cred-1", "cred-2"}

	for i, cred := range allowCredentials {
		credMap, ok := cred.(map[string]interface{})
		if !ok {
			t.Fatalf("credential %d is not a map", i)
		}

		credID, err := extractTaggedBinary(credMap, "id")
		if err != nil {
			t.Fatalf("failed to extract credential %d id: %v", i, err)
		}
		if string(credID) != expectedIDs[i] {
			t.Errorf("credential %d id = %q, want %q", i, credID, expectedIDs[i])
		}
	}
}

func TestTaggedBinaryRoundtrip(t *testing.T) {
	// Test that taggedBinary and extractTaggedBinary are inverse operations
	// Note: taggedBinary returns map[string]string but extractTaggedBinary expects
	// map[string]interface{}, so we need to convert when simulating JSON roundtrip
	testData := [][]byte{
		[]byte("hello world"),
		[]byte{0x00, 0x01, 0x02, 0x03},
		[]byte(""),
		[]byte("a very long string that contains many characters and should still work correctly when encoded and decoded"),
		// Challenge-like random bytes
		{0x7f, 0x8a, 0x12, 0x3b, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23},
	}

	for i, original := range testData {
		// Create tagged binary
		tagged := taggedBinary(original)

		// Convert map[string]string to map[string]interface{} (simulates JSON unmarshal)
		taggedInterface := map[string]interface{}{
			"$b64u": tagged["$b64u"],
		}

		// Create a map with the tagged value
		m := map[string]interface{}{
			"data": taggedInterface,
		}

		// Extract it back
		extracted, err := extractTaggedBinary(m, "data")
		if err != nil {
			t.Errorf("test %d: extractTaggedBinary failed: %v", i, err)
			continue
		}

		if string(extracted) != string(original) {
			t.Errorf("test %d: roundtrip failed: got %v, want %v", i, extracted, original)
		}
	}
}
