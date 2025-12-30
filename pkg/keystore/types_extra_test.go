package keystore

import (
	"encoding/base64"
	"testing"
)

func TestTaggedBinary_ToBase64URL(t *testing.T) {
	tests := []struct {
		name     string
		data     TaggedBinary
		expected string
	}{
		{
			name:     "empty",
			data:     TaggedBinary([]byte{}),
			expected: "",
		},
		{
			name:     "simple string",
			data:     TaggedBinary([]byte("Hello World")),
			expected: "SGVsbG8gV29ybGQ",
		},
		{
			name:     "binary data",
			data:     TaggedBinary([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE}),
			expected: "AAEC__4",
		},
		{
			name:     "credential ID",
			data:     TaggedBinary([]byte("credential-1")),
			expected: "Y3JlZGVudGlhbC0x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.data.ToBase64URL()
			if result != tt.expected {
				t.Errorf("ToBase64URL() = %q, want %q", result, tt.expected)
			}
			// Verify we can decode it back
			decoded, err := base64.RawURLEncoding.DecodeString(result)
			if err != nil {
				t.Fatalf("Failed to decode result: %v", err)
			}
			if !BytesEqual(decoded, []byte(tt.data)) {
				t.Errorf("Roundtrip failed: got %v, want %v", decoded, tt.data)
			}
		})
	}
}

func TestEncryptedContainer_GetCredentialIDs(t *testing.T) {
	container := &EncryptedContainer{
		JWE: "test-jwe",
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{
			{
				CredentialID: TaggedBinary([]byte("cred-1")),
			},
			{
				CredentialID: TaggedBinary([]byte("cred-2")),
			},
			{
				CredentialID: TaggedBinary([]byte("longer-credential-id-3")),
			},
		},
	}

	ids := container.GetCredentialIDs()

	if len(ids) != 3 {
		t.Fatalf("GetCredentialIDs() returned %d IDs, want 3", len(ids))
	}

	// Verify each ID is valid base64url
	for i, id := range ids {
		// Should not have padding
		if len(id) > 0 && id[len(id)-1] == '=' {
			t.Errorf("ID %d has padding: %q", i, id)
		}
		// Should be decodable
		decoded, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil {
			t.Errorf("ID %d not valid base64url: %q, err: %v", i, id, err)
		}
		if len(decoded) == 0 {
			t.Errorf("ID %d decoded to empty", i)
		}
	}
}

func TestEncryptedContainer_GetCredentialIDs_Empty(t *testing.T) {
	container := &EncryptedContainer{
		JWE:     "test-jwe",
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{},
	}

	ids := container.GetCredentialIDs()

	if len(ids) != 0 {
		t.Errorf("GetCredentialIDs() returned %d IDs, want 0", len(ids))
	}
}

func TestEncryptedContainer_FindPRFKeyByCredentialID_NotFound(t *testing.T) {
	container := &EncryptedContainer{
		JWE: "test-jwe",
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{
			{
				CredentialID: TaggedBinary([]byte("cred-1")),
				PRFSalt:      TaggedBinary([]byte("salt-1")),
			},
		},
	}

	// Try to find a non-existent credential
	result := container.FindPRFKeyByCredentialID([]byte("nonexistent"))
	if result != nil {
		t.Error("FindPRFKeyByCredentialID should return nil for nonexistent credential")
	}
}

func TestEncryptedContainer_FindPRFKeyByCredentialID_MultipleKeys(t *testing.T) {
	container := &EncryptedContainer{
		JWE: "test-jwe",
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{
			{
				CredentialID: TaggedBinary([]byte("cred-1")),
				PRFSalt:      TaggedBinary([]byte("salt-1")),
			},
			{
				CredentialID: TaggedBinary([]byte("cred-2")),
				PRFSalt:      TaggedBinary([]byte("salt-2")),
			},
			{
				CredentialID: TaggedBinary([]byte("cred-3")),
				PRFSalt:      TaggedBinary([]byte("salt-3")),
			},
		},
	}

	// Find first credential
	result := container.FindPRFKeyByCredentialID([]byte("cred-1"))
	if result == nil {
		t.Fatal("FindPRFKeyByCredentialID returned nil for cred-1")
	}
	if !BytesEqual(result.PRFSalt, []byte("salt-1")) {
		t.Errorf("Wrong PRFSalt: got %q, want %q", result.PRFSalt, "salt-1")
	}

	// Find middle credential
	result = container.FindPRFKeyByCredentialID([]byte("cred-2"))
	if result == nil {
		t.Fatal("FindPRFKeyByCredentialID returned nil for cred-2")
	}
	if !BytesEqual(result.PRFSalt, []byte("salt-2")) {
		t.Errorf("Wrong PRFSalt: got %q, want %q", result.PRFSalt, "salt-2")
	}

	// Find last credential
	result = container.FindPRFKeyByCredentialID([]byte("cred-3"))
	if result == nil {
		t.Fatal("FindPRFKeyByCredentialID returned nil for cred-3")
	}
	if !BytesEqual(result.PRFSalt, []byte("salt-3")) {
		t.Errorf("Wrong PRFSalt: got %q, want %q", result.PRFSalt, "salt-3")
	}
}

func TestEncryptedContainer_GetPRFKeyInfos_EmptyContainer(t *testing.T) {
	container := &EncryptedContainer{
		JWE:     "test-jwe",
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{},
	}

	infos := container.GetPRFKeyInfos()

	if len(infos) != 0 {
		t.Errorf("GetPRFKeyInfos() returned %d infos, want 0", len(infos))
	}
}

func TestEncryptedContainer_GetPRFKeyInfos_WithTransports(t *testing.T) {
	container := &EncryptedContainer{
		JWE: "test-jwe",
		PRFKeys: []WebauthnPrfEncryptionKeyInfo{
			{
				CredentialID: TaggedBinary([]byte("cred-usb")),
				Transports:   []string{"usb"},
				PRFSalt:      TaggedBinary([]byte("salt-1")),
			},
			{
				CredentialID: TaggedBinary([]byte("cred-nfc")),
				Transports:   []string{"nfc", "usb"},
				PRFSalt:      TaggedBinary([]byte("salt-2")),
			},
		},
	}

	infos := container.GetPRFKeyInfos()

	if len(infos) != 2 {
		t.Fatalf("GetPRFKeyInfos() returned %d infos, want 2", len(infos))
	}

	// Check first info
	if !BytesEqual(infos[0].CredentialID, []byte("cred-usb")) {
		t.Errorf("First CredentialID = %q, want %q", infos[0].CredentialID, "cred-usb")
	}
	if len(infos[0].Transports) != 1 || infos[0].Transports[0] != "usb" {
		t.Errorf("First Transports = %v, want [usb]", infos[0].Transports)
	}
	if !BytesEqual(infos[0].PRFSalt, []byte("salt-1")) {
		t.Errorf("First PRFSalt = %q, want %q", infos[0].PRFSalt, "salt-1")
	}

	// Check second info
	if len(infos[1].Transports) != 2 {
		t.Errorf("Second Transports length = %d, want 2", len(infos[1].Transports))
	}
}

func TestParseEncryptedContainer_InvalidJSON(t *testing.T) {
	_, err := ParseEncryptedContainer([]byte("not valid json"))
	if err == nil {
		t.Error("ParseEncryptedContainer should return error for invalid JSON")
	}
}

func TestParseEncryptedContainer_MinimalValid(t *testing.T) {
	json := `{"jwe": "test", "prfKeys": []}`
	container, err := ParseEncryptedContainer([]byte(json))
	if err != nil {
		t.Fatalf("ParseEncryptedContainer failed: %v", err)
	}
	if container.JWE != "test" {
		t.Errorf("JWE = %q, want %q", container.JWE, "test")
	}
}

func TestPRFKeyInfo_Fields(t *testing.T) {
	info := PRFKeyInfo{
		CredentialID: []byte("cred-123"),
		Transports:   []string{"usb", "nfc"},
		PRFSalt:      []byte("salt-456"),
	}

	if !BytesEqual(info.CredentialID, []byte("cred-123")) {
		t.Errorf("CredentialID = %q, want %q", info.CredentialID, "cred-123")
	}
	if len(info.Transports) != 2 {
		t.Errorf("Transports length = %d, want 2", len(info.Transports))
	}
	if !BytesEqual(info.PRFSalt, []byte("salt-456")) {
		t.Errorf("PRFSalt = %q, want %q", info.PRFSalt, "salt-456")
	}
}

func TestKeystoreErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrKeystoreLocked", ErrKeystoreLocked, "keystore is locked"},
		{"ErrKeyNotFound", ErrKeyNotFound, "key not found"},
		{"ErrInvalidContainer", ErrInvalidContainer, "invalid encrypted container"},
		{"ErrDecryptionFailed", ErrDecryptionFailed, "decryption failed"},
		{"ErrKeyDerivationFailed", ErrKeyDerivationFailed, "key derivation failed"},
		{"ErrNoPRFKeyMatch", ErrNoPRFKeyMatch, "no matching PRF key found for credential"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.msg {
				t.Errorf("Error message = %q, want %q", tt.err.Error(), tt.msg)
			}
		})
	}
}
