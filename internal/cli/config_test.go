package cli

import (
	"testing"
)

func TestValueOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue string
		want         string
	}{
		{"empty value", "", "default", "default"},
		{"has value", "myvalue", "default", "myvalue"},
		{"both empty", "", "", ""},
		{"value same as default", "default", "default", "default"},
		{"whitespace value", "  ", "default", "  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valueOrDefault(tt.value, tt.defaultValue)
			if got != tt.want {
				t.Errorf("valueOrDefault(%q, %q) = %q, want %q", tt.value, tt.defaultValue, got, tt.want)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"empty string", "", 10, "(not set)"},
		{"shorter than max", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"longer than max", "hello world", 5, "hello..."},
		{"max length 0", "hello", 0, "..."},
		{"max length 1", "hello", 1, "h..."},
		{"unicode string short", "你好", 10, "你好"},
		{"single char", "x", 1, "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"empty token", "", "(not set)"},
		{"short token", "abc", "****"},
		{"10 char token", "1234567890", "****"},
		{"long token", "abcdefghijklmnopqrstuvwxyz", "abcde...vwxyz"},
		{"exactly 11 chars", "12345678901", "12345...78901"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskToken(tt.token)
			if got != tt.want {
				t.Errorf("maskToken(%q) = %q, want %q", tt.token, got, tt.want)
			}
		})
	}
}

func TestConfigParameter(t *testing.T) {
	// Test that configParameters slice is properly initialized
	if len(configParameters) == 0 {
		t.Error("configParameters should not be empty")
	}

	// Check for required parameters
	requiredParams := []string{"backend_url", "active_profile", "debug"}
	for _, required := range requiredParams {
		found := false
		for _, p := range configParameters {
			if p.Key == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing required config parameter: %s", required)
		}
	}
}

func TestConfigParameterScopes(t *testing.T) {
	// Verify all parameters have valid scopes
	validScopes := map[string]bool{"global": true, "profile": true}

	for _, p := range configParameters {
		if !validScopes[p.Scope] {
			t.Errorf("Parameter %q has invalid scope %q", p.Key, p.Scope)
		}
	}
}

func TestConfigParameterDescriptions(t *testing.T) {
	// Verify all parameters have descriptions
	for _, p := range configParameters {
		if p.Description == "" {
			t.Errorf("Parameter %q has no description", p.Key)
		}
	}
}
