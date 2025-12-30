package pinentry

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Method != MethodPinentry {
		t.Errorf("Default method = %q, want %q", cfg.Method, MethodPinentry)
	}
	if cfg.Title == "" {
		t.Error("Default title should not be empty")
	}
	if cfg.Description == "" {
		t.Error("Default description should not be empty")
	}
	if cfg.Prompt == "" {
		t.Error("Default prompt should not be empty")
	}
}

func TestMethodConstants(t *testing.T) {
	tests := []struct {
		method Method
		want   string
	}{
		{MethodPinentry, "pinentry"},
		{MethodStdin, "stdin"},
		{MethodTerminal, "terminal"},
		{MethodArg, "arg"},
	}

	for _, tt := range tests {
		if string(tt.method) != tt.want {
			t.Errorf("Method %v = %q, want %q", tt.method, tt.method, tt.want)
		}
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"Cancelled", ErrCancelled, "PIN entry cancelled"},
		{"NoPinentry", ErrNoPinentry, "no pinentry program found"},
		{"InvalidPIN", ErrInvalidPIN, "invalid PIN"},
		{"PinentryFailed", ErrPinentryFailed, "pinentry program failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.msg {
				t.Errorf("Error message = %q, want %q", tt.err.Error(), tt.msg)
			}
		})
	}
}

func TestGetPIN_MethodArg(t *testing.T) {
	tests := []struct {
		name    string
		pin     string
		wantErr bool
	}{
		{"Valid PIN", "123456", false},
		{"Empty PIN", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Method: MethodArg,
				PIN:    tt.pin,
			}

			got, err := GetPIN(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPIN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.pin {
				t.Errorf("GetPIN() = %q, want %q", got, tt.pin)
			}
		})
	}
}

func TestGetPIN_NilConfig(t *testing.T) {
	// This test checks that GetPIN handles nil config gracefully
	// It will try to use pinentry which may or may not be available
	// So we just verify it doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("GetPIN(nil) panicked: %v", r)
		}
	}()

	// Note: This will actually try to run pinentry or fall back to terminal
	// In a test environment without a terminal, this will return an error
	// but should not panic
	_, _ = GetPIN(nil)
}

func TestEscapeAssuan(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hello world", "hello world"},
		{"100%", "100%25"},
		{"line1\nline2", "line1%0Aline2"},
		{"cr\rtest", "cr%0Dtest"},
		{"mixed%\n\r", "mixed%25%0A%0D"},
	}

	for _, tt := range tests {
		got := escapeAssuan(tt.input)
		if got != tt.want {
			t.Errorf("escapeAssuan(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUnescapeAssuan(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"100%25", "100%"},
		{"line1%0Aline2", "line1\nline2"},
		{"cr%0Dtest", "cr\rtest"},
		{"mixed%25%0A%0D", "mixed%\n\r"},
	}

	for _, tt := range tests {
		got := unescapeAssuan(tt.input)
		if got != tt.want {
			t.Errorf("unescapeAssuan(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHasPinentry(t *testing.T) {
	// Just verify this doesn't panic
	result := HasPinentry()
	t.Logf("HasPinentry() = %v", result)
}

func TestGetPinentryPath(t *testing.T) {
	// Just verify this doesn't panic
	path := GetPinentryPath()
	t.Logf("GetPinentryPath() = %q", path)
}

func TestFindPinentry(t *testing.T) {
	// This tests the internal function - it should return a path or empty string
	path := findPinentry()
	// On a typical Linux system with GPG installed, this should find pinentry
	// But we can't guarantee it in all test environments
	t.Logf("findPinentry() = %q", path)
}

func TestConfig(t *testing.T) {
	cfg := &Config{
		Method:      MethodPinentry,
		Program:     "/usr/bin/pinentry",
		Title:       "Test Title",
		Description: "Test Description",
		Prompt:      "Test PIN:",
		ErrorText:   "Wrong PIN",
		PIN:         "123456",
	}

	if cfg.Method != MethodPinentry {
		t.Errorf("Method = %q, want %q", cfg.Method, MethodPinentry)
	}
	if cfg.Program != "/usr/bin/pinentry" {
		t.Errorf("Program = %q, want %q", cfg.Program, "/usr/bin/pinentry")
	}
	if cfg.Title != "Test Title" {
		t.Errorf("Title = %q, want %q", cfg.Title, "Test Title")
	}
}

func TestGetPIN_DefaultMethod(t *testing.T) {
	// Test that default method falls through to pinentry or terminal
	cfg := &Config{
		Method: Method("unknown"),
		PIN:    "test",
	}

	// This will try pinentry or fall back to terminal
	// In a test environment, this may fail but should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("GetPIN with unknown method panicked: %v", r)
		}
	}()

	_, _ = GetPIN(cfg)
}

func TestEscapeAssuan_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"only percent", "%%%", "%25%25%25"},
		{"only newlines", "\n\n\n", "%0A%0A%0A"},
		{"unicode", "пароль", "пароль"}, // Unicode should pass through
		{"special chars", "test%test\ntest\rtest", "test%25test%0Atest%0Dtest"},
		{"no special", "ABCdef123", "ABCdef123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeAssuan(tt.input)
			if got != tt.want {
				t.Errorf("escapeAssuan(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnescapeAssuan_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"multiple percent", "%25%25%25", "%%%"},
		{"multiple newlines", "%0A%0A%0A", "\n\n\n"},
		{"mixed escapes", "test%25test%0Atest%0Dtest", "test%test\ntest\rtest"},
		{"no escapes", "ABCdef123", "ABCdef123"},
		{"lowercase hex", "%0a%0d%25", "%0a%0d%"}, // Only uppercase handled
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unescapeAssuan(tt.input)
			if got != tt.want {
				t.Errorf("unescapeAssuan(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEscapeUnescapeRoundtrip(t *testing.T) {
	// Test that escaping then unescaping returns the original
	inputs := []string{
		"hello",
		"test%value",
		"line1\nline2",
		"cr\rtest",
		"mixed%\n\rtest",
		"",
		"no special chars",
	}

	for _, input := range inputs {
		escaped := escapeAssuan(input)
		unescaped := unescapeAssuan(escaped)
		if unescaped != input {
			t.Errorf("Roundtrip failed for %q: escaped=%q, unescaped=%q", input, escaped, unescaped)
		}
	}
}

func TestConfigCopy(t *testing.T) {
	// Test that Config can be copied safely
	original := &Config{
		Method:      MethodTerminal,
		Program:     "/custom/pinentry",
		Title:       "Original Title",
		Description: "Original Desc",
		Prompt:      "Original:",
		ErrorText:   "Original Error",
		PIN:         "original-pin",
	}

	// Create a copy
	copy := &Config{
		Method:      original.Method,
		Program:     original.Program,
		Title:       original.Title,
		Description: original.Description,
		Prompt:      original.Prompt,
		ErrorText:   original.ErrorText,
		PIN:         original.PIN,
	}

	// Modify original
	original.Title = "Modified Title"

	// Copy should be unchanged
	if copy.Title != "Original Title" {
		t.Errorf("Copy was modified when original changed")
	}
}

func TestGetPIN_MethodTerminalNoTTY(t *testing.T) {
	// In a test environment, there's no terminal, so this should fail gracefully
	cfg := &Config{
		Method: MethodTerminal,
	}

	_, err := GetPIN(cfg)
	// This should return an error since tests don't have a terminal
	if err == nil {
		t.Log("GetPIN with MethodTerminal succeeded (might have a terminal)")
	}
}

func TestGetPIN_MethodStdin(t *testing.T) {
	// Note: Actually testing stdin requires pipe manipulation
	// This test just verifies the code path doesn't panic
	cfg := &Config{
		Method: MethodStdin,
	}

	// In a test environment, stdin will be empty/closed
	// so this should return an error but not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("GetPIN with MethodStdin panicked: %v", r)
		}
	}()

	_, _ = GetPIN(cfg)
}
