// Package pinentry provides PIN entry functionality using system pinentry programs.package pinentry

package pinentry

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// Common errors
var (
	ErrCancelled      = errors.New("PIN entry cancelled")
	ErrNoPinentry     = errors.New("no pinentry program found")
	ErrInvalidPIN     = errors.New("invalid PIN")
	ErrPinentryFailed = errors.New("pinentry program failed")
)

// Method specifies how to obtain the PIN.
type Method string

const (
	// MethodPinentry uses the system pinentry program (default).
	MethodPinentry Method = "pinentry"
	// MethodStdin reads the PIN from stdin (for scripting).
	MethodStdin Method = "stdin"
	// MethodTerminal prompts interactively in the terminal.
	MethodTerminal Method = "terminal"
	// MethodArg uses a PIN provided as a command-line argument (insecure).
	MethodArg Method = "arg"
)

// Config holds pinentry configuration.
type Config struct {
	// Method specifies how to obtain the PIN.
	Method Method

	// Program is the path to the pinentry program (for MethodPinentry).
	// If empty, the system default is used.
	Program string

	// Title is the window title for the pinentry dialog.
	Title string

	// Description is the descriptive text shown to the user.
	Description string

	// Prompt is the prompt text (usually "PIN:").
	Prompt string

	// ErrorText is shown if the previous PIN was wrong.
	ErrorText string

	// PIN is the pre-set PIN (for MethodArg).
	PIN string
}

// DefaultConfig returns a default pinentry configuration.
func DefaultConfig() *Config {
	return &Config{
		Method:      MethodPinentry,
		Title:       "FIDO2 PIN Entry",
		Description: "Enter the PIN for your FIDO2 security key",
		Prompt:      "PIN:",
	}
}

// GetPIN obtains a PIN using the configured method.
func GetPIN(cfg *Config) (string, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	switch cfg.Method {
	case MethodPinentry:
		return getPINFromPinentry(cfg)
	case MethodStdin:
		return getPINFromStdin(cfg)
	case MethodTerminal:
		return getPINFromTerminal(cfg)
	case MethodArg:
		if cfg.PIN == "" {
			return "", ErrInvalidPIN
		}
		return cfg.PIN, nil
	default:
		// Default to pinentry
		return getPINFromPinentry(cfg)
	}
}

// getPINFromPinentry uses the system pinentry program.
func getPINFromPinentry(cfg *Config) (string, error) {
	// Find pinentry program
	program := cfg.Program
	if program == "" {
		program = findPinentry()
	}
	if program == "" {
		// Fall back to terminal if no pinentry found
		return getPINFromTerminal(cfg)
	}

	// Start pinentry process
	cmd := exec.Command(program)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start pinentry: %w", err)
	}

	reader := bufio.NewReader(stdout)

	// Helper to send command and read response
	sendCommand := func(command string) (string, error) {
		if _, err := fmt.Fprintf(stdin, "%s\n", command); err != nil {
			return "", err
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}

	// Read initial OK
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK") {
		cmd.Process.Kill()
		return "", fmt.Errorf("pinentry did not respond correctly: %v", err)
	}

	// Set title
	if cfg.Title != "" {
		if resp, err := sendCommand(fmt.Sprintf("SETTITLE %s", escapeAssuan(cfg.Title))); err != nil || !strings.HasPrefix(resp, "OK") {
			// Ignore errors for optional commands
		}
	}

	// Set description
	if cfg.Description != "" {
		if resp, err := sendCommand(fmt.Sprintf("SETDESC %s", escapeAssuan(cfg.Description))); err != nil || !strings.HasPrefix(resp, "OK") {
			// Ignore errors for optional commands
		}
	}

	// Set prompt
	prompt := cfg.Prompt
	if prompt == "" {
		prompt = "PIN:"
	}
	if resp, err := sendCommand(fmt.Sprintf("SETPROMPT %s", escapeAssuan(prompt))); err != nil || !strings.HasPrefix(resp, "OK") {
		// Ignore errors for optional commands
	}

	// Set error text if provided
	if cfg.ErrorText != "" {
		if resp, err := sendCommand(fmt.Sprintf("SETERROR %s", escapeAssuan(cfg.ErrorText))); err != nil || !strings.HasPrefix(resp, "OK") {
			// Ignore errors for optional commands
		}
	}

	// Request PIN
	resp, err := sendCommand("GETPIN")
	if err != nil {
		cmd.Process.Kill()
		return "", fmt.Errorf("failed to get PIN: %w", err)
	}

	// Close pinentry
	sendCommand("BYE")
	stdin.Close()
	cmd.Wait()

	// Parse response
	if strings.HasPrefix(resp, "D ") {
		// PIN received
		pin := strings.TrimPrefix(resp, "D ")
		// Read the final OK
		reader.ReadString('\n')
		return unescapeAssuan(pin), nil
	} else if strings.HasPrefix(resp, "ERR") {
		// Check if cancelled
		if strings.Contains(resp, "83886179") || strings.Contains(resp, "cancelled") {
			return "", ErrCancelled
		}
		return "", fmt.Errorf("%w: %s", ErrPinentryFailed, resp)
	}

	return "", fmt.Errorf("%w: unexpected response: %s", ErrPinentryFailed, resp)
}

// getPINFromStdin reads the PIN from stdin (for scripting).
func getPINFromStdin(cfg *Config) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	pin, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return "", ErrCancelled
		}
		return "", fmt.Errorf("failed to read PIN from stdin: %w", err)
	}
	return strings.TrimSpace(pin), nil
}

// getPINFromTerminal prompts interactively in the terminal.
func getPINFromTerminal(cfg *Config) (string, error) {
	// Check if we have a terminal
	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", fmt.Errorf("no terminal available for PIN entry")
	}

	// Show description if provided
	if cfg.Description != "" {
		fmt.Fprintln(os.Stderr, cfg.Description)
	}

	// Show error if provided
	if cfg.ErrorText != "" {
		fmt.Fprintf(os.Stderr, "Error: %s\n", cfg.ErrorText)
	}

	// Prompt for PIN
	prompt := cfg.Prompt
	if prompt == "" {
		prompt = "PIN:"
	}
	fmt.Fprintf(os.Stderr, "%s ", prompt)

	// Read PIN without echo
	pinBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // Add newline after PIN entry

	if err != nil {
		return "", fmt.Errorf("failed to read PIN: %w", err)
	}

	pin := strings.TrimSpace(string(pinBytes))
	if pin == "" {
		return "", ErrCancelled
	}

	return pin, nil
}

// findPinentry looks for a pinentry program on the system.
func findPinentry() string {
	// Try common pinentry programs in order of preference
	candidates := []string{
		"pinentry",           // Default on most systems
		"pinentry-gnome3",    // GNOME
		"pinentry-gtk-2",     // GTK
		"pinentry-qt",        // Qt/KDE
		"pinentry-curses",    // Terminal-based
		"pinentry-tty",       // Simple TTY
	}

	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}

	return ""
}

// escapeAssuan escapes a string for the Assuan protocol used by pinentry.
func escapeAssuan(s string) string {
	// Replace special characters
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return s
}

// unescapeAssuan unescapes a string from the Assuan protocol.
func unescapeAssuan(s string) string {
	s = strings.ReplaceAll(s, "%0D", "\r")
	s = strings.ReplaceAll(s, "%0A", "\n")
	s = strings.ReplaceAll(s, "%25", "%")
	return s
}

// HasPinentry checks if a pinentry program is available.
func HasPinentry() bool {
	return findPinentry() != ""
}

// GetPinentryPath returns the path to the pinentry program.
func GetPinentryPath() string {
	return findPinentry()
}
