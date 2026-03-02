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
		resp, err := sendCommand(fmt.Sprintf("SETTITLE %s", escapeAssuan(cfg.Title)))
		// Ignore errors for optional commands
		_, _ = resp, err
	}

	// Set description
	if cfg.Description != "" {
		resp, err := sendCommand(fmt.Sprintf("SETDESC %s", escapeAssuan(cfg.Description)))
		// Ignore errors for optional commands
		_, _ = resp, err
	}

	// Set prompt
	prompt := cfg.Prompt
	if prompt == "" {
		prompt = "PIN:"
	}
	{
		resp, err := sendCommand(fmt.Sprintf("SETPROMPT %s", escapeAssuan(prompt)))
		// Ignore errors for optional commands
		_, _ = resp, err
	}

	// Set error text if provided
	if cfg.ErrorText != "" {
		resp, err := sendCommand(fmt.Sprintf("SETERROR %s", escapeAssuan(cfg.ErrorText)))
		// Ignore errors for optional commands
		_, _ = resp, err
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
	if !term.IsTerminal(syscall.Stdin) {
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
	pinBytes, err := term.ReadPassword(syscall.Stdin)
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
		"pinentry",        // Default on most systems
		"pinentry-gnome3", // GNOME
		"pinentry-gtk-2",  // GTK
		"pinentry-qt",     // Qt/KDE
		"pinentry-curses", // Terminal-based
		"pinentry-tty",    // Simple TTY
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

// ConfirmConfig holds configuration for a confirmation dialog.
type ConfirmConfig struct {
	// Program is the path to the pinentry program.
	Program string

	// Title is the window title.
	Title string

	// Description is the descriptive text shown to the user.
	Description string

	// OKButton is the text for the OK/approve button.
	OKButton string

	// CancelButton is the text for the Cancel/deny button.
	CancelButton string

	// Timeout in seconds (0 for no timeout).
	Timeout int
}

// DefaultConfirmConfig returns a default confirmation configuration.
func DefaultConfirmConfig() *ConfirmConfig {
	return &ConfirmConfig{
		Title:        "Wallet Approval Required",
		Description:  "An application is requesting access to your wallet.",
		OKButton:     "Approve",
		CancelButton: "Deny",
	}
}

// GetConfirmation shows a confirmation dialog and returns true if approved.
// Falls back to terminal prompt if pinentry is not available.
func GetConfirmation(cfg *ConfirmConfig) (bool, error) {
	if cfg == nil {
		cfg = DefaultConfirmConfig()
	}

	program := cfg.Program
	if program == "" {
		program = findPinentry()
	}

	if program == "" {
		// Fall back to terminal confirmation
		return getConfirmationFromTerminal(cfg)
	}

	return getConfirmationFromPinentry(cfg, program)
}

// getConfirmationFromPinentry uses the pinentry CONFIRM command.
func getConfirmationFromPinentry(cfg *ConfirmConfig, program string) (bool, error) {
	cmd := exec.Command(program)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("failed to start pinentry: %w", err)
	}

	reader := bufio.NewReader(stdout)

	// Helper to send command
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
		return false, fmt.Errorf("pinentry did not respond correctly")
	}

	// Set title
	if cfg.Title != "" {
		sendCommand(fmt.Sprintf("SETTITLE %s", escapeAssuan(cfg.Title)))
	}

	// Set description
	if cfg.Description != "" {
		sendCommand(fmt.Sprintf("SETDESC %s", escapeAssuan(cfg.Description)))
	}

	// Set button text
	if cfg.OKButton != "" {
		sendCommand(fmt.Sprintf("SETOK %s", escapeAssuan(cfg.OKButton)))
	}
	if cfg.CancelButton != "" {
		sendCommand(fmt.Sprintf("SETCANCEL %s", escapeAssuan(cfg.CancelButton)))
	}

	// Set timeout if specified
	if cfg.Timeout > 0 {
		sendCommand(fmt.Sprintf("SETTIMEOUT %d", cfg.Timeout))
	}

	// Request confirmation
	resp, err := sendCommand("CONFIRM")

	// Close pinentry
	sendCommand("BYE")
	stdin.Close()
	cmd.Wait()

	if err != nil {
		return false, fmt.Errorf("pinentry error: %w", err)
	}

	// Check response
	if strings.HasPrefix(resp, "OK") {
		return true, nil
	}

	return false, nil
}

// getConfirmationFromTerminal prompts in the terminal.
func getConfirmationFromTerminal(cfg *ConfirmConfig) (bool, error) {
	// Check if stdin is a terminal
	if !term.IsTerminal(syscall.Stdin) {
		return false, fmt.Errorf("no terminal available for confirmation")
	}

	fmt.Println()
	fmt.Println(cfg.Title)
	fmt.Println(strings.Repeat("-", len(cfg.Title)))
	fmt.Println(cfg.Description)
	fmt.Println()
	fmt.Printf("[%s/deny]: ", cfg.OKButton)

	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	approved := response == "y" || response == "yes" || response == "approve" ||
		strings.ToLower(response) == strings.ToLower(cfg.OKButton)

	return approved, nil
}
