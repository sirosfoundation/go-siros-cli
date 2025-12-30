package fido2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// BrowserProvider implements the Provider interface using browser-based WebAuthn.
// This starts a local HTTP server and opens a browser for the WebAuthn ceremony.
type BrowserProvider struct {
	// CallbackPort is the port for the local callback server
	CallbackPort int

	// BrowserCommand overrides the browser launch command
	BrowserCommand string

	// Timeout for the browser ceremony
	Timeout string

	// RPID is the relying party ID
	RPID string
}

// NewBrowserProvider creates a new browser-based FIDO2 provider.
func NewBrowserProvider(opts ...BrowserOption) *BrowserProvider {
	p := &BrowserProvider{
		CallbackPort: 0, // Random port
		Timeout:      "120s",
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// BrowserOption configures the BrowserProvider.
type BrowserOption func(*BrowserProvider)

// WithCallbackPort sets a specific callback port.
func WithCallbackPort(port int) BrowserOption {
	return func(p *BrowserProvider) {
		p.CallbackPort = port
	}
}

// WithBrowserCommand sets the browser launch command.
func WithBrowserCommand(cmd string) BrowserOption {
	return func(p *BrowserProvider) {
		p.BrowserCommand = cmd
	}
}

// WithTimeout sets the ceremony timeout.
func WithTimeout(timeout string) BrowserOption {
	return func(p *BrowserProvider) {
		p.Timeout = timeout
	}
}

// WithBrowserRPID sets the relying party ID.
func WithBrowserRPID(rpID string) BrowserOption {
	return func(p *BrowserProvider) {
		p.RPID = rpID
	}
}

// SupportsExtension checks if an extension is available.
func (p *BrowserProvider) SupportsExtension(ext ExtensionID) bool {
	// Browser supports all standard extensions
	switch ext {
	case ExtensionPRF:
		return true
	case ExtensionLargeBlob:
		return true
	default:
		return false
	}
}

// ListDevices returns a list of connected FIDO2 devices.
func (p *BrowserProvider) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	// Browser provider doesn't have direct device access
	return []DeviceInfo{
		{
			Path:         "browser",
			ProductName:  "Browser WebAuthn",
			PRFSupported: true,
		},
	}, nil
}

// browserCeremony handles a WebAuthn ceremony via browser.
type browserCeremony struct {
	provider   *BrowserProvider
	resultChan chan *browserResult
	errChan    chan error
	server     *http.Server
	listener   net.Listener
	mu         sync.Mutex
	done       bool
}

type browserResult struct {
	Registration   *RegistrationResult
	Authentication *AssertionResult
}

func (p *BrowserProvider) newCeremony() (*browserCeremony, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.CallbackPort))
	if err != nil {
		return nil, fmt.Errorf("failed to start listener: %w", err)
	}

	c := &browserCeremony{
		provider:   p,
		resultChan: make(chan *browserResult, 1),
		errChan:    make(chan error, 1),
		listener:   listener,
	}

	return c, nil
}

func (c *browserCeremony) port() int {
	return c.listener.Addr().(*net.TCPAddr).Port
}

func (c *browserCeremony) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		c.done = true
		if c.server != nil {
			c.server.Close()
		}
		c.listener.Close()
	}
}

// Register performs a WebAuthn registration ceremony via browser.
func (p *BrowserProvider) Register(ctx context.Context, opts *RegisterOptions) (*RegistrationResult, error) {
	ceremony, err := p.newCeremony()
	if err != nil {
		return nil, err
	}
	defer ceremony.close()

	// Generate a random state token for CSRF protection
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	rpID := opts.RPID
	if rpID == "" {
		rpID = p.RPID
	}

	// Prepare registration options for the browser
	regOpts := map[string]interface{}{
		"challenge": base64.URLEncoding.EncodeToString(opts.Challenge),
		"rp": map[string]string{
			"id":   rpID,
			"name": opts.RPName,
		},
		"user": map[string]interface{}{
			"id":          base64.URLEncoding.EncodeToString(opts.UserID),
			"name":        opts.UserName,
			"displayName": opts.UserDisplayName,
		},
		"pubKeyCredParams": []map[string]interface{}{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"authenticatorSelection": map[string]interface{}{
			"residentKey":      boolToResidentKey(opts.ResidentKey),
			"userVerification": string(opts.UserVerification),
		},
		"attestation": string(opts.Attestation),
		"extensions": map[string]interface{}{
			"prf": opts.EnablePRF,
		},
	}

	regOptsJSON, _ := json.Marshal(regOpts)

	// Set up HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(generateRegistrationHTML(string(regOptsJSON), state, ceremony.port())))
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		ceremony.handleRegistrationCallback(w, r, state)
	})

	ceremony.server = &http.Server{Handler: mux}
	go ceremony.server.Serve(ceremony.listener)

	// Open browser
	url := fmt.Sprintf("http://127.0.0.1:%d/", ceremony.port())
	if err := openBrowser(url, p.BrowserCommand); err != nil {
		return nil, fmt.Errorf("failed to open browser: %w", err)
	}

	// Wait for result or timeout
	timeout, _ := time.ParseDuration(p.Timeout)
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	select {
	case result := <-ceremony.resultChan:
		return result.Registration, nil
	case err := <-ceremony.errChan:
		return nil, err
	case <-time.After(timeout):
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *browserCeremony) handleRegistrationCallback(w http.ResponseWriter, r *http.Request, expectedState string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		State        string `json:"state"`
		Error        string `json:"error"`
		CredentialID string `json:"credentialId"`
		PublicKey    string `json:"publicKey"`
		AuthData     string `json:"authData"`
		ClientData   string `json:"clientDataJSON"`
		PRFSupported bool   `json:"prfSupported"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.errChan <- fmt.Errorf("failed to decode callback: %w", err)
		return
	}

	if req.State != expectedState {
		c.errChan <- fmt.Errorf("invalid state token")
		return
	}

	if req.Error != "" {
		c.errChan <- fmt.Errorf("browser error: %s", req.Error)
		w.Write([]byte(`{"status":"error"}`))
		return
	}

	credID, _ := base64.URLEncoding.DecodeString(req.CredentialID)
	pubKey, _ := base64.URLEncoding.DecodeString(req.PublicKey)
	authData, _ := base64.URLEncoding.DecodeString(req.AuthData)
	clientData, _ := base64.URLEncoding.DecodeString(req.ClientData)

	c.resultChan <- &browserResult{
		Registration: &RegistrationResult{
			CredentialID:      credID,
			PublicKey:         pubKey,
			AttestationObject: authData,
			ClientDataJSON:    clientData,
			PRFSupported:      req.PRFSupported,
		},
	}

	w.Write([]byte(`{"status":"ok"}`))
}

// Authenticate performs a WebAuthn authentication ceremony via browser.
func (p *BrowserProvider) Authenticate(ctx context.Context, opts *AuthenticateOptions) (*AssertionResult, error) {
	ceremony, err := p.newCeremony()
	if err != nil {
		return nil, err
	}
	defer ceremony.close()

	// Generate a random state token
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	rpID := opts.RPID
	if rpID == "" {
		rpID = p.RPID
	}

	// Build allowed credentials
	allowCredentials := make([]map[string]interface{}, len(opts.AllowCredentials))
	for i, cid := range opts.AllowCredentials {
		allowCredentials[i] = map[string]interface{}{
			"type": "public-key",
			"id":   base64.URLEncoding.EncodeToString(cid),
		}
	}

	// Build PRF extension inputs
	prfExt := map[string]interface{}{}
	if len(opts.PRFSalt1) > 0 {
		evalInput := map[string]interface{}{
			"first": base64.URLEncoding.EncodeToString(opts.PRFSalt1),
		}
		if len(opts.PRFSalt2) > 0 {
			evalInput["second"] = base64.URLEncoding.EncodeToString(opts.PRFSalt2)
		}
		prfExt["eval"] = evalInput
	}

	// Prepare authentication options
	authOpts := map[string]interface{}{
		"challenge":        base64.URLEncoding.EncodeToString(opts.Challenge),
		"rpId":             rpID,
		"userVerification": string(opts.UserVerification),
		"allowCredentials": allowCredentials,
		"extensions": map[string]interface{}{
			"prf": prfExt,
		},
	}

	authOptsJSON, _ := json.Marshal(authOpts)

	// Set up HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(generateAuthenticationHTML(string(authOptsJSON), state, ceremony.port())))
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		ceremony.handleAuthenticationCallback(w, r, state)
	})

	ceremony.server = &http.Server{Handler: mux}
	go ceremony.server.Serve(ceremony.listener)

	// Open browser
	url := fmt.Sprintf("http://127.0.0.1:%d/", ceremony.port())
	if err := openBrowser(url, p.BrowserCommand); err != nil {
		return nil, fmt.Errorf("failed to open browser: %w", err)
	}

	// Wait for result or timeout
	timeout, _ := time.ParseDuration(p.Timeout)
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	select {
	case result := <-ceremony.resultChan:
		return result.Authentication, nil
	case err := <-ceremony.errChan:
		return nil, err
	case <-time.After(timeout):
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *browserCeremony) handleAuthenticationCallback(w http.ResponseWriter, r *http.Request, expectedState string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		State        string `json:"state"`
		Error        string `json:"error"`
		CredentialID string `json:"credentialId"`
		AuthData     string `json:"authenticatorData"`
		Signature    string `json:"signature"`
		UserHandle   string `json:"userHandle"`
		ClientData   string `json:"clientDataJSON"`
		PRFFirst     string `json:"prfFirst"`
		PRFSecond    string `json:"prfSecond"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.errChan <- fmt.Errorf("failed to decode callback: %w", err)
		return
	}

	if req.State != expectedState {
		c.errChan <- fmt.Errorf("invalid state token")
		return
	}

	if req.Error != "" {
		c.errChan <- fmt.Errorf("browser error: %s", req.Error)
		w.Write([]byte(`{"status":"error"}`))
		return
	}

	credID, _ := base64.URLEncoding.DecodeString(req.CredentialID)
	authData, _ := base64.URLEncoding.DecodeString(req.AuthData)
	sig, _ := base64.URLEncoding.DecodeString(req.Signature)
	userHandle, _ := base64.URLEncoding.DecodeString(req.UserHandle)

	result := &AssertionResult{
		CredentialID: credID,
		AuthData:     authData,
		Signature:    sig,
		UserHandle:   userHandle,
	}

	// Extract PRF output if present
	if req.PRFFirst != "" {
		prfFirst, _ := base64.URLEncoding.DecodeString(req.PRFFirst)
		result.PRFOutput = &PRFOutput{First: prfFirst}
		if req.PRFSecond != "" {
			prfSecond, _ := base64.URLEncoding.DecodeString(req.PRFSecond)
			result.PRFOutput.Second = prfSecond
		}
	}

	c.resultChan <- &browserResult{Authentication: result}
	w.Write([]byte(`{"status":"ok"}`))
}

// GetPRFOutput evaluates the PRF extension with the given salts.
func (p *BrowserProvider) GetPRFOutput(ctx context.Context, credential CredentialID, salt1, salt2 []byte) (*PRFOutput, error) {
	result, err := p.Authenticate(ctx, &AuthenticateOptions{
		AllowCredentials: []CredentialID{credential},
		UserVerification: UVRequired,
		PRFSalt1:         salt1,
		PRFSalt2:         salt2,
	})
	if err != nil {
		return nil, err
	}
	return result.PRFOutput, nil
}

// Helper functions

func boolToResidentKey(b bool) string {
	if b {
		return "required"
	}
	return "discouraged"
}

func openBrowser(url, customCmd string) error {
	var cmd *exec.Cmd

	if customCmd != "" {
		cmd = exec.Command(customCmd, url)
	} else {
		switch runtime.GOOS {
		case "linux":
			cmd = exec.Command("xdg-open", url)
		case "darwin":
			cmd = exec.Command("open", url)
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		default:
			return fmt.Errorf("unsupported platform")
		}
	}

	return cmd.Start()
}

// Ensure BrowserProvider implements Provider
var _ Provider = (*BrowserProvider)(nil)
