package daemon

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"

	daemonv1 "github.com/sirosfoundation/go-siros-cli/api/proto/daemon/v1"
	"github.com/sirosfoundation/go-siros-cli/internal/daemon/ipc"
	"github.com/sirosfoundation/go-siros-cli/pkg/keystore"
	"github.com/sirosfoundation/go-siros-cli/pkg/pinentry"
)

// Server is the gRPC server for the wallet daemon.
type Server struct {
	daemonv1.UnimplementedWalletDaemonServer
	engine     Engine
	grpcServer *grpc.Server
	listener   *ipc.Listener
	tenantID   string
}

// ServerConfig contains configuration for the gRPC server.
type ServerConfig struct {
	SocketPath string
	Engine     Engine
	TenantID   string
}

// NewServer creates a new gRPC server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("engine is required")
	}

	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	listener, err := ipc.NewUnixListener(socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	grpcServer := grpc.NewServer()

	server := &Server{
		engine:     cfg.Engine,
		grpcServer: grpcServer,
		listener:   listener,
		tenantID:   cfg.TenantID,
	}

	// Register the gRPC service
	daemonv1.RegisterWalletDaemonServer(grpcServer, server)

	return server, nil
}

// Serve starts the gRPC server.
func (s *Server) Serve() error {
	return s.grpcServer.Serve(s.listener)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

// SocketPath returns the socket path.
func (s *Server) SocketPath() string {
	return s.listener.SocketPath()
}

// --- gRPC Method Implementations ---

// Status returns the daemon status.
func (s *Server) Status(ctx context.Context, req *daemonv1.StatusRequest) (*daemonv1.StatusResponse, error) {
	status, err := s.engine.Status(ctx)
	if err != nil {
		return nil, err
	}

	resp := &daemonv1.StatusResponse{
		Running:  true,
		Unlocked: status.Unlocked,
		KeyCount: int32(status.KeyCount),
		TenantId: status.TenantID,
	}

	// Calculate remaining timeout
	if status.Unlocked && !status.SessionTimeout.IsZero() {
		remaining := time.Until(status.SessionTimeout)
		if remaining > 0 {
			resp.TimeoutRemaining = int32(remaining.Seconds())
		}
	}

	return resp, nil
}

// UnlockWithPRF unlocks using FIDO2 PRF.
func (s *Server) UnlockWithPRF(ctx context.Context, req *daemonv1.UnlockWithPRFRequest) (*daemonv1.UnlockResponse, error) {
	// This would need to coordinate with FIDO2 provider
	// For now, return not implemented
	return &daemonv1.UnlockResponse{
		Success: false,
		Error:   "PRF unlock via daemon not yet implemented - unlock interactively first",
	}, nil
}

// UnlockWithPassword unlocks using a password.
func (s *Server) UnlockWithPassword(ctx context.Context, req *daemonv1.UnlockWithPasswordRequest) (*daemonv1.UnlockResponse, error) {
	// Get encrypted data from backend
	client := s.engine.GetBackendClient()
	if client == nil {
		return &daemonv1.UnlockResponse{
			Success: false,
			Error:   "backend client not configured",
		}, nil
	}

	accountInfo, err := client.GetAccountInfo(ctx)
	if err != nil {
		return &daemonv1.UnlockResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to get account info: %v", err),
		}, nil
	}

	// Extract encrypted data
	var encryptedData []byte
	if pdMap, ok := accountInfo.PrivateData.(map[string]interface{}); ok {
		if jsonData, err := json.Marshal(pdMap); err == nil {
			encryptedData = jsonData
		}
	}

	if len(encryptedData) == 0 {
		return &daemonv1.UnlockResponse{
			Success: false,
			Error:   "no keystore data found",
		}, nil
	}

	err = s.engine.UnlockWithPassword(ctx, req.Password, encryptedData)
	if err != nil {
		return &daemonv1.UnlockResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &daemonv1.UnlockResponse{
		Success: true,
	}, nil
}

// Lock locks the keystore.
func (s *Server) Lock(ctx context.Context, req *daemonv1.LockRequest) (*daemonv1.LockResponse, error) {
	err := s.engine.Lock(ctx)
	if err != nil {
		return &daemonv1.LockResponse{Success: false}, err
	}
	return &daemonv1.LockResponse{Success: true}, nil
}

// SignJWT signs a JWT.
func (s *Server) SignJWT(ctx context.Context, req *daemonv1.SignJWTRequest) (*daemonv1.SignJWTResponse, error) {
	if !s.engine.IsUnlocked() {
		return &daemonv1.SignJWTResponse{
			Error: "keystore is locked",
		}, nil
	}

	// Parse claims from JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(req.ClaimsJson, &claims); err != nil {
		return &daemonv1.SignJWTResponse{
			Error: fmt.Sprintf("invalid claims JSON: %v", err),
		}, nil
	}

	// Add any extra headers
	for k, v := range req.Headers {
		claims[k] = v
	}

	jwt, err := s.engine.SignJWT(ctx, req.KeyId, claims)
	if err != nil {
		return &daemonv1.SignJWTResponse{
			Error: err.Error(),
		}, nil
	}

	// Reset timeout on activity
	s.engine.ResetTimeout()

	return &daemonv1.SignJWTResponse{
		Jwt: jwt,
	}, nil
}

// Sign performs a raw signature.
func (s *Server) Sign(ctx context.Context, req *daemonv1.SignRequest) (*daemonv1.SignResponse, error) {
	if !s.engine.IsUnlocked() {
		return &daemonv1.SignResponse{
			Error: "keystore is locked",
		}, nil
	}

	signature, err := s.engine.Sign(ctx, req.KeyId, req.Data)
	if err != nil {
		return &daemonv1.SignResponse{
			Error: err.Error(),
		}, nil
	}

	// Reset timeout on activity
	s.engine.ResetTimeout()

	return &daemonv1.SignResponse{
		Signature: signature,
	}, nil
}

// ListKeys returns available keys.
func (s *Server) ListKeys(ctx context.Context, req *daemonv1.ListKeysRequest) (*daemonv1.ListKeysResponse, error) {
	if !s.engine.IsUnlocked() {
		return &daemonv1.ListKeysResponse{
			Keys: []*daemonv1.KeyInfo{},
		}, nil
	}

	keys, err := s.engine.ListKeys()
	if err != nil {
		return nil, err
	}

	protoKeys := make([]*daemonv1.KeyInfo, len(keys))
	for i, k := range keys {
		protoKeys[i] = &daemonv1.KeyInfo{
			KeyId:     k.KeyID,
			Algorithm: k.Algorithm,
			// PRF info would be added if available
		}
	}

	return &daemonv1.ListKeysResponse{
		Keys: protoKeys,
	}, nil
}

// GetApproval requests user approval.
func (s *Server) GetApproval(ctx context.Context, req *daemonv1.GetApprovalRequest) (*daemonv1.GetApprovalResponse, error) {
	// Build description from request
	description := fmt.Sprintf("Operation: %s\nDetails: %s",
		req.GetOperationType(),
		req.GetDescription())

	timeout := int(req.GetTimeoutSeconds())
	if timeout <= 0 {
		timeout = 60 // default 60 seconds
	}

	cfg := &pinentry.ConfirmConfig{
		Title:        "Wallet Operation Approval",
		Description:  description,
		OKButton:     "Approve",
		CancelButton: "Deny",
		Timeout:      timeout,
	}

	approved, err := pinentry.GetConfirmation(cfg)
	if err != nil {
		return &daemonv1.GetApprovalResponse{
			Approved: false,
			Error:    fmt.Sprintf("approval dialog failed: %v", err),
		}, nil
	}

	return &daemonv1.GetApprovalResponse{
		Approved: approved,
	}, nil
}

// Client is a helper for connecting to the daemon.
type Client struct {
	conn       *grpc.ClientConn
	client     daemonv1.WalletDaemonClient
	socketPath string
}

// NewClient creates a new daemon client.
func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	// Check if daemon is running
	if !ipc.IsDaemonRunning(socketPath) {
		return nil, fmt.Errorf("daemon not running at %s", socketPath)
	}

	// Connect via Unix socket
	conn, err := grpc.Dial(
		"unix://"+socketPath,
		grpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}

	return &Client{
		conn:       conn,
		client:     daemonv1.NewWalletDaemonClient(conn),
		socketPath: socketPath,
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Status returns the daemon status.
func (c *Client) Status(ctx context.Context) (*daemonv1.StatusResponse, error) {
	return c.client.Status(ctx, &daemonv1.StatusRequest{})
}

// Lock locks the daemon keystore.
func (c *Client) Lock(ctx context.Context) (*daemonv1.LockResponse, error) {
	return c.client.Lock(ctx, &daemonv1.LockRequest{})
}

// ListKeys returns available keys.
func (c *Client) ListKeys(ctx context.Context) (*daemonv1.ListKeysResponse, error) {
	return c.client.ListKeys(ctx, &daemonv1.ListKeysRequest{})
}

// SignJWT signs a JWT using the daemon.
func (c *Client) SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error) {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	resp, err := c.client.SignJWT(ctx, &daemonv1.SignJWTRequest{
		KeyId:      keyID,
		ClaimsJson: claimsJSON,
	})
	if err != nil {
		return "", err
	}

	if resp.Error != "" {
		return "", fmt.Errorf("%s", resp.Error)
	}

	return resp.Jwt, nil
}

// Sign performs a raw signature via the daemon.
func (c *Client) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	resp, err := c.client.Sign(ctx, &daemonv1.SignRequest{
		KeyId: keyID,
		Data:  data,
	})
	if err != nil {
		return nil, err
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	return resp.Signature, nil
}

// IsDaemonRunning checks if a daemon is running.
func IsDaemonRunning() bool {
	return ipc.IsDaemonRunning(ipc.DefaultSocketPath())
}

// ConnectToDaemon attempts to connect to a running daemon.
func ConnectToDaemon() (*Client, error) {
	return NewClient(ipc.DefaultSocketPath())
}

// KeystoreInterface provides a compatible interface for daemon or direct keystore.
type KeystoreInterface interface {
	IsUnlocked() bool
	ListKeys() ([]keystore.KeyInfo, error)
	GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error)
	SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error)
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)
	Lock() error
}

// Ensure Client implements KeystoreInterface
var _ KeystoreInterface = (*daemonKeystore)(nil)

// daemonKeystore wraps a daemon client to provide KeystoreInterface.
type daemonKeystore struct {
	client *Client
}

// WrapDaemonAsKeystore wraps a daemon client as a KeystoreInterface.
func WrapDaemonAsKeystore(c *Client) KeystoreInterface {
	return &daemonKeystore{client: c}
}

func (d *daemonKeystore) IsUnlocked() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := d.client.Status(ctx)
	if err != nil {
		return false
	}
	return status.Unlocked
}

func (d *daemonKeystore) ListKeys() ([]keystore.KeyInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := d.client.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]keystore.KeyInfo, len(resp.Keys))
	for i, k := range resp.Keys {
		keys[i] = keystore.KeyInfo{
			KeyID:     k.KeyId,
			Algorithm: k.Algorithm,
		}
	}
	return keys, nil
}

func (d *daemonKeystore) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	// Private keys cannot be extracted from daemon - this is intentional
	return nil, fmt.Errorf("private key extraction not supported via daemon")
}

func (d *daemonKeystore) SignJWT(ctx context.Context, keyID string, claims map[string]interface{}) (string, error) {
	return d.client.SignJWT(ctx, keyID, claims)
}

func (d *daemonKeystore) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	return d.client.Sign(ctx, keyID, data)
}

func (d *daemonKeystore) Lock() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.client.Lock(ctx)
	return err
}
