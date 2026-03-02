// Package mcp provides a Model Context Protocol server for the wallet daemon.
//
// The MCP server allows AI assistants to interact with the wallet through
// a standardized JSON-RPC 2.0 protocol over stdio.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirosfoundation/go-siros-cli/internal/daemon"
)

// JSON-RPC 2.0 types

// Request represents a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
}

// Error represents a JSON-RPC 2.0 error.
type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes
const (
	ErrParseError     = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternalError  = -32603
)

// MCP Protocol types

// ServerInfo describes the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientInfo describes the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeParams contains parameters for the initialize method.
type InitializeParams struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ClientInfo      ClientInfo   `json:"clientInfo"`
	Capabilities    Capabilities `json:"capabilities,omitempty"`
}

// Capabilities describes MCP capabilities.
type Capabilities struct {
	Tools     *ToolCapabilities     `json:"tools,omitempty"`
	Resources *ResourceCapabilities `json:"resources,omitempty"`
}

// ToolCapabilities describes tool capabilities.
type ToolCapabilities struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourceCapabilities describes resource capabilities.
type ResourceCapabilities struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeResult contains the result of initialization.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Capabilities    Capabilities `json:"capabilities"`
}

// Tool represents an MCP tool definition.
type Tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema JSONSchema `json:"inputSchema"`
}

// JSONSchema represents a JSON Schema for tool parameters.
type JSONSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]PropertySchema `json:"properties,omitempty"`
	Required   []string                  `json:"required,omitempty"`
}

// PropertySchema represents a property in a JSON Schema.
type PropertySchema struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

// ToolsListResult contains the list of available tools.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// ToolCallParams contains parameters for a tool call.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolCallResult contains the result of a tool call.
type ToolCallResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ContentItem represents content in a tool result.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Server is the MCP server for the wallet.
type Server struct {
	mu       sync.Mutex
	client   *daemon.Client
	input    io.Reader
	output   io.Writer
	shutdown chan struct{}
}

// ServerConfig contains configuration for the MCP server.
type ServerConfig struct {
	SocketPath string
	Input      io.Reader
	Output     io.Writer
}

// NewServer creates a new MCP server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	input := cfg.Input
	if input == nil {
		input = os.Stdin
	}

	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}

	s := &Server{
		input:    input,
		output:   output,
		shutdown: make(chan struct{}),
	}

	// Try to connect to daemon
	if cfg.SocketPath != "" {
		client, err := daemon.NewClient(cfg.SocketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to daemon: %w", err)
		}
		s.client = client
	} else {
		// Try default socket
		client, err := daemon.ConnectToDaemon()
		if err == nil {
			s.client = client
		}
		// It's OK if daemon isn't running - some tools will be unavailable
	}

	return s, nil
}

// Run starts the MCP server, processing requests until shutdown.
func (s *Server) Run() error {
	scanner := bufio.NewScanner(s.input)
	// Set a large buffer for potentially large JSON messages
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-s.shutdown:
			return nil
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendError(nil, ErrParseError, "Parse error", err.Error())
			continue
		}

		s.handleRequest(&req)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() {
	close(s.shutdown)
	if s.client != nil {
		s.client.Close()
	}
}

func (s *Server) handleRequest(req *Request) {
	if req.JSONRPC != "2.0" {
		s.sendError(req.ID, ErrInvalidRequest, "Invalid Request", "jsonrpc must be 2.0")
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "initialized":
		// Notification - no response needed
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	default:
		s.sendError(req.ID, ErrMethodNotFound, "Method not found", req.Method)
	}
}

func (s *Server) handleInitialize(req *Request) {
	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		ServerInfo: ServerInfo{
			Name:    "wallet-cli-mcp",
			Version: "0.1.0",
		},
		Capabilities: Capabilities{
			Tools: &ToolCapabilities{
				ListChanged: false,
			},
		},
	}

	s.sendResult(req.ID, result)
}

func (s *Server) handleToolsList(req *Request) {
	tools := []Tool{
		{
			Name:        "wallet_status",
			Description: "Get the status of the wallet daemon (running, unlocked, key count)",
			InputSchema: JSONSchema{
				Type:       "object",
				Properties: map[string]PropertySchema{},
			},
		},
		{
			Name:        "wallet_list_keys",
			Description: "List all keys in the wallet",
			InputSchema: JSONSchema{
				Type:       "object",
				Properties: map[string]PropertySchema{},
			},
		},
		{
			Name:        "wallet_lock",
			Description: "Lock the wallet, securing all keys",
			InputSchema: JSONSchema{
				Type:       "object",
				Properties: map[string]PropertySchema{},
			},
		},
		{
			Name:        "wallet_sign_jwt",
			Description: "Sign a JWT using a wallet key",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]PropertySchema{
					"key_id": {
						Type:        "string",
						Description: "The ID of the key to use for signing",
					},
					"claims": {
						Type:        "object",
						Description: "The JWT claims to sign (as JSON object)",
					},
				},
				Required: []string{"key_id", "claims"},
			},
		},
	}

	s.sendResult(req.ID, ToolsListResult{Tools: tools})
}

func (s *Server) handleToolsCall(req *Request) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, ErrInvalidParams, "Invalid params", err.Error())
		return
	}

	switch params.Name {
	case "wallet_status":
		s.handleWalletStatus(req)
	case "wallet_list_keys":
		s.handleWalletListKeys(req)
	case "wallet_lock":
		s.handleWalletLock(req)
	case "wallet_sign_jwt":
		s.handleWalletSignJWT(req, params.Arguments)
	default:
		s.sendError(req.ID, ErrInvalidParams, "Unknown tool", params.Name)
	}
}

func (s *Server) handleWalletStatus(req *Request) {
	if s.client == nil {
		s.sendToolResult(req.ID, "Wallet daemon is not running. Start it with: wallet-cli daemon start", true)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := s.client.Status(ctx)
	if err != nil {
		s.sendToolResult(req.ID, fmt.Sprintf("Failed to get status: %v", err), true)
		return
	}

	result := fmt.Sprintf("Wallet Status:\n"+
		"- Running: %v\n"+
		"- Unlocked: %v\n"+
		"- Key Count: %d\n"+
		"- Tenant ID: %s\n",
		status.Running, status.Unlocked, status.KeyCount, status.TenantId)

	if status.TimeoutRemaining > 0 {
		result += fmt.Sprintf("- Session timeout in: %d seconds\n", status.TimeoutRemaining)
	}

	s.sendToolResult(req.ID, result, false)
}

func (s *Server) handleWalletListKeys(req *Request) {
	if s.client == nil {
		s.sendToolResult(req.ID, "Wallet daemon is not running. Start it with: wallet-cli daemon start", true)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.client.ListKeys(ctx)
	if err != nil {
		s.sendToolResult(req.ID, fmt.Sprintf("Failed to list keys: %v", err), true)
		return
	}

	if len(resp.Keys) == 0 {
		s.sendToolResult(req.ID, "No keys available. The wallet may be locked.", false)
		return
	}

	result := fmt.Sprintf("Found %d key(s):\n", len(resp.Keys))
	for _, key := range resp.Keys {
		result += fmt.Sprintf("- %s (algorithm: %s)\n", key.KeyId, key.Algorithm)
	}

	s.sendToolResult(req.ID, result, false)
}

func (s *Server) handleWalletLock(req *Request) {
	if s.client == nil {
		s.sendToolResult(req.ID, "Wallet daemon is not running. Start it with: wallet-cli daemon start", true)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.client.Lock(ctx)
	if err != nil {
		s.sendToolResult(req.ID, fmt.Sprintf("Failed to lock wallet: %v", err), true)
		return
	}

	if resp.Success {
		s.sendToolResult(req.ID, "Wallet locked successfully.", false)
	} else {
		s.sendToolResult(req.ID, "Failed to lock wallet.", true)
	}
}

type signJWTArgs struct {
	KeyID  string                 `json:"key_id"`
	Claims map[string]interface{} `json:"claims"`
}

func (s *Server) handleWalletSignJWT(req *Request, args json.RawMessage) {
	if s.client == nil {
		s.sendToolResult(req.ID, "Wallet daemon is not running. Start it with: wallet-cli daemon start", true)
		return
	}

	var params signJWTArgs
	if err := json.Unmarshal(args, &params); err != nil {
		s.sendToolResult(req.ID, fmt.Sprintf("Invalid arguments: %v", err), true)
		return
	}

	if params.KeyID == "" {
		s.sendToolResult(req.ID, "key_id is required", true)
		return
	}

	if params.Claims == nil {
		s.sendToolResult(req.ID, "claims is required", true)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jwt, err := s.client.SignJWT(ctx, params.KeyID, params.Claims)
	if err != nil {
		s.sendToolResult(req.ID, fmt.Sprintf("Failed to sign JWT: %v", err), true)
		return
	}

	s.sendToolResult(req.ID, fmt.Sprintf("Signed JWT:\n%s", jwt), false)
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeResponse(resp)
}

func (s *Server) sendError(id interface{}, code int, message string, data interface{}) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	s.writeResponse(resp)
}

func (s *Server) sendToolResult(id interface{}, text string, isError bool) {
	result := ToolCallResult{
		Content: []ContentItem{
			{
				Type: "text",
				Text: text,
			},
		},
		IsError: isError,
	}
	s.sendResult(id, result)
}

func (s *Server) writeResponse(resp Response) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, _ := json.Marshal(resp)
	fmt.Fprintln(s.output, string(data))
}
