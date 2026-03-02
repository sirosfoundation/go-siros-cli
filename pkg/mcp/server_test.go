package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewServer(t *testing.T) {
	input := strings.NewReader("")
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if server == nil {
		t.Fatal("NewServer() returned nil server")
	}
}

func TestServer_Initialize(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}
`)
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Parse response
	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("Response contains error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Result is not a map: %T", resp.Result)
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion = %v, want 2024-11-05", result["protocolVersion"])
	}

	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatalf("serverInfo is not a map")
	}

	if serverInfo["name"] != "wallet-cli-mcp" {
		t.Errorf("serverInfo.name = %v, want wallet-cli-mcp", serverInfo["name"])
	}
}

func TestServer_ToolsList(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}
`)
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Parse response
	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("Response contains error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Result is not a map: %T", resp.Result)
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("tools is not an array")
	}

	// Should have at least 4 tools
	if len(tools) < 4 {
		t.Errorf("Expected at least 4 tools, got %d", len(tools))
	}

	// Check that expected tools are present
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		toolNames[name] = true
	}

	expectedTools := []string{"wallet_status", "wallet_list_keys", "wallet_lock", "wallet_sign_jwt"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Missing expected tool: %s", name)
		}
	}
}

func TestServer_ToolCall_WalletStatus_NoDaemon(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wallet_status"}}
`)
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Ensure no daemon client is connected
	server.client = nil

	err = server.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Parse response
	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("Response contains error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Result is not a map: %T", resp.Result)
	}

	// Should indicate daemon isn't running
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Missing content in result")
	}

	firstContent := content[0].(map[string]interface{})
	text := firstContent["text"].(string)
	if !strings.Contains(text, "not running") {
		t.Errorf("Expected 'not running' message, got: %s", text)
	}

	// Should be an error result
	if isError, ok := result["isError"].(bool); !ok || !isError {
		t.Error("Expected isError to be true")
	}
}

func TestServer_MethodNotFound(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"unknown/method"}
`)
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Parse response
	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected error for unknown method")
	}

	if resp.Error.Code != ErrMethodNotFound {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrMethodNotFound)
	}
}

func TestServer_ParseError(t *testing.T) {
	input := strings.NewReader(`{invalid json}
`)
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Parse response
	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected parse error")
	}

	if resp.Error.Code != ErrParseError {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrParseError)
	}
}

func TestServer_InvalidJSONRPCVersion(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"1.0","id":1,"method":"initialize"}
`)
	output := &bytes.Buffer{}

	server, err := NewServer(&ServerConfig{
		Input:  input,
		Output: output,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Parse response
	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected error for invalid jsonrpc version")
	}

	if resp.Error.Code != ErrInvalidRequest {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrInvalidRequest)
	}
}

func TestToolSchema(t *testing.T) {
	schema := JSONSchema{
		Type: "object",
		Properties: map[string]PropertySchema{
			"key_id": {
				Type:        "string",
				Description: "The key ID",
			},
			"claims": {
				Type:        "object",
				Description: "JWT claims",
			},
		},
		Required: []string{"key_id", "claims"},
	}

	if schema.Type != "object" {
		t.Errorf("Type = %s, want object", schema.Type)
	}

	if len(schema.Properties) != 2 {
		t.Errorf("Properties count = %d, want 2", len(schema.Properties))
	}

	if len(schema.Required) != 2 {
		t.Errorf("Required count = %d, want 2", len(schema.Required))
	}
}

func TestContentItem(t *testing.T) {
	item := ContentItem{
		Type: "text",
		Text: "Hello, world!",
	}

	if item.Type != "text" {
		t.Errorf("Type = %s, want text", item.Type)
	}

	if item.Text != "Hello, world!" {
		t.Errorf("Text = %s, want 'Hello, world!'", item.Text)
	}
}
