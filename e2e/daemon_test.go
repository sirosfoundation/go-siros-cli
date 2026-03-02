//go:build e2e
// +build e2e

// Package e2e contains end-to-end integration tests for go-siros-cli.
// This file contains tests specific to the daemon functionality.
package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/go-siros-cli/internal/daemon"
	"github.com/sirosfoundation/go-siros-cli/internal/daemon/ipc"
)

// TestDaemonStartStop tests basic daemon lifecycle.
func TestDaemonStartStop(t *testing.T) {
	config := DefaultTestConfig()

	// Create a unique socket path for this test
	tempDir, err := os.MkdirTemp("", "daemon-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "wallet.sock")

	// Create engine configuration
	engineCfg := &daemon.EngineConfig{
		BackendURL:     config.BackendURL,
		TenantID:       config.TenantID,
		SessionTimeout: 5 * time.Minute,
	}

	// Create engine
	engine, err := daemon.NewEngine(engineCfg)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Create server
	serverCfg := &daemon.ServerConfig{
		SocketPath: socketPath,
		Engine:     engine,
		TenantID:   config.TenantID,
	}

	server, err := daemon.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Verify daemon is running
	if !ipc.IsDaemonRunning(socketPath) {
		t.Fatal("Daemon should be running after Serve()")
	}

	// Connect as client
	client, err := daemon.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to daemon: %v", err)
	}

	// Check status
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Failed to get status: %v", err)
	}

	if !status.Running {
		t.Error("Expected daemon to be running")
	}

	// Note: Keystore should be locked since we haven't unlocked it
	if status.Unlocked {
		t.Error("Expected keystore to be locked")
	}

	// Close client
	client.Close()

	// Stop server
	server.Stop()

	// Check server stopped
	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("Server stopped with error (expected): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server did not stop within timeout")
	}

	// Verify socket is cleaned up (listener should have removed it)
	time.Sleep(100 * time.Millisecond)
	if ipc.IsDaemonRunning(socketPath) {
		t.Error("Daemon should not be running after Stop()")
	}
}

// TestDaemonStatusQueryRoundtrip tests status query through the daemon.
func TestDaemonStatusQueryRoundtrip(t *testing.T) {
	config := DefaultTestConfig()

	tempDir, err := os.MkdirTemp("", "daemon-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "wallet.sock")

	// Create engine with specific settings
	engineCfg := &daemon.EngineConfig{
		BackendURL:     config.BackendURL,
		TenantID:       "test-tenant-123",
		SessionTimeout: 10 * time.Minute,
	}

	engine, err := daemon.NewEngine(engineCfg)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	serverCfg := &daemon.ServerConfig{
		SocketPath: socketPath,
		Engine:     engine,
		TenantID:   "test-tenant-123",
	}

	server, err := daemon.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	go func() {
		server.Serve()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Connect as client
	client, err := daemon.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to daemon: %v", err)
	}
	defer client.Close()

	// Query status
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status query failed: %v", err)
	}

	// Verify status fields
	if !status.Running {
		t.Error("Expected Running=true")
	}

	if status.TenantId != "test-tenant-123" {
		t.Errorf("Expected TenantId='test-tenant-123', got '%s'", status.TenantId)
	}
}

// TestDaemonLockOperation tests lock operation through the daemon.
func TestDaemonLockOperation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "daemon-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "wallet.sock")

	engineCfg := &daemon.EngineConfig{
		BackendURL:     "http://test.local",
		SessionTimeout: 5 * time.Minute,
	}

	engine, err := daemon.NewEngine(engineCfg)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	serverCfg := &daemon.ServerConfig{
		SocketPath: socketPath,
		Engine:     engine,
	}

	server, err := daemon.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		server.Serve()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := daemon.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Lock operation should succeed even when already locked
	resp, err := client.Lock(ctx)
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected Lock to succeed")
	}

	// Verify status shows locked
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status query failed: %v", err)
	}

	if status.Unlocked {
		t.Error("Expected keystore to be locked after Lock()")
	}
}

// TestDaemonListKeysEmpty tests ListKeys when keystore is locked/empty.
func TestDaemonListKeysEmpty(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "daemon-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "wallet.sock")

	engineCfg := &daemon.EngineConfig{
		BackendURL:     "http://test.local",
		SessionTimeout: 5 * time.Minute,
	}

	engine, err := daemon.NewEngine(engineCfg)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	serverCfg := &daemon.ServerConfig{
		SocketPath: socketPath,
		Engine:     engine,
	}

	server, err := daemon.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		server.Serve()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := daemon.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ListKeys should return empty when locked
	resp, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp.Keys) != 0 {
		t.Errorf("Expected empty key list, got %d keys", len(resp.Keys))
	}
}

// TestMultipleClientConnections tests multiple clients connecting to same daemon.
func TestMultipleClientConnections(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "daemon-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "wallet.sock")

	engineCfg := &daemon.EngineConfig{
		BackendURL:     "http://test.local",
		SessionTimeout: 5 * time.Minute,
	}

	engine, err := daemon.NewEngine(engineCfg)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	serverCfg := &daemon.ServerConfig{
		SocketPath: socketPath,
		Engine:     engine,
	}

	server, err := daemon.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		server.Serve()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create multiple clients
	client1, err := daemon.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to connect client 1: %v", err)
	}
	defer client1.Close()

	client2, err := daemon.NewClient(socketPath)
	if err != nil {
		t.Fatalf("Failed to connect client 2: %v", err)
	}
	defer client2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Both clients should get consistent status
	status1, err := client1.Status(ctx)
	if err != nil {
		t.Fatalf("Client 1 status failed: %v", err)
	}

	status2, err := client2.Status(ctx)
	if err != nil {
		t.Fatalf("Client 2 status failed: %v", err)
	}

	if status1.Running != status2.Running {
		t.Error("Inconsistent Running status between clients")
	}

	if status1.Unlocked != status2.Unlocked {
		t.Error("Inconsistent Unlocked status between clients")
	}
}
