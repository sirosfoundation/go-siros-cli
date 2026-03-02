package ipc

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultSocketPath(t *testing.T) {
	path := DefaultSocketPath()
	if path == "" {
		t.Error("DefaultSocketPath() returned empty string")
	}

	if runtime.GOOS == "windows" {
		if path != `\\.\pipe\siros-wallet` {
			t.Errorf("DefaultSocketPath() = %q, want named pipe path", path)
		}
	} else {
		// Should end with siros-wallet.sock
		if filepath.Base(path) != "siros-wallet.sock" {
			t.Errorf("DefaultSocketPath() = %q, want path ending with siros-wallet.sock", path)
		}
	}
}

func TestDefaultSocketPath_XDGRuntimeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG_RUNTIME_DIR not used on Windows")
	}

	// Save and restore original value
	orig := os.Getenv("XDG_RUNTIME_DIR")
	defer os.Setenv("XDG_RUNTIME_DIR", orig)

	// Test with XDG_RUNTIME_DIR set
	os.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	path := DefaultSocketPath()
	expected := "/run/user/1000/siros-wallet.sock"
	if path != expected {
		t.Errorf("DefaultSocketPath() = %q, want %q", path, expected)
	}

	// Test with XDG_RUNTIME_DIR unset
	os.Unsetenv("XDG_RUNTIME_DIR")
	path = DefaultSocketPath()
	expected = "/tmp/siros-wallet.sock"
	if path != expected {
		t.Errorf("DefaultSocketPath() = %q, want %q", path, expected)
	}
}

func TestNewUnixListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}

	// Create a temp directory for the socket
	tempDir, err := os.MkdirTemp("", "ipc-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := NewUnixListener(socketPath)
	if err != nil {
		t.Fatalf("NewUnixListener() error = %v", err)
	}
	defer listener.Close()

	// Check socket was created
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("Socket file was not created")
	}

	// Check socket path is returned correctly
	if listener.SocketPath() != socketPath {
		t.Errorf("SocketPath() = %q, want %q", listener.SocketPath(), socketPath)
	}

	// Check permissions
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Failed to stat socket: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Socket permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestNewUnixListener_ReplacesStaleSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}

	tempDir, err := os.MkdirTemp("", "ipc-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create a stale socket file
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("Failed to create stale socket: %v", err)
	}
	f.Close()

	// NewUnixListener should replace it
	listener, err := NewUnixListener(socketPath)
	if err != nil {
		t.Fatalf("NewUnixListener() error = %v", err)
	}
	defer listener.Close()

	// Should be able to connect
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Errorf("Failed to connect to socket: %v", err)
	} else {
		conn.Close()
	}
}

func TestNewUnixListener_CreatesDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}

	tempDir, err := os.MkdirTemp("", "ipc-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Socket in non-existent subdirectory
	socketPath := filepath.Join(tempDir, "subdir", "test.sock")

	listener, err := NewUnixListener(socketPath)
	if err != nil {
		t.Fatalf("NewUnixListener() error = %v", err)
	}
	defer listener.Close()

	// Check directory was created
	if _, err := os.Stat(filepath.Dir(socketPath)); os.IsNotExist(err) {
		t.Error("Directory was not created")
	}
}

func TestListener_Close(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}

	tempDir, err := os.MkdirTemp("", "ipc-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := NewUnixListener(socketPath)
	if err != nil {
		t.Fatalf("NewUnixListener() error = %v", err)
	}

	// Close should remove socket file
	err = listener.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("Socket file should be removed after Close()")
	}
}

func TestIsDaemonRunning_NotRunning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}

	// Non-existent socket
	result := IsDaemonRunning("/tmp/nonexistent-socket-12345.sock")
	if result {
		t.Error("IsDaemonRunning() = true for non-existent socket")
	}
}

func TestIsDaemonRunning_Running(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets not supported on Windows")
	}

	tempDir, err := os.MkdirTemp("", "ipc-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := NewUnixListener(socketPath)
	if err != nil {
		t.Fatalf("NewUnixListener() error = %v", err)
	}
	defer listener.Close()

	result := IsDaemonRunning(socketPath)
	if !result {
		t.Error("IsDaemonRunning() = false for running daemon")
	}
}
