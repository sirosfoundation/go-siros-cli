// Package ipc provides inter-process communication for the wallet daemon.
package ipc

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultSocketPath returns the default socket path for the current platform.
func DefaultSocketPath() string {
	if runtime.GOOS == "windows" {
		// Named pipe on Windows (not yet implemented)
		return `\\.\pipe\siros-wallet`
	}

	// Unix socket - use XDG_RUNTIME_DIR if available, otherwise /tmp
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = "/tmp"
	}
	return filepath.Join(runtimeDir, "siros-wallet.sock")
}

// Listener wraps a net.Listener with platform-specific cleanup.
type Listener struct {
	net.Listener
	socketPath string
}

// NewUnixListener creates a Unix domain socket listener.
func NewUnixListener(socketPath string) (*Listener, error) {
	// Remove stale socket if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	}

	// Create the socket directory if needed
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	// Create the Unix socket
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	// Set restrictive permissions
	if err := os.Chmod(socketPath, 0600); err != nil {
		l.Close()
		os.Remove(socketPath)
		return nil, err
	}

	return &Listener{
		Listener:   l,
		socketPath: socketPath,
	}, nil
}

// Close closes the listener and removes the socket file.
func (l *Listener) Close() error {
	err := l.Listener.Close()
	os.Remove(l.socketPath)
	return err
}

// SocketPath returns the path to the socket.
func (l *Listener) SocketPath() string {
	return l.socketPath
}

// IsDaemonRunning checks if a daemon is already running by attempting to connect.
func IsDaemonRunning(socketPath string) bool {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
