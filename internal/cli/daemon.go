package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/internal/config"
	"github.com/sirosfoundation/go-siros-cli/internal/daemon"
	"github.com/sirosfoundation/go-siros-cli/internal/daemon/ipc"
	"github.com/sirosfoundation/go-siros-cli/pkg/backend"
)

var (
	daemonSocketPath string
	daemonForeground bool
)

// daemonCmd represents the daemon command group.
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the wallet daemon",
	Long: `Manage the wallet daemon process.

The daemon keeps the keystore unlocked for a configurable session period,
allowing multiple commands to run without repeated authentication. It communicates
with CLI commands over Unix domain sockets (or named pipes on Windows).

Examples:
  # Start the daemon
  wallet-cli daemon start

  # Check daemon status
  wallet-cli daemon status

  # Stop the daemon
  wallet-cli daemon stop`,
}

// daemonStartCmd starts the daemon.
var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the wallet daemon",
	Long: `Start the wallet daemon in the background.

The daemon listens on a Unix domain socket and provides wallet operations
to CLI commands. Use --foreground to run in the foreground for debugging.`,
	RunE: runDaemonStart,
}

// daemonStopCmd stops the daemon.
var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the wallet daemon",
	RunE:  runDaemonStop,
}

// daemonStatusCmd shows daemon status.
var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	RunE:  runDaemonStatus,
}

// daemonUnlockCmd unlocks the daemon keystore.
var daemonUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the daemon keystore with your security key",
	Long: `Unlock the daemon keystore using FIDO2 PRF authentication.

This requires the daemon to be running. After unlocking, the keystore
remains accessible for other wallet commands until the session times out
or you run 'daemon lock'.`,
	RunE: runDaemonUnlock,
}

// daemonLockCmd locks the daemon keystore.
var daemonLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the daemon keystore",
	Long:  `Immediately lock the daemon keystore, requiring re-authentication for future operations.`,
	RunE:  runDaemonLock,
}

func init() {
	// Add daemon to root
	rootCmd.AddCommand(daemonCmd)

	// Add subcommands
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonUnlockCmd)
	daemonCmd.AddCommand(daemonLockCmd)

	// Flags for daemon start
	daemonStartCmd.Flags().StringVar(&daemonSocketPath, "socket", "", "socket path (default: platform-specific)")
	daemonStartCmd.Flags().BoolVarP(&daemonForeground, "foreground", "f", false, "run in foreground")

	// Flags for other commands
	daemonStopCmd.Flags().StringVar(&daemonSocketPath, "socket", "", "socket path")
	daemonStatusCmd.Flags().StringVar(&daemonSocketPath, "socket", "", "socket path")
	daemonUnlockCmd.Flags().StringVar(&daemonSocketPath, "socket", "", "socket path")
	daemonLockCmd.Flags().StringVar(&daemonSocketPath, "socket", "", "socket path")
}

func getSocketPath() string {
	if daemonSocketPath != "" {
		return daemonSocketPath
	}
	return ipc.DefaultSocketPath()
}

func runDaemonStart(cmd *cobra.Command, args []string) error {
	socketPath := getSocketPath()

	// Check if already running
	if ipc.IsDaemonRunning(socketPath) {
		return fmt.Errorf("daemon already running at %s", socketPath)
	}

	if daemonForeground {
		// Run in foreground
		return runDaemonForeground(socketPath)
	}

	// Start as background process
	return startDaemonBackground(socketPath)
}

func runDaemonForeground(socketPath string) error {
	cfg := config.Get()
	if cfg == nil {
		return fmt.Errorf("configuration not loaded")
	}

	profile := cfg.GetProfile()

	// Create backend client
	var backendClient *backend.Client
	if profile.BackendURL != "" {
		backendClient = backend.NewClient(profile.BackendURL)
		backendClient.SetTenantID(profile.TenantID)
		if profile.Token != "" {
			backendClient.SetToken(profile.Token)
		}
	}

	// Create engine config
	sessionTimeout := 30 * time.Minute // Default session timeout

	engineCfg := &daemon.EngineConfig{
		Profile:        profile,
		BackendURL:     profile.BackendURL,
		TenantID:       profile.TenantID,
		SessionTimeout: sessionTimeout,
		FIDO2Provider:  getFIDO2Provider(),
	}

	// Create engine
	engine, err := daemon.NewEngine(engineCfg)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	defer engine.Close()

	// Create gRPC server
	server, err := daemon.NewServer(&daemon.ServerConfig{
		SocketPath: socketPath,
		Engine:     engine,
		TenantID:   profile.TenantID,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Write PID file
	pidPath := socketPath + ".pid"
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}
	defer os.Remove(pidPath)

	fmt.Printf("Daemon starting on socket: %s\n", socketPath)
	fmt.Printf("PID: %d\n", os.Getpid())
	fmt.Printf("Session timeout: %s\n", sessionTimeout)
	fmt.Println("Press Ctrl+C to stop.")

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve()
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		fmt.Printf("\nReceived %s, shutting down...\n", sig)
		server.Stop()
		return nil
	case err := <-errChan:
		return err
	}
}

func startDaemonBackground(socketPath string) error {
	// Get the executable path
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Build command arguments
	args := []string{"daemon", "start", "--foreground", "--socket", socketPath}
	if cfgFile != "" {
		args = append([]string{"--config", cfgFile}, args...)
	}
	if profile != "" {
		args = append([]string{"--profile", profile}, args...)
	}

	// Create the command
	cmd := exec.Command(executable, args...)

	// Detach from parent
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	// Redirect output to files
	logDir := filepath.Dir(socketPath)
	stdout, err := os.OpenFile(filepath.Join(logDir, "daemon.stdout.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to create stdout log: %w", err)
	}
	stderr, err := os.OpenFile(filepath.Join(logDir, "daemon.stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to create stderr log: %w", err)
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Start the daemon
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Release the process
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("failed to release daemon process: %w", err)
	}

	// Wait a moment for the daemon to start
	time.Sleep(100 * time.Millisecond)

	// Verify it started
	if !ipc.IsDaemonRunning(socketPath) {
		return fmt.Errorf("daemon failed to start - check logs at %s", filepath.Join(logDir, "daemon.stderr.log"))
	}

	fmt.Printf("Daemon started (socket: %s)\n", socketPath)
	return nil
}

func runDaemonStop(cmd *cobra.Command, args []string) error {
	socketPath := getSocketPath()
	pidPath := socketPath + ".pid"

	// Read PID file
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("daemon not running (no PID file at %s)", pidPath)
		}
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		return fmt.Errorf("invalid PID file: %w", err)
	}

	// Find and kill the process
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// Send SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// Process might already be dead
		os.Remove(pidPath)
		os.Remove(socketPath)
		return fmt.Errorf("failed to stop daemon (PID %d): %w", pid, err)
	}

	// Wait for it to exit (up to 5 seconds)
	for i := 0; i < 50; i++ {
		if !ipc.IsDaemonRunning(socketPath) {
			fmt.Println("Daemon stopped")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	process.Signal(syscall.SIGKILL)
	os.Remove(pidPath)
	os.Remove(socketPath)

	fmt.Println("Daemon killed")
	return nil
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	socketPath := getSocketPath()
	pidPath := socketPath + ".pid"

	if !ipc.IsDaemonRunning(socketPath) {
		fmt.Println("Daemon is not running")
		return nil
	}

	// Try to get PID
	pidBytes, err := os.ReadFile(pidPath)
	if err == nil {
		pid, _ := strconv.Atoi(string(pidBytes))
		if pid > 0 {
			fmt.Printf("Daemon is running (PID %d)\n", pid)
		} else {
			fmt.Println("Daemon is running")
		}
	} else {
		fmt.Println("Daemon is running")
	}

	fmt.Printf("Socket: %s\n", socketPath)

	// Connect and query actual status
	client, err := daemon.NewClient(socketPath)
	if err != nil {
		fmt.Printf("Warning: could not connect to daemon: %v\n", err)
		return nil
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		fmt.Printf("Warning: could not get status: %v\n", err)
		return nil
	}

	fmt.Printf("Keystore: %s\n", map[bool]string{true: "unlocked", false: "locked"}[status.Unlocked])
	if status.Unlocked {
		fmt.Printf("Keys available: %d\n", status.KeyCount)
		if status.TimeoutRemaining > 0 {
			fmt.Printf("Session timeout in: %s\n", time.Duration(status.TimeoutRemaining)*time.Second)
		}
	}
	if status.TenantId != "" {
		fmt.Printf("Tenant: %s\n", status.TenantId)
	}

	return nil
}

func runDaemonUnlock(cmd *cobra.Command, args []string) error {
	socketPath := getSocketPath()

	if !ipc.IsDaemonRunning(socketPath) {
		return fmt.Errorf("daemon not running - start it with: wallet-cli daemon start")
	}

	// Connect to daemon to check current status
	client, err := daemon.NewClient(socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get daemon status: %w", err)
	}

	if status.Unlocked {
		fmt.Println("Keystore is already unlocked")
		fmt.Printf("Keys available: %d\n", status.KeyCount)
		if status.TimeoutRemaining > 0 {
			fmt.Printf("Session timeout in: %s\n", time.Duration(status.TimeoutRemaining)*time.Second)
		}
		return nil
	}

	// Perform FIDO2 PRF unlock locally and pass the result to daemon
	fmt.Println("Unlocking keystore via FIDO2 PRF authentication...")
	fmt.Println()

	// Get keystore data from backend and perform PRF authentication
	// The daemon will use the PRF output to decrypt the keystore
	ksCtx, ksCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer ksCancel()

	_, err = getUnlockedKeystore(ksCtx)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// For now, direct unlock works but the daemon doesn't persist it
	// TODO: Implement proper daemon-side PRF unlock with session persistence
	fmt.Println("\nNote: Keystore unlocked locally. Daemon-side persistent unlock coming soon.")
	fmt.Println("For now, use direct commands (without daemon) or run daemon --foreground.")

	return nil
}

func runDaemonLock(cmd *cobra.Command, args []string) error {
	socketPath := getSocketPath()

	if !ipc.IsDaemonRunning(socketPath) {
		return fmt.Errorf("daemon not running")
	}

	client, err := daemon.NewClient(socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Lock(ctx)
	if err != nil {
		return fmt.Errorf("failed to lock daemon: %w", err)
	}

	if resp.Success {
		fmt.Println("Keystore locked")
	} else {
		fmt.Println("Failed to lock keystore")
	}

	return nil
}
