# wallet-cli Daemon Architecture Analysis

**Date:** Analysis of proposed local service architecture  
**Status:** Accepted (PRF-mandatory, libfido2-only architecture)  
**Context:** go-siros-cli as a local daemon with gRPC/domain socket + MCP server

---

## Executive Summary

This document analyzes the proposal to transform `wallet-cli` from a command-line tool into a local daemon service with:

1. **gRPC over local IPC** (Unix domain socket on Linux/macOS, named pipe on Windows)
2. **`--daemon` mode** for background operation  
3. **MCP server** integration for LLM tooling
4. **Cross-platform support** for Linux, macOS, and Windows

The architecture leverages the existing native SDK infrastructure in `go-wallet-backend` while enabling rich local client scenarios.

---

## Current Architecture

```
┌─────────────────┐     HTTPS/REST      ┌──────────────────┐
│   wallet-cli    │ ─────────────────▶  │ go-wallet-backend│
│  (direct mode)  │                     │   (remote API)   │
└─────────────────┘                     └──────────────────┘
        │
        │ libfido2
        ▼
   [Hardware Token]
```

**Current flow:**
- Each CLI invocation creates a new `backend.Client`
- Authentication requires FIDO2 PIN entry per session
- No persistent keystore unlocking between commands
- Each command is stateless (except stored profile/token)

---

## Proposed Daemon Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         wallet-cli daemon                          │
│                                                                    │
│  ┌────────────┐    ┌────────────┐    ┌────────────────────┐       │
│  │  gRPC API  │    │ MCP Server │    │   Keystore State   │       │
│  │(domain sock)│    │ (stdio/sse)│    │ (unlocked session) │       │
│  └─────┬──────┘    └─────┬──────┘    └─────────┬──────────┘       │
│        │                 │                      │                  │
│        └────────────────┬┴──────────────────────┘                  │
│                         │                                          │
│              ┌──────────▼──────────┐                               │
│              │    Engine Core      │                               │
│              │  - AuthProvider     │                               │
│              │  - BackendClient    │                               │
│              │  - KeystoreManager  │                               │
│              └──────────┬──────────┘                               │
└─────────────────────────┼──────────────────────────────────────────┘
                          │
           ┌──────────────┴──────────────┐
           │ HTTPS/REST                  │ libfido2
           ▼                             ▼
    ┌──────────────┐              [Hardware Token]
    │go-wallet-    │
    │backend       │
    └──────────────┘
```

---

## Component Analysis

### 1. gRPC over Domain Socket

**Advantages:**
- Secure local-only communication (filesystem permissions)
- Efficient binary protocol (protobuf)
- Bidirectional streaming for signing requests
- Fits existing `go-wallet-backend` transport abstraction

**Implementation approach:**

```protobuf
// api/proto/daemon/v1/wallet.proto

service WalletDaemon {
  // Authentication
  rpc Unlock(UnlockRequest) returns (UnlockResponse);
  rpc Lock(LockRequest) returns (LockResponse);
  rpc Status(StatusRequest) returns (StatusResponse);

  // Credentials
  rpc ListCredentials(ListCredentialsRequest) returns (ListCredentialsResponse);
  rpc GetCredential(GetCredentialRequest) returns (GetCredentialResponse);

  // Issuance
  rpc StartIssuance(StartIssuanceRequest) returns (StartIssuanceResponse);
  rpc AcceptOffer(AcceptOfferRequest) returns (AcceptOfferResponse);

  // Presentation
  rpc HandleAuthorizationRequest(AuthRequestRequest) returns (AuthRequestResponse);
  rpc ApprovePresentation(ApprovePresentationRequest) returns (ApprovePresentationResponse);

  // Server-initiated signing (bidirectional stream)
  rpc SigningSession(stream SigningMessage) returns (stream SigningMessage);
}
```

**IPC location by platform:**
- Linux: `$XDG_RUNTIME_DIR/wallet-cli/daemon.sock`
- macOS: `~/Library/Application Support/wallet-cli/daemon.sock`
- Windows: `\\.\pipe\wallet-cli-daemon`

### 2. `--daemon` Mode

**Startup flow:**

```go
// cmd/wallet-cli/main.go

func runDaemon(cfg *config.Config) error {
    // 1. Check for existing daemon (pid file / socket)
    if isDaemonRunning() {
        return fmt.Errorf("daemon already running")
    }

    // 2. Create gRPC server with domain socket
    socketPath := getSocketPath()
    lis, err := net.Listen("unix", socketPath)
    if err != nil {
        return err
    }
    defer lis.Close()

    // 3. Set socket permissions (owner read/write only)
    os.Chmod(socketPath, 0600)

    // 4. Initialize engine components
    engine := NewDaemonEngine(cfg)

    // 5. Register gRPC services
    grpcServer := grpc.NewServer(/* interceptors */)
    pb.RegisterWalletDaemonServer(grpcServer, engine)

    // 6. Start MCP server (if enabled)
    if cfg.MCP.Enabled {
        go engine.StartMCPServer()
    }

    // 7. Write PID file
    writePIDFile()

    // 8. Handle signals (graceful shutdown)
    go handleSignals(grpcServer)

    return grpcServer.Serve(lis)
}
```

**CLI client mode:**

```bash
# Daemon commands
wallet-cli daemon start           # Start daemon in foreground
wallet-cli daemon start -d       # Start daemon (daemonize)
wallet-cli daemon stop           # Stop daemon
wallet-cli daemon status         # Check daemon status

# Regular commands auto-connect to daemon if running
wallet-cli credentials list      # Uses daemon if available, else direct
wallet-cli present <url>         # Routes through daemon for signing
```

### 3. MCP Server Integration

Model Context Protocol enables LLM assistants to interact with the wallet:

**MCP Tools:**

```json
{
  "tools": [
    {
      "name": "wallet_list_credentials",
      "description": "List all verifiable credentials in the wallet",
      "inputSchema": {"type": "object", "properties": {}}
    },
    {
      "name": "wallet_get_credential",
      "description": "Get details of a specific credential",
      "inputSchema": {
        "type": "object",
        "properties": {
          "id": {"type": "string", "description": "Credential ID"}
        },
        "required": ["id"]
      }
    },
    {
      "name": "wallet_check_issuer",
      "description": "Check if an issuer is trusted and what credentials they offer",
      "inputSchema": {
        "type": "object",
        "properties": {
          "issuer_url": {"type": "string"}
        },
        "required": ["issuer_url"]
      }
    },
    {
      "name": "wallet_accept_credential_offer",
      "description": "Accept a credential offer URL (requires user approval)",
      "inputSchema": {
        "type": "object",
        "properties": {
          "offer_url": {"type": "string"},
          "pin": {"type": "string", "description": "Transaction code if required"}
        },
        "required": ["offer_url"]
      }
    },
    {
      "name": "wallet_check_presentation_request",
      "description": "Analyze what a presentation request is asking for",
      "inputSchema": {
        "type": "object",
        "properties": {
          "request_url": {"type": "string"}
        },
        "required": ["request_url"]
      }
    },
    {
      "name": "wallet_status",
      "description": "Check wallet daemon status and connection",
      "inputSchema": {"type": "object", "properties": {}}
    }
  ]
}
```

**Security considerations:**
- MCP should NOT auto-approve presentations (require explicit user action)
- Read operations are safe
- Write operations (accept offer, present) should display prompts
- Consider approval workflow: MCP proposes → daemon notifies → user approves

---

## Session Management

### Keystore Unlock Lifecycle

```
┌───────────────────────────────────────────────────────────────┐
│                    Keystore State Machine                      │
├───────────────────────────────────────────────────────────────┤
│                                                                │
│   ┌──────────┐     unlock()      ┌───────────┐                │
│   │  LOCKED  │ ──────────────▶  │ UNLOCKED  │                │
│   └──────────┘                   └─────┬─────┘                │
│        ▲                               │                       │
│        │         lock() or             │                       │
│        │         timeout               │                       │
│        └───────────────────────────────┘                       │
│                                                                │
└───────────────────────────────────────────────────────────────┘
```

**Unlock strategies:**
1. **FIDO2 PIN + PRF**: Standard WebAuthn PRF output derives keystore key
2. **PIN-only (daemon mode)**: Cache PRF output in memory after first unlock
3. **Session token**: Use existing JWT token for backend, keystore unlocked

**Configuration options:**

```yaml
# ~/.wallet-cli/config.yaml
daemon:
  enabled: true
  auto_start: false           # Start daemon on first command
  socket_path: ""             # Default: $XDG_RUNTIME_DIR/wallet-cli/daemon.sock
  session_timeout: 30m        # Auto-lock after inactivity
  unlock_timeout: 5m          # Keep unlocked for this duration
  
mcp:
  enabled: true
  transport: stdio           # stdio | sse | websocket
  auto_approve: false        # Never auto-approve presentations
  allowed_operations:
    - list_credentials
    - get_credential
    - check_presentation_request
    - status
```

---

## Implementation Phases

### Phase 1: Core Daemon Infrastructure (Linux first)

- [ ] gRPC service definitions (`api/proto/daemon/v1/`)
- [ ] Platform abstraction interfaces (`internal/daemon/ipc/`)
- [ ] Unix socket listener with permissions (Linux/macOS)
- [ ] PID file management
- [ ] Daemon start/stop/status commands
- [ ] Signal handling (SIGTERM, SIGINT)

### Phase 2: Engine Integration

- [ ] Persistent keystore state across requests
- [ ] Session timeout handling
- [ ] Backend client connection pooling
- [ ] Tenant-aware routing (done ✓)

### Phase 3: CLI Client Mode

- [ ] Auto-detect running daemon
- [ ] Fallback to direct mode
- [ ] gRPC client for CLI commands
- [ ] Connection retry logic

### Phase 4: Cross-Platform Support

- [ ] Named pipe listener for Windows (`go-winio`)
- [ ] Platform-specific path resolution
- [ ] Windows security descriptors (DACL)
- [ ] Service manager abstraction:
  - [ ] systemd support (Linux)
  - [ ] launchd support (macOS)
  - [ ] Windows Service / Task Scheduler
- [ ] CGO + libfido2 builds for all platforms (PRF required)
- [ ] Windows build pipeline with bundled libfido2.dll
- [ ] CI/CD for multi-platform builds with CGO

### Phase 5: MCP Server

- [ ] MCP tool definitions
- [ ] stdio transport implementation
- [ ] Tool handlers calling daemon engine
- [ ] Approval workflow design

### Phase 6: Advanced Features

- [ ] Server-initiated signing (backend → daemon → hardware)
- [ ] Credential sync notifications
- [ ] Multi-profile daemon support

---

## Security Considerations

### Domain Socket Security
- Socket file permissions: `0600` (owner read/write only)
- Socket directory: `0700`
- Process ownership verification via `SO_PEERCRED`

### MCP Security
- No auto-approval for sensitive operations
- Explicit user consent for presentations
- Rate limiting on MCP requests
- Audit logging of MCP operations

### Keystore Security
- PRF output never written to disk
- Memory-only caching with secure wipe on lock
- Timeout-based auto-lock
- Option to require re-authentication per operation

---

## Cross-Platform Support (Linux, macOS, Windows)

### Platform Abstraction Layer

The daemon architecture requires a platform abstraction layer to handle OS-specific IPC and service management:

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Platform Abstraction                          │
├─────────────────────────────────────────────────────────────────┤
│  IPCListener        ServiceManager        PathResolver          │
│  ├─ Unix Socket     ├─ systemd           ├─ XDG (Linux)        │
│  ├─ Unix Socket     ├─ launchd           ├─ ~/Library (macOS)  │
│  └─ Named Pipe      └─ Windows Service   └─ %APPDATA% (Win)    │
└─────────────────────────────────────────────────────────────────┘
```

### IPC Mechanism by Platform

| Platform | IPC Mechanism | Address Format | Go Implementation |
|----------|---------------|----------------|-------------------|
| Linux    | Unix Domain Socket | `/run/user/<uid>/wallet-cli/daemon.sock` | `net.Listen("unix", path)` |
| macOS    | Unix Domain Socket | `~/Library/Application Support/wallet-cli/daemon.sock` | `net.Listen("unix", path)` |
| Windows  | Named Pipe | `\\.\pipe\wallet-cli-daemon` | `github.com/Microsoft/go-winio` |

**Implementation:**

```go
// internal/daemon/ipc/listener.go

// Listener abstracts platform-specific IPC mechanisms
type Listener interface {
    Listen() (net.Listener, error)
    Address() string
    Cleanup() error
}

// NewListener creates the appropriate IPC listener for the current platform
func NewListener(cfg *Config) (Listener, error) {
    switch runtime.GOOS {
    case "linux", "darwin":
        return NewUnixSocketListener(cfg)
    case "windows":
        return NewNamedPipeListener(cfg)
    default:
        return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
    }
}
```

```go
// internal/daemon/ipc/unix.go
//go:build unix

type UnixSocketListener struct {
    socketPath string
}

func (l *UnixSocketListener) Listen() (net.Listener, error) {
    // Remove stale socket
    os.Remove(l.socketPath)
    
    // Create parent directory
    if err := os.MkdirAll(filepath.Dir(l.socketPath), 0700); err != nil {
        return nil, err
    }
    
    lis, err := net.Listen("unix", l.socketPath)
    if err != nil {
        return nil, err
    }
    
    // Set restrictive permissions
    if err := os.Chmod(l.socketPath, 0600); err != nil {
        lis.Close()
        return nil, err
    }
    
    return lis, nil
}
```

```go
// internal/daemon/ipc/windows.go
//go:build windows

import "github.com/Microsoft/go-winio"

type NamedPipeListener struct {
    pipeName string
}

func (l *NamedPipeListener) Listen() (net.Listener, error) {
    // Configure pipe security (current user only)
    cfg := &winio.PipeConfig{
        SecurityDescriptor: "D:P(A;;GA;;;AU)", // Authenticated Users
        MessageMode:        false,              // Byte stream for gRPC
    }
    return winio.ListenPipe(l.pipeName, cfg)
}

func (l *NamedPipeListener) Address() string {
    return l.pipeName
}
```

### Configuration Paths by Platform

| Platform | Config Dir | Runtime Dir | Socket/Pipe |
|----------|------------|-------------|-------------|
| Linux | `$XDG_CONFIG_HOME/wallet-cli` or `~/.config/wallet-cli` | `$XDG_RUNTIME_DIR/wallet-cli` | `daemon.sock` |
| macOS | `~/Library/Application Support/wallet-cli` | `$TMPDIR/wallet-cli-<uid>` | `daemon.sock` |
| Windows | `%APPDATA%\wallet-cli` | N/A | `\\.\pipe\wallet-cli-daemon` |

```go
// internal/config/paths.go

func GetConfigDir() string {
    switch runtime.GOOS {
    case "linux":
        if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
            return filepath.Join(xdg, "wallet-cli")
        }
        return filepath.Join(os.Getenv("HOME"), ".config", "wallet-cli")
    case "darwin":
        return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "wallet-cli")
    case "windows":
        return filepath.Join(os.Getenv("APPDATA"), "wallet-cli")
    }
    return ""
}

func GetRuntimeDir() string {
    switch runtime.GOOS {
    case "linux":
        if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
            return filepath.Join(xdg, "wallet-cli")
        }
        return filepath.Join(os.TempDir(), fmt.Sprintf("wallet-cli-%d", os.Getuid()))
    case "darwin":
        return filepath.Join(os.Getenv("TMPDIR"), fmt.Sprintf("wallet-cli-%d", os.Getuid()))
    case "windows":
        return "" // Windows uses named pipes, no runtime dir needed
    }
    return ""
}
```

### Service Management by Platform

#### Linux (systemd)

```ini
# ~/.config/systemd/user/wallet-cli.service
[Unit]
Description=Wallet CLI Daemon
Documentation=https://github.com/sirosfoundation/go-siros-cli

[Service]
Type=simple
ExecStart=%h/.local/bin/wallet-cli daemon start
ExecStop=%h/.local/bin/wallet-cli daemon stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Commands: `systemctl --user enable/start/stop wallet-cli`

#### macOS (launchd)

```xml
<!-- ~/Library/LaunchAgents/org.siros.wallet-cli.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.siros.wallet-cli</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/wallet-cli</string>
        <string>daemon</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/wallet-cli.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/wallet-cli.err</string>
</dict>
</plist>
```

Commands: `launchctl load/unload ~/Library/LaunchAgents/org.siros.wallet-cli.plist`

#### Windows (Task Scheduler or Windows Service)

**Option A: Task Scheduler (user-level, simpler)**

```powershell
# Install as scheduled task that runs at login
$action = New-ScheduledTaskAction -Execute "wallet-cli.exe" -Argument "daemon start"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -TaskName "WalletCLI" -Description "Wallet CLI Daemon"
```

**Option B: Windows Service (system-level, requires admin)**

```go
// internal/daemon/service_windows.go
//go:build windows

import "golang.org/x/sys/windows/svc"

type walletService struct {
    engine *DaemonEngine
}

func (s *walletService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
    changes <- svc.Status{State: svc.StartPending}
    
    // Start daemon engine
    go s.engine.Run()
    
    changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
    
    for c := range r {
        switch c.Cmd {
        case svc.Stop, svc.Shutdown:
            changes <- svc.Status{State: svc.StopPending}
            s.engine.Shutdown()
            return false, 0
        }
    }
    return false, 0
}
```

### Signal Handling by Platform

```go
// internal/daemon/signals.go

func SetupSignalHandler(shutdown func()) {
    sigChan := make(chan os.Signal, 1)
    
    if runtime.GOOS == "windows" {
        // Windows: only SIGINT (Ctrl+C) is reliable
        signal.Notify(sigChan, os.Interrupt)
    } else {
        // Unix: SIGTERM, SIGINT, SIGHUP
        signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
    }
    
    go func() {
        sig := <-sigChan
        log.Info("received signal", "signal", sig)
        shutdown()
    }()
}
```

### Security by Platform

| Platform | Client Validation | Permission Model |
|----------|-------------------|------------------|
| Linux | `SO_PEERCRED` (uid/gid) | Unix file permissions |
| macOS | `LOCAL_PEERCRED` | Unix file permissions |
| Windows | Named pipe DACL | Security Descriptors |

```go
// internal/daemon/security_unix.go
//go:build unix

func ValidateClient(conn net.Conn) (uid, gid int, err error) {
    unixConn, ok := conn.(*net.UnixConn)
    if !ok {
        return 0, 0, fmt.Errorf("not a unix connection")
    }
    
    file, err := unixConn.File()
    if err != nil {
        return 0, 0, err
    }
    defer file.Close()
    
    cred, err := syscall.GetsockoptUcred(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
    if err != nil {
        return 0, 0, err
    }
    
    // Verify caller is same user as daemon
    if cred.Uid != uint32(os.Getuid()) {
        return 0, 0, fmt.Errorf("client uid %d does not match daemon uid %d", cred.Uid, os.Getuid())
    }
    
    return int(cred.Uid), int(cred.Gid), nil
}
```

### FIDO2/libfido2 by Platform

> **PRF Requirement**: This wallet system requires the WebAuthn PRF extension for key derivation.
> Platform passkeys (Windows Hello, macOS Keychain) do NOT support PRF.
> Therefore, libfido2 is **mandatory** on all platforms.

| Platform | Library | Notes |
|----------|---------|-------|
| Linux | libfido2 (system) | Install via package manager (`apt install libfido2-1` / `dnf install libfido2`) |
| macOS | libfido2 (homebrew) | `brew install libfido2` |
| Windows | libfido2.dll | Bundle with application (CGO cross-compilation required) |

**Why not platform passkeys?**

- Windows Hello platform authenticator: Does NOT support PRF extension
- macOS Keychain passkeys: Does NOT support PRF extension  
- PRF is essential for deriving encryption keys from the authenticator
- Only roaming authenticators (hardware security keys) and some platform authenticators via libfido2 support PRF

**CGO and libfido2:**

Since libfido2 is mandatory, CGO is also mandatory on all platforms. This affects the build process:

- **Linux**: CGO enabled by default, link against system libfido2
- **macOS**: CGO enabled by default, link against Homebrew libfido2
- **Windows**: Requires CGO cross-compilation with MinGW or native Windows build

### Build Configuration

```makefile
# Makefile
# Note: CGO is REQUIRED for libfido2 support (PRF extension)

.PHONY: build-all build-linux build-darwin build-windows

build-all: build-linux build-darwin build-windows

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o dist/wallet-cli-linux-amd64 ./cmd/wallet-cli

build-darwin:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o dist/wallet-cli-darwin-amd64 ./cmd/wallet-cli
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o dist/wallet-cli-darwin-arm64 ./cmd/wallet-cli

# Windows build requires cross-compilation with MinGW or native Windows build environment
# libfido2.dll must be bundled with the executable
build-windows:
	# Option 1: Cross-compile from Linux (requires mingw-w64)
	# CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -o dist/wallet-cli-windows-amd64.exe ./cmd/wallet-cli
	# Option 2: Build on Windows with MSYS2/MinGW
	# CGO_ENABLED=1 go build -o dist/wallet-cli-windows-amd64.exe ./cmd/wallet-cli
	@echo "Windows build requires CGO + MinGW. See docs for setup."
```

**Windows Build Requirements:**

1. **MinGW-w64** for CGO cross-compilation (from Linux/macOS), or MSYS2 for native Windows builds
2. **libfido2 headers and import library** for linking
3. **libfido2.dll** must be distributed alongside the executable
4. **Visual C++ Redistributable** may be required by libfido2.dll

**CI Pipeline Considerations:**

```yaml
# Example GitHub Actions for multi-platform builds
jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            goos: linux
            deps: "sudo apt-get install -y libfido2-dev"
          - os: macos-latest  
            goos: darwin
            deps: "brew install libfido2"
          - os: windows-latest
            goos: windows
            deps: "choco install mingw libfido2"  # Or use vcpkg/MSYS2
```

### Platform-Specific Package Structure

```text
internal/
└── daemon/
    ├── daemon.go           # Platform-independent daemon logic
    ├── engine.go           # Core engine
    ├── ipc/
    │   ├── listener.go     # Listener interface
    │   ├── unix.go         # Unix socket (linux, darwin)
    │   └── windows.go      # Named pipe (windows)
    ├── service/
    │   ├── manager.go      # Service manager interface
    │   ├── systemd.go      # Linux systemd
    │   ├── launchd.go      # macOS launchd
    │   └── windows.go      # Windows Service/Task Scheduler
    └── security/
        ├── security.go     # Security interface
        ├── unix.go         # SO_PEERCRED
        └── windows.go      # DACL/Security Descriptors
```

---

## Alternatives Considered

### Alternative 1: HTTP Server Instead of gRPC

- **Pro:** Easier debugging, works with curl
- **Con:** Less efficient, harder to do bidirectional streaming
- **Decision:** gRPC preferred for consistency with backend transport

### Alternative 2: Named Pipe/Domain Socket Abstraction

- **Pro:** Go's `net` package already abstracts Unix sockets; `go-winio` does same for Windows
- **Con:** Slight API differences
- **Decision:** Abstract behind `Listener` interface, platform-specific implementations

### Alternative 3: DBus Interface (Linux-only)

- **Pro:** System integration, desktop notifications
- **Con:** Linux-only, more complex
- **Decision:** Out of scope; may add as optional transport later

### Alternative 4: TCP localhost with auth token

- **Pro:** Works on all platforms without special libraries
- **Con:** Less secure (any process can connect), token management overhead
- **Decision:** Rejected for primary IPC; may use as fallback

---

## Recommendations

1. **Start with Phase 1-2**: Get basic daemon working on Linux before cross-platform
2. **Security-first**: Domain socket/named pipe permissions before features
3. **Graceful degradation**: Commands should work without daemon on all platforms
4. **Interface-driven design**: Define IPC, Service, Security interfaces early
5. **Platform parity**: Ensure feature parity across Linux/macOS/Windows
6. **CI/CD matrix**: Test on all three platforms from the start
7. **Logging**: Structured logging for daemon operations (platform-agnostic)
8. **Testing**: Integration tests with gRPC client (mock IPC layer for unit tests)

---

## Decisions

This section documents the resolved architectural decisions:

### General Architecture

| Decision | Resolution | Rationale |
|----------|------------|----------|
| Multi-user support | **No** | Single-user daemon. Multi-user/kiosk scenarios use web frontend. |
| Credential caching | **Yes, pluggable** | Start with in-memory cache. Pluggable interface for future backends. |
| Notification system | **Native platform** | Use system notification APIs (D-Bus/libnotify on Linux, Notification Center on macOS, Toast on Windows). |

### FIDO2 and PRF (Critical)

| Decision | Resolution | Rationale |
|----------|------------|----------|
| PRF Extension | **Mandatory** | PRF is required for key derivation. Non-negotiable. |
| Windows Hello | **Not viable** | Does NOT support PRF for platform authenticators. |
| macOS Keychain | **Not viable** | Does NOT support PRF extension. |
| libfido2 | **Required on all platforms** | Only library that provides PRF support cross-platform. |
| CGO | **Required on all platforms** | libfido2 is a C library; CGO is mandatory. |

### Cross-Platform

| Decision | Resolution | Rationale |
|----------|------------|----------|
| Windows builds | **CGO + bundled DLLs** | Cross-compile with MinGW or native build. Bundle libfido2.dll. |
| Service installation | **Auto-install** | `wallet-cli daemon install` generates and installs service files. |
| Token/secret storage | **File-based** | Local file storage preferred over platform keychains for PRF/signing compatibility. Pluggable interface for future. |

### Package Distribution

| Platform | Primary | Stretch Goals |
|----------|---------|---------------|
| Linux | .deb, .rpm | AppImage, Flatpak |
| macOS | Homebrew | .pkg installer (notarized) |
| Windows | Portable ZIP, WinGet | Chocolatey |

**Windows Packaging Notes:**
- Portable ZIP: Include `wallet-cli.exe` + `libfido2.dll` + README
- WinGet: Publish to winget-pkgs repository for `winget install wallet-cli`
- Both require bundling libfido2.dll and any VC++ runtime dependencies

### Daemon Operations

| Decision | Resolution | Rationale |
|----------|------------|----------|
| Authenticator handling | **Queue + notify** | If hardware token unavailable, queue operation and notify user "Please insert your security key" with timeout |
| Multiple authenticators | **Supported with policy caveats** | Allow multiple enrolled authenticators; note hardware-bound credentials may require re-issuance over backup recovery |
| Offline operation | **BLE/ISO 18013-5** | Support in-person/proximity flows offline via engine |
| Concurrent signing | **Serialize** | Serialize signing requests from multiple CLI clients |
| Health checks | **Yes** | `wallet-cli daemon health` command + socket-based health check |
| Audit logging | **Platform-native** | Use platform log capabilities (systemd journal, macOS unified log, Windows Event Log) |
| Crash recovery | **Accept loss** | Accept loss on crash for v1; no operation journaling |
| Upgrade behavior | **Session loss OK** | User re-authenticates after daemon upgrade |
| Protocol versioning | **Numbered** | Straight numbered versioning (v1, v2, etc.) |

### Security Operations

| Decision | Resolution | Rationale |
|----------|------------|----------|
| Secure memory | **memguard** | Use `memguard` or similar for PRF output and sensitive data |
| Log sanitization | **Never log secrets** | Never log secrets or privacy-sensitive info (issuers, verifiers) except DEBUG mode |
| JWT handling | **Frontend patterns** | CLI reacts gracefully to token expiry; refresh/retry auth with user notification. Follow wallet-frontend patterns. |
| gRPC deadlines | **Configurable** | Configurable per-RPC deadlines with sensible defaults |

### UX/Workflow

| Decision | Resolution | Rationale |
|----------|------------|----------|
| MCP approval | **Desktop notification + pinentry** | Use desktop notification + pinentry-style approve/deny for platform-specific UX |
| Presentation flow | **Check then approve** | Separate `check` vs `approve` steps; preview before commit |
| Timeouts | **Cancel** | Timeout always results in cancel |

### Testing Strategy

| Decision | Resolution | Rationale |
|----------|------------|----------|
| FIDO2 testing | **soft-fido2** | Use soft-fido2 authenticator (PRF-capable) for CI |
| gRPC testing | **CLI as client** | Use `wallet-cli` cmdline as test client |

---

## Open Questions

*All major architectural questions have been resolved above. Remaining items:*

1. **Signing plugin architecture**: If platform keychains are needed for specific signing operations (not PRF), how to integrate?
   - Consider pluggable signer interface that can delegate to platform-native or libfido2
   - PRF operations always go through libfido2

2. **Cross-compilation CI/CD**: Exact CI configuration for Windows builds with CGO
   - MSYS2 vs MinGW-w64 vs native Windows runner
   - Pre-built libfido2 binaries or build from source

---

## Gaps and Future Work

This section documents identified limitations and gaps requiring future resolution.

### Critical Gaps

| Gap | Issue | Status | Decision/Notes |
|-----|-------|--------|----------------|
| **Authenticator unavailability** | What if hardware token isn't plugged in when daemon needs to sign? | ✅ Resolved | Use queuing + notification: "Please insert your security key" with timeout |
| **Multiple authenticators** | Users have backup keys; design assumes single authenticator | ✅ Resolved | Support multiple enrolled authenticators. Note: for hardware-bound credentials, backup key may violate policy—may be better to re-issue than recover |
| **Token loss/recovery** | No recovery path if hardware token is lost | ✅ Resolved | Re-enrollment preferred over backup recovery for hardware-bound credentials; backup authenticator supported where policy allows |
| **Offline operation** | No consideration of network outages | ✅ Resolved | Support BLE/ISO 18013-5 for in-person/proximity flows in engine |
| **Concurrent signing** | Two CLI clients request signing simultaneously | ✅ Resolved | Serialize signing requests |

### Operational Gaps

| Gap | Issue | Status | Decision/Notes |
|-----|-------|--------|----------------|
| **Health checks** | systemd/launchd need health endpoints | ✅ Resolved | Add `wallet-cli daemon health` command + socket-based health check |
| **Metrics/observability** | No monitoring story | 🚫 Deferred | Less critical for single-user tool; investigate best practices for target platforms later |
| **Audit logging** | Mentioned but not specified | ✅ Resolved | Use platform-log capabilities (systemd journal, macOS unified log, Windows Event Log). Tamper-evident logs deferred |
| **Daemon crash recovery** | In-flight operations lost | ✅ Resolved | Accept loss on crash for v1; revisit later |
| **Upgrade path** | How to upgrade daemon without killing sessions | ✅ Resolved | Accept session loss; user re-authenticates after daemon upgrade |
| **Protocol versioning** | gRPC service may evolve | ✅ Resolved | Straight numbered versioning (v1, v2, etc.) |

### Security Gaps

| Gap | Issue | Status | Decision/Notes |
|-----|-------|--------|----------------|
| **Secure memory** | PRF output "secure wipe" mentioned but not specified | ✅ Resolved | Use `memguard` or similar for secure memory handling |
| **Log sanitization** | Credentials/PINs could leak to logs | ✅ Resolved | Never log secrets or privacy-sensitive info (issuers, verifiers) except DEBUG mode |
| **JWT revocation** | Compromised session token handling | ✅ Resolved | Already planned for go-wallet-backend authz server. CLI reacts gracefully to token expiry, refresh, retry auth with user notification. Follow wallet-frontend patterns. |
| **PIN brute-force** | Daemon could allow rapid unlock attempts | 🚫 Deferred | Exponential backoff good idea; implement in future version |

### UX/Workflow Gaps

| Gap | Issue | Status | Decision/Notes |
|-----|-------|--------|----------------|
| **MCP approval flow** | "daemon notifies → user approves" is vague | ✅ Resolved | Desktop notification + pinentry-style approve/deny dialog for platform-specific UX |
| **Presentation disclosure** | User needs to see what's being shared before approving | ✅ Resolved | Separate `check` vs `approve` steps; MCP returns preview first |
| **Timeout handling** | User walks away mid-operation | ✅ Resolved | Timeout always results in cancel |
| **SSH/headless scenarios** | User SSHed in, no GUI, no FIDO2 forwarding | 🚫 Deferred | Investigate agent forwarding in future version |

### Testing Gaps

| Gap | Issue | Status | Decision/Notes |
|-----|-------|--------|----------------|
| **Daemon integration tests** | How to test without real hardware | ✅ Resolved | Use soft-fido2 authenticator (in workspace) which supports PRF for CI |
| **gRPC client testing** | No test client mentioned | ✅ Resolved | Use cmdline client (`wallet-cli`) as test client |
| **Cross-platform CI** | Windows CGO builds are complex | 🚫 Deferred | Windows CI in future versions; tool needs stability before Windows release |

### Architecture Gaps

| Gap | Issue | Status | Decision/Notes |
|-----|-------|--------|----------------|
| **gRPC deadlines** | No timeout specification | ✅ Resolved | Configurable per-RPC deadlines with sensible defaults |
| **Connection pooling** | Backend client pooling undefined | 🚫 Deferred | Investigate further in future version |
| **Backpressure** | What if daemon is overwhelmed | 🚫 Deferred | Investigate further in future version |
| **Graceful degradation** | Partial failures not addressed | 🚫 Deferred | Investigate further in future version |

### Legend

- ⏳ **Open**: Needs decision
- ✅ **Resolved**: Decision made (move to Decisions section)
- 🚫 **Deferred**: Explicitly out of scope for v1
- 📝 **Documented**: Limitation accepted and documented

---

## References

- [go-wallet-backend Transport Abstraction](../go-wallet-backend/docs/TRANSPORT_ABSTRACTION_IMPLEMENTATION.md)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [gRPC over Unix Domain Sockets](https://grpc.io/docs/guides/custom-name-resolution/)
- [WebAuthn PRF Extension](https://w3c.github.io/webauthn/#prf-extension)
- [go-winio (Windows Named Pipes)](https://github.com/Microsoft/go-winio)
- [Windows Hello WebAuthn](https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis)
- [memguard - Secure Memory](https://github.com/awnumar/memguard)
