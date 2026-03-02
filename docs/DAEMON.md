# Wallet Daemon

The wallet daemon provides background services for the wallet-cli, including:

- **gRPC Server** - Inter-process communication for wallet operations
- **MCP Server** - Model Context Protocol integration for AI assistants
- **User Approval Flow** - Pinentry-based approval for sensitive operations

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   wallet-cli    │     │   AI Assistant  │     │   Other Apps    │
│   (commands)    │     │   (Claude, etc) │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │      Unix Socket        │
                    │ ~/.config/wallet-cli/   │
                    │    daemon.sock          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │      Wallet Daemon      │
                    │                         │
                    │  ┌─────────────────┐    │
                    │  │   gRPC Server   │    │
                    │  └─────────────────┘    │
                    │  ┌─────────────────┐    │
                    │  │   MCP Server    │    │
                    │  │   (stdio)       │    │
                    │  └─────────────────┘    │
                    │  ┌─────────────────┐    │
                    │  │   Keystore      │    │
                    │  │   (in-memory)   │    │
                    │  └─────────────────┘    │
                    └─────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │     FIDO2 Device        │
                    │   (YubiKey, etc.)       │
                    └─────────────────────────┘
```

## Quick Start

### Starting the Daemon

```bash
# Start the daemon (foreground)
wallet-cli daemon start

# Start with MCP server enabled
wallet-cli daemon start --mcp

# Start in foreground mode (for debugging)
wallet-cli daemon start --foreground
```

### Daemon Management

```bash
# Check daemon status
wallet-cli daemon status

# Stop the daemon
wallet-cli daemon stop

# Unlock the keystore (requires security key)
wallet-cli daemon unlock

# Lock the keystore
wallet-cli daemon lock
```

## Systemd Integration

For automatic startup, use the provided systemd user service:

```bash
# Copy service files (done automatically by Debian package)
cp debian/wallet-cli-daemon.service ~/.config/systemd/user/
cp debian/wallet-cli-daemon.socket ~/.config/systemd/user/

# Reload systemd
systemctl --user daemon-reload

# Enable and start the service
systemctl --user enable wallet-cli-daemon
systemctl --user start wallet-cli-daemon

# Check status
systemctl --user status wallet-cli-daemon

# View logs
journalctl --user -u wallet-cli-daemon -f
```

## MCP Server Integration

The daemon includes an MCP (Model Context Protocol) server for AI assistant integration.

### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wallet": {
      "command": "wallet-cli",
      "args": ["daemon", "start", "--mcp"],
      "env": {}
    }
  }
}
```

### Available MCP Tools

The MCP server exposes the following tools to AI assistants:

| Tool | Description |
|------|-------------|
| `wallet_status` | Get daemon and keystore status |
| `wallet_list_keys` | List available signing keys |
| `wallet_sign` | Sign data with a wallet key |

### User Approval Flow

Sensitive operations (like signing) require user approval via pinentry:

1. AI assistant requests a signing operation
2. Daemon displays pinentry dialog with operation details
3. User approves or denies
4. Result returned to AI assistant

The approval dialog shows:
- Operation type (e.g., "sign", "present credential")
- Description of what's being signed
- Approve/Deny buttons

## Security

### Unix Socket Permissions

The daemon socket is created with mode 0600 (owner only):
- Location: `~/.config/wallet-cli/daemon.sock` or `$XDG_RUNTIME_DIR/wallet-cli/daemon.sock`
- Only the owner can connect

### In-Memory Keystore

- Private keys are derived from FIDO2 PRF and held in memory
- Auto-lock after configurable timeout (default: 5 minutes)
- Never written to disk

### Approval Flow

- All signing operations from MCP clients require explicit user approval
- Uses system pinentry for secure UI
- 60-second timeout for approval dialogs

## API Reference

### gRPC API

The daemon exposes a gRPC API at the Unix socket:

```protobuf
service WalletDaemon {
  // Status returns daemon status
  rpc Status(StatusRequest) returns (StatusResponse);
  
  // Lock immediately locks the keystore
  rpc Lock(LockRequest) returns (LockResponse);
  
  // ListKeys returns available signing keys
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  
  // SignJWT signs a JWT with the specified key
  rpc SignJWT(SignJWTRequest) returns (SignJWTResponse);
  
  // Sign performs raw signing with the specified key
  rpc Sign(SignRequest) returns (SignResponse);
  
  // GetApproval requests user approval for an operation
  rpc GetApproval(GetApprovalRequest) returns (GetApprovalResponse);
}
```

### Proto Definitions

See `api/proto/daemon/v1/wallet.proto` for full API definitions.

## Troubleshooting

### Daemon Won't Start

```bash
# Check if already running
wallet-cli daemon status

# Check socket file
ls -la ~/.config/wallet-cli/daemon.sock

# Remove stale socket
rm ~/.config/wallet-cli/daemon.sock
```

### MCP Server Not Working

```bash
# Test MCP directly
wallet-cli daemon start --mcp --foreground

# Check Claude Desktop logs
tail -f ~/.config/claude/logs/mcp.log
```

### Pinentry Not Found

Install a pinentry program:

```bash
# GNOME
sudo apt install pinentry-gnome3

# KDE
sudo apt install pinentry-qt

# TTY fallback
sudo apt install pinentry-curses
```

### Socket Permission Denied

```bash
# Check socket permissions
ls -la ~/.config/wallet-cli/daemon.sock

# Should be -rw------- (0600)
# Owner should be your user
```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `WALLET_DAEMON_SOCKET` | Socket path | `~/.config/wallet-cli/daemon.sock` |
| `WALLET_DAEMON_TIMEOUT` | Auto-lock timeout (seconds) | `300` |
| `PINENTRY_PROGRAM` | Path to pinentry | Auto-detected |

## Development

### Building

```bash
# Build with daemon support
make build

# Run tests
make test

# Test daemon specifically
go test -v ./internal/daemon/...
```

### Debugging

```bash
# Run daemon with verbose logging
wallet-cli --debug daemon start --foreground

# Test gRPC connection
grpcurl -plaintext -unix ~/.config/wallet-cli/daemon.sock siros.daemon.v1.WalletDaemon/Status
```
