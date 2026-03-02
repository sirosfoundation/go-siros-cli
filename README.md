# go-siros-cli

A command-line interface wallet for verifiable credentials, designed to work with `go-wallet-backend`.

## Overview

`go-siros-cli` (also known as `wallet-cli`) provides command-line access to wallet functionality:

- **WebAuthn authentication** using FIDO2 hardware keys (YubiKey, SoloKey, etc.)
- **Credential management** - list, view, and export verifiable credentials
- **OpenID4VCI** - receive credentials from issuers
- **OpenID4VP** - present credentials to verifiers
- **Multi-profile support** - manage multiple wallet identities

## Requirements

### FIDO2 Hardware Security Key

This CLI requires a **FIDO2-compatible hardware security key** for authentication:

- **YubiKey 5 series** (recommended - supports PRF extension for key derivation)
- **SoloKey**
- **Feitian keys**
- Other FIDO2/WebAuthn compatible authenticators

The PRF (Pseudo-Random Function) extension is used to derive encryption keys for the wallet keystore. Keys without PRF support can still authenticate but won't be able to unlock encrypted wallet data.

### libfido2 Library

The native FIDO2 support requires the `libfido2` library:

**Ubuntu/Debian:**
```bash
sudo apt-get install libfido2-dev
```

**macOS:**
```bash
brew install libfido2
```

**Fedora:**
```bash
sudo dnf install libfido2-devel
```

### Verify Your Setup

```bash
# Check if your device is compatible
wallet-cli device check

# List connected FIDO2 devices
wallet-cli device list
```

## Installation

```bash
# From source (requires libfido2-dev)
git clone https://github.com/sirosfoundation/go-siros-cli
cd go-siros-cli
make build

# Install to PATH
make install
```

## Quick Start

```bash
# Register a new wallet
wallet-cli auth register --display-name "My Wallet"

# Login
wallet-cli auth login

# List credentials
wallet-cli credentials list

# Receive a credential (from QR code or URL)
wallet-cli issue offer "openid-credential-offer://..."

# Present credentials
wallet-cli present "openid4vp://authorize?..."
```

## Configuration

Configuration is stored in `~/.wallet-cli/`:

```bash
# Show current configuration
wallet-cli config show

# Set backend URL
wallet-cli config set backend_url https://wallet.example.com
```

## Profile Management

Manage multiple wallet identities:

```bash
# List profiles
wallet-cli profile list

# Create a new profile
wallet-cli profile create work --backend https://corp.example.com

# Switch profiles
wallet-cli profile use work

# Use specific profile for one command
wallet-cli --profile work credentials list
```

## Development

```bash
# Run tests
make test

# Run with debug logging
wallet-cli --debug auth login

# Build for all platforms
make build-all
```

## Architecture

See [docs/CLI_WALLET_DESIGN.md](docs/CLI_WALLET_DESIGN.md) for detailed design documentation.

## Daemon & MCP Server

The wallet includes a background daemon with MCP (Model Context Protocol) integration for AI assistants:

```bash
# Start the daemon
wallet-cli daemon start

# Enable MCP server for Claude Desktop
wallet-cli daemon start --mcp
```

Configure Claude Desktop (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wallet": {
      "command": "wallet-cli",
      "args": ["daemon", "start", "--mcp"]
    }
  }
}
```

See [docs/DAEMON.md](docs/DAEMON.md) for full daemon documentation.

## Debian Package

Build a Debian package:

```bash
make deb
```

Install:

```bash
sudo dpkg -i ../wallet-cli_0.1.0-1_amd64.deb
```

## License

Apache 2.0 - See [LICENSE](LICENSE)
