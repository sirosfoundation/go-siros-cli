# go-siros-cli E2E Tests

End-to-end integration tests for go-siros-cli using a software FIDO2 token.

## Overview

These tests validate the CLI functionality against a real go-wallet-backend instance without requiring a physical hardware security key. The tests use `TestProvider`, a software FIDO2 implementation that:

- Generates real ECDSA P-256 cryptographic keys
- Supports PRF extension for key derivation  
- Creates valid WebAuthn attestations and assertions
- Maintains credential state during test runs

## Requirements

- Docker and Docker Compose
- Go 1.24+
- Access to go-wallet-backend Docker image

## Quick Start

From the `e2e/` directory:

```bash
# Start test environment and run tests
make test

# Or run individual steps:
make up         # Start backend services
make test-fast  # Run tests (assumes services are running)
make down       # Stop services
```

From the repository root:

```bash
make e2e        # Run full e2e test suite
make e2e-fast   # Run tests without starting environment
make e2e-up     # Start test environment
make e2e-down   # Stop test environment
make e2e-logs   # View service logs
```

## Test Environment

The Docker Compose setup includes:

- **mongodb**: MongoDB 6.x for wallet backend storage
- **wallet-backend**: go-wallet-backend server configured for testing

Services are available at:
- Wallet Backend: http://localhost:8080

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WALLET_BACKEND_URL` | `http://localhost:8080` | Backend API URL |
| `WEBAUTHN_RP_ID` | `localhost` | WebAuthn Relying Party ID |

## Test Categories

### Integration Tests (require backend)

- `TestBackendStatus` - Verify backend connectivity
- `TestRegistrationFlow` - Full user registration with software token
- `TestLoginFlow` - Full authentication flow

### Unit Tests (no external dependencies)

- `TestPRFKeyDerivation` - Test PRF extension functionality

Run unit tests only:

```bash
make test-unit
```

## Software FIDO2 Token

The `TestProvider` in `pkg/fido2/test_provider.go` simulates a hardware FIDO2 authenticator:

```go
// Create a test provider
provider := fido2.NewTestProvider().WithRPID("localhost")

// Register a credential
result, err := provider.Register(ctx, &fido2.RegisterOptions{
    Challenge: challengeBytes,
    RPID:      "localhost",
    UserID:    userID,
    EnablePRF: true,
})

// Authenticate
assertion, err := provider.Authenticate(ctx, &fido2.AuthenticateOptions{
    Challenge:        challengeBytes,
    AllowCredentials: []fido2.CredentialID{result.CredentialID},
})

// Get PRF output for key derivation
prfOutput, err := provider.GetPRFOutput(ctx, credentialID, salt1, salt2)
```

## CI Integration

For CI pipelines, use:

```bash
make -C e2e test-ci
```

This will:
1. Start the test environment
2. Run all e2e tests
3. Stop the environment (even on test failures)

## Troubleshooting

### Services not starting

Check Docker Compose logs:
```bash
make e2e-logs
```

### Backend not ready

The Makefile waits for the backend to be healthy. If tests fail immediately, increase the wait timeout or check service logs.

### Test failures

Run with verbose output:
```bash
cd e2e && go test -v -tags=e2e ./...
```

## Comparison with wallet-e2e-tests

| Feature | go-siros-cli e2e | wallet-e2e-tests |
|---------|------------------|------------------|
| Technology | Go, TestProvider | Playwright, browser |
| Authentication | Software FIDO2 | Real WebAuthn |
| Target | CLI integration | Browser wallet |
| Dependencies | Docker only | Node.js, Playwright |
| Speed | Fast | Slower (browser startup) |
