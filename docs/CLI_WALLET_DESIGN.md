# CLI Wallet Design Document

**Author:** GitHub Copilot  
**Date:** December 17, 2025  
**Status:** Draft  
**Version:** 0.1

## 1. Overview

This document outlines the design for a command-line interface (CLI) wallet tool that provides core wallet functionality without requiring a web browser. The CLI wallet is designed to complement the existing `wallet-frontend` web application and `go-wallet-backend` server, enabling programmatic and headless wallet operations.

### 1.1 Goals

- Provide basic wallet operations via command line
- Support WebAuthn authentication (FIDO2 hardware keys)
- List and manage verifiable credentials
- Receive credentials via OpenID4VCI
- Respond to OpenID4VP presentation requests
- Enable CI/CD integration and scripting scenarios
- Maintain compatibility with the existing wallet ecosystem

### 1.2 Non-Goals (Initial Release)

- Full feature parity with `wallet-frontend`
- GUI or TUI interfaces
- Browser-based authentication fallback
- Credential deletion/revocation (read-only initially)

## 2. Architecture Analysis

### 2.1 Current System Overview

The existing wallet system consists of:

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│ wallet-frontend │────▶│  go-wallet-backend   │◀────│    MongoDB      │
│    (React)      │     │    (Gin/Go)          │     │                 │
└────────┬────────┘     └──────────┬───────────┘     └─────────────────┘
         │                         │
         │ WebSocket               │
         │ (keystore signing)      │
         ▼                         │
┌─────────────────────────────────┤
│      Browser Keystore           │
│  (WebAuthn PRF + client-side)   │
│                                 │
│  - Key generation               │
│  - JWT signing                  │
│  - Private data encryption      │
└─────────────────────────────────┘
```

**Key architectural insights:**

1. **WebAuthn PRF Extension**: The frontend uses the WebAuthn PRF (Pseudo-Random Function) extension to derive encryption keys from hardware authenticators. This is used to encrypt the wallet's private data.

2. **Client-Side Keystore**: Private keys never leave the browser. The backend only stores encrypted containers that can only be decrypted with the user's WebAuthn credential.

3. **WebSocket Bridge**: For operations requiring signing (OpenID4VCI proofs, VP presentations), the backend communicates with the frontend via WebSocket to request signatures.

4. **Private Data Format**: Uses an `EncryptedContainer` with JWE encryption, supporting:
   - PRF-derived keys (primary)
   - Password-derived keys (backup)
   - Asymmetric key encapsulation

### 2.2 Wallet State Schema

From `wallet-frontend/src/services/WalletStateSchema.ts`, the private data contains:

```typescript
interface WalletState {
  keypairs: Array<{
    kid: string;  // Key ID (usually DID#fragment)
    keypair: {
      did: string;
      alg: string;        // e.g., "ES256"
      publicKey: JWK;
      privateKey: JWK;    // Cleartext after decryption
    }
  }>;
}
```

### 2.3 Backend Services (go-wallet-backend)

Relevant services from `internal/service/`:

| Service | Purpose |
|---------|---------|
| `WebAuthnService` | Registration and login ceremonies |
| `CredentialService` | Store/retrieve verifiable credentials |
| `PresentationService` | Store/retrieve presentations |
| `IssuerService` | Manage trusted credential issuers |
| `KeystoreService` | WebSocket-based remote signing |

## 3. CLI Wallet Design

### 3.1 Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       CLI Application                            │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ Command Layer │  │ Auth Module  │  │ Credential Module  │   │
│  │   (Cobra)     │  │              │  │                    │   │
│  └───────┬───────┘  └──────┬───────┘  └─────────┬──────────┘   │
│          │                 │                    │               │
│          ▼                 ▼                    ▼               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Core Library                          │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐  │   │
│  │  │ Keystore     │ │ OpenID4VCI   │ │ OpenID4VP       │  │   │
│  │  │ Manager      │ │ Client       │ │ Handler         │  │   │
│  │  └──────────────┘ └──────────────┘ └─────────────────┘  │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐  │   │
│  │  │ WebAuthn     │ │ Backend API  │ │ Local Storage   │  │   │
│  │  │ Client       │ │ Client       │ │                 │  │   │
│  │  └──────────────┘ └──────────────┘ └─────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
           │                      │
           ▼                      ▼
    ┌──────────────┐      ┌───────────────────┐
    │ FIDO2 Device │      │ go-wallet-backend │
    │ (via libfido2)│      │      (API)       │
    └──────────────┘      └───────────────────┘
```

### 3.2 Module Descriptions

#### 3.2.1 Command Layer

Uses Cobra for CLI command structure:

```
wallet-cli
├── auth
│   ├── register    # Register new wallet with WebAuthn
│   ├── login       # Login with existing WebAuthn credential
│   └── status      # Check authentication status
├── credentials
│   ├── list        # List all credentials
│   ├── show <id>   # Show credential details
│   └── export <id> # Export credential (if supported)
├── issue
│   ├── start <issuer>              # Start issuance flow
│   └── complete <credential-offer> # Complete with offer URL
├── present
│   ├── start <request-uri>  # Handle OpenID4VP request
│   └── approve              # Approve pending presentation
└── config
    ├── show                 # Show current configuration
    └── set <key> <value>    # Set configuration option
```

#### 3.2.2 Authentication Module (WebAuthn)

**Challenge: WebAuthn in CLI**

WebAuthn is designed for browser environments. For CLI usage, we have options:

**Option A: Use libfido2 directly (RECOMMENDED)**
- Pros: Native FIDO2 support, works offline, supports any RP ID
- Cons: Requires libfido2 library installed
- Library: `github.com/keys-pub/go-libfido2`

**Option B: WebAuthn proxy via local browser (LIMITED USE)**
- Pros: Uses standard WebAuthn API
- Cons: **Only works with localhost backends** due to RP ID origin restrictions
- Implementation: Start local HTTP server, open browser for ceremony
- Note: WebAuthn enforces that the RP ID must match or be a registrable suffix of 
  the origin's domain. A localhost page cannot create credentials for remote RP IDs
  like `demo.wwwallet.org`.

**Option C: Headless Chrome/Playwright**
- Pros: Uses real WebAuthn implementation
- Cons: Heavy dependency, requires Chrome installation

**Implementation: Option A (libfido2) is required for production use**

Hardware authenticators (FIDO2 devices) do not have the same origin restrictions as 
browsers. They can register/authenticate for any RP ID as long as the user physically
confirms the operation. This makes libfido2 the only viable option for CLI use with
production backends.

The PRF extension is critical for key derivation. libfido2 supports the `hmac-secret` 
extension which is the underlying CTAP2 mechanism for WebAuthn PRF.

```go
// Simplified authentication flow
type AuthModule interface {
    // Register creates a new wallet identity with WebAuthn
    Register(ctx context.Context, displayName string) (*RegisterResult, error)
    
    // Login authenticates with an existing WebAuthn credential
    Login(ctx context.Context) (*LoginResult, error)
    
    // GetPRFKey derives the encryption key using PRF
    GetPRFKey(ctx context.Context, salt []byte) ([]byte, error)
}
```

#### 3.2.3 Keystore Manager

Handles encrypted private data storage compatible with the web frontend format:

```go
type KeystoreManager interface {
    // Unlock decrypts the keystore using the PRF-derived key
    Unlock(ctx context.Context, prfKey []byte, encryptedData []byte) error
    
    // GetPrivateKey retrieves a private key by DID
    GetPrivateKey(did string) (*ecdsa.PrivateKey, error)
    
    // Sign creates a JWT signature
    Sign(ctx context.Context, claims map[string]interface{}, did string) (string, error)
    
    // Lock re-encrypts and clears in-memory keys
    Lock() error
}
```

**Key considerations:**
- Must maintain compatibility with `AsymmetricEncryptedContainer` format
- Support JWE decryption with the PRF-derived key
- Handle key migration from older formats (V0, V1, V2 → V3)

#### 3.2.4 OpenID4VCI Client

Handles credential issuance:

```go
type OpenID4VCIClient interface {
    // DiscoverIssuer fetches issuer metadata
    DiscoverIssuer(ctx context.Context, issuerURL string) (*IssuerMetadata, error)
    
    // StartIssuance initiates the credential offer
    StartIssuance(ctx context.Context, issuer string, credentialType string) (*CredentialOffer, error)
    
    // HandleCredentialOffer processes an openid-credential-offer:// URL
    HandleCredentialOffer(ctx context.Context, offerURL string) (*IssuanceSession, error)
    
    // CompleteIssuance exchanges the authorization code for credentials
    CompleteIssuance(ctx context.Context, session *IssuanceSession) ([]*Credential, error)
}
```

**Issuance flow:**

1. Parse `openid-credential-offer://` URL or issuer identifier
2. Fetch issuer metadata from `.well-known/openid-credential-issuer`
3. If authorization required:
   - For interactive: Open browser for OIDC flow
   - For pre-authorized: Use PIN if required
4. Generate key-bound proof JWT using local keystore
5. Request credential from credential endpoint
6. Store credential via backend API

#### 3.2.5 OpenID4VP Handler

Handles presentation requests:

```go
type OpenID4VPHandler interface {
    // ParseRequest parses an authorization request
    ParseRequest(ctx context.Context, requestURI string) (*PresentationRequest, error)
    
    // FindMatchingCredentials finds credentials matching the request
    FindMatchingCredentials(ctx context.Context, req *PresentationRequest) ([]*CredentialMatch, error)
    
    // CreatePresentation creates a VP with selected credentials
    CreatePresentation(ctx context.Context, req *PresentationRequest, 
                       credentials []*CredentialMatch) (*Presentation, error)
    
    // SubmitPresentation sends the VP to the verifier
    SubmitPresentation(ctx context.Context, presentation *Presentation) (*VerificationResult, error)
}
```

**Presentation flow:**

1. Parse authorization request from URL or QR code content
2. Fetch request object if using `request_uri`
3. Evaluate presentation definition against stored credentials
4. Display credential selection to user (interactive) or auto-select (scripted)
5. Generate VP JWT signed with holder's key
6. Submit to verifier's redirect_uri
7. Handle response

### 3.3 Storage Strategy

#### 3.3.1 Local Storage

For offline capability, the CLI should maintain local state:

```
~/.wallet-cli/
├── config.yaml           # CLI configuration
├── credentials.db        # SQLite: cached credentials (encrypted)
├── session.json          # Current session info (encrypted)
└── keystore.enc          # Encrypted keystore backup
```

#### 3.3.2 Backend Synchronization

The CLI should sync with `go-wallet-backend` when online:

- **Credentials**: Bidirectional sync with backend storage
- **Private Data**: Pull-only (server is source of truth for encrypted container)
- **Session**: Maintain JWT for API authentication

### 3.4 Security Considerations

#### 3.4.1 Key Material Protection

1. **Never store cleartext private keys** - Always require WebAuthn unlock
2. **Memory protection** - Clear keys from memory after use
3. **Session timeout** - Auto-lock after configurable inactivity period
4. **PRF salt protection** - Unique salt per credential, stored in encrypted container

#### 3.4.2 Authentication

1. **Hardware-bound authentication** - Require FIDO2 device for all sensitive operations
2. **User verification** - Always require PIN/biometric (UV flag)
3. **Replay protection** - Use fresh challenges from backend

#### 3.4.3 Transport Security

1. **TLS only** - All backend communication over HTTPS
2. **Certificate pinning** - Optional, for high-security deployments
3. **mTLS support** - For enterprise environments

## 4. Command Specifications

### 4.1 Authentication Commands

#### `wallet-cli auth register`

```bash
# Interactive registration
$ wallet-cli auth register
Display name [optional]: Alice's CLI Wallet
[Touch your security key to register...]
✓ Registration successful
  User ID: 550e8400-e29b-41d4-a716-446655440000
  Credential ID: abc123...

# Non-interactive (for scripts)
$ wallet-cli auth register --display-name "CI Wallet" --json
{"user_id": "...", "credential_id": "..."}
```

#### `wallet-cli auth login`

```bash
$ wallet-cli auth login
[Touch your security key to login...]
✓ Login successful
  Session valid until: 2025-12-17T14:30:00Z

# With specific credential
$ wallet-cli auth login --credential-id abc123
```

### 4.2 Credential Commands

#### `wallet-cli credentials list`

```bash
$ wallet-cli credentials list
ID                                   TYPE              ISSUER                EXPIRES
────────────────────────────────────────────────────────────────────────────────────
pid-001                              PID               gov.example.com       2026-01-15
diploma-2024                         Diploma           uni.example.edu       Never
mdl-driver-license                   mDL               dmv.example.gov       2028-03-20

# Detailed JSON output
$ wallet-cli credentials list --format json
[{"id": "pid-001", "type": "PID", ...}]

# Filter by type
$ wallet-cli credentials list --type PID
```

#### `wallet-cli credentials show <id>`

```bash
$ wallet-cli credentials show pid-001
Credential: pid-001
Type: PersonIdentificationData (PID)
Issuer: gov.example.com
Issued: 2025-01-15
Expires: 2026-01-15
Format: vc+sd-jwt

Claims:
  family_name: Doe
  given_name: Alice  
  birth_date: 1990-05-15
  [3 more claims hidden - use --show-all]

Disclosure Digests: 7
```

### 4.3 Issuance Commands

#### `wallet-cli issue start`

```bash
# Start issuance from known issuer
$ wallet-cli issue start https://issuer.example.com --type PID
Authorization required. Opening browser...
[Complete login in browser, then return here]
Press Enter when authorization is complete...

✓ Credential received
  Type: PID
  ID: pid-002

# Handle credential offer URL (e.g., from QR code)
$ wallet-cli issue offer "openid-credential-offer://issuer.example.com?credential_offer=..."
Issuer: issuer.example.com
Credential Types: [PID, Diploma]
Pre-authorized: Yes
PIN required: Yes

Enter PIN: ****
[Touch your security key to sign proof...]

✓ Credentials received:
  - PID (pid-002)
  - Diploma (diploma-002)
```

### 4.4 Presentation Commands

#### `wallet-cli present`

```bash
# Handle presentation request
$ wallet-cli present "openid4vp://authorize?request_uri=https://verifier.example.com/request/123"

Verifier: Acme Corporation (verifier.example.com)
Purpose: Age verification for alcohol purchase

Requested credentials:
  ✓ PID - birth_date (you have 1 matching credential)

Disclose the following claims?
  - birth_date: 1990-05-15

[a]pprove / [d]eny / [s]elect different credential? a
[Touch your security key to sign presentation...]

✓ Presentation submitted successfully
  Redirect: https://shop.example.com/checkout?success=true

# Non-interactive (for automation)
$ wallet-cli present "$REQUEST_URI" --auto-approve --credential pid-001
```

## 5. Implementation Considerations

### 5.1 Reusable Components from vc Project

The `github.com/dc4eu/vc` (or `github.com/sirosfoundation/vc`) project provides:

- `pkg/openid4vci` - OpenID4VCI client implementation
- `pkg/openid4vp` - OpenID4VP verifier (can adapt for holder)
- `pkg/mdoc` - mDL/mDoc handling
- `pkg/sdjwt` - SD-JWT processing

### 5.2 Dependencies

```go
// Core
github.com/spf13/cobra         // CLI framework
github.com/spf13/viper        // Configuration

// WebAuthn/FIDO2
github.com/keys-pub/go-libfido2  // Native FIDO2 support

// Cryptography
github.com/go-jose/go-jose/v4    // JOSE/JWE/JWS
github.com/lestrrat-go/jwx/v2    // Alternative JOSE library

// Storage
modernc.org/sqlite               // Pure Go SQLite

// HTTP Client
github.com/go-resty/resty/v2     // REST client with retries
```

### 5.3 Platform Support

| Platform | WebAuthn Support | Notes |
|----------|------------------|-------|
| Linux    | libfido2         | Requires udev rules for USB |
| macOS    | libfido2         | Works with built-in Touch ID via platform authenticator |
| Windows  | libfido2/Windows Hello | May need Windows Hello bridge |

### 5.4 Testing Strategy

1. **Unit tests** - Core crypto and parsing logic
2. **Integration tests** - Against mock backend
3. **E2E tests** - With real FIDO2 emulator (SoftWebAuthn)
4. **Conformance tests** - Against OWF conformance suite for OpenID4VCI/VP

## 6. Future Enhancements

### 6.1 Phase 2 Features

- Credential backup/restore
- Multi-device sync
- Batch operations
- Credential revocation checking
- Selective disclosure UI improvements

### 6.2 Phase 3 Features

- Plugin system for custom credential types
- mDL BLE/NFC presentation
- Integration with system keychain (macOS Keychain, Windows Credential Manager)
- Daemon mode for automated workflows

## 7. Design Decisions

### 7.1 WebAuthn PRF Extension Support

**Decision**: Ensure libfido2 uses the WebAuthn PRF extension, with willingness to contribute patches upstream if needed.

**Rationale**: 
- The PRF extension is the W3C-standardized mechanism for deriving secrets from WebAuthn credentials
- CTAP2 `hmac-secret` is the underlying transport mechanism, but PRF adds important semantics (salt handling, evaluation context)
- Future WebAuthn extensions (e.g., `largeBlob`, `credBlob`, potential wallet-specific extensions) will be critical for wallet use cases
- We should be prepared to maintain a fork of libfido2 if upstream is slow to adopt new extensions

**Implementation approach**:
1. Audit libfido2 for PRF extension support vs raw hmac-secret
2. Test interoperability with browser WebAuthn PRF outputs
3. If gaps exist, contribute patches or maintain compatibility layer
4. Design abstraction layer to isolate FIDO2 library specifics

```go
// Abstraction to allow for future FIDO2 library changes
type FIDO2Provider interface {
    // GetPRFOutput evaluates PRF with the given salts
    GetPRFOutput(ctx context.Context, credential CredentialID, 
                 salt1, salt2 []byte) (*PRFOutput, error)
    
    // SupportsExtension checks if an extension is available
    SupportsExtension(ext ExtensionID) bool
    
    // Future extensions
    // GetLargeBlob, SetLargeBlob, etc.
}
```

### 7.2 Browser Fallback Authentication

**Decision**: Include browser fallback as a first-class authentication path.

**Rationale**:
- Ensures compatibility across all platforms
- Reduces deployment friction (no native library dependencies)
- Provides path for platforms where libfido2 support is incomplete
- Users may prefer using their existing browser authenticator setup

**Implementation**:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Authentication Flow                         │
│                                                                 │
│   ┌─────────┐     ┌──────────────┐     ┌─────────────────────┐ │
│   │  CLI    │────▶│ Try libfido2 │────▶│ Success: Continue   │ │
│   └─────────┘     └──────┬───────┘     └─────────────────────┘ │
│                          │                                      │
│                          │ Fallback                             │
│                          ▼                                      │
│                   ┌──────────────┐                              │
│                   │ Start local  │                              │
│                   │ HTTP server  │                              │
│                   │ (localhost)  │                              │
│                   └──────┬───────┘                              │
│                          │                                      │
│                          ▼                                      │
│                   ┌──────────────┐     ┌─────────────────────┐ │
│                   │ Open browser │────▶│ WebAuthn ceremony   │ │
│                   │ to auth page │     │ in browser          │ │
│                   └──────────────┘     └──────────┬──────────┘ │
│                                                   │             │
│                                                   ▼             │
│                   ┌──────────────┐     ┌─────────────────────┐ │
│                   │ Receive PRF  │◀────│ Redirect to         │ │
│                   │ result       │     │ localhost callback  │ │
│                   └──────────────┘     └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Browser fallback flow**:

1. CLI starts local HTTPS server on `localhost:<random-port>`
2. Opens browser to: `https://localhost:<port>/auth?action=login`
3. Browser page performs WebAuthn ceremony with PRF extension
4. PRF output is encrypted with a one-time key and returned via callback
5. CLI receives encrypted result, completes authentication

**Security considerations**:
- Use TLS even on localhost (self-signed cert, pinned in CLI)
- One-time encryption key generated per ceremony
- Short timeout on callback
- Bind to localhost only

**Configuration**:
```yaml
auth:
  prefer_native: true          # Try libfido2 first
  browser_fallback: true       # Allow browser fallback
  browser_command: ""          # Override browser launch command
  callback_timeout: 120s       # Timeout for browser callback
```

### 7.3 Offline Capability

**Decision**: Design for online-first, but maintain architecture that doesn't preclude offline operation.

**Rationale**:
- Initial use cases (CI/CD, scripting) typically have network access
- Backend sync simplifies credential management
- Offline support adds significant complexity (conflict resolution, stale data)
- However, future use cases (air-gapped environments, mobile connectivity) may require offline

**Architectural guidelines**:
1. Local SQLite storage for credentials (not just cache)
2. Clear separation between "local operations" and "sync operations"
3. Credential verification should work offline (signature validation)
4. Presentation creation should work offline (signing with local keys)
5. Defer offline issuance support (requires pre-authorized flows)

```go
type OperationMode int

const (
    ModeOnline  OperationMode = iota  // Full backend connectivity
    ModeOffline                        // Local-only operations
    ModeSync                           // Background sync when available
)

type WalletClient interface {
    // SetMode configures online/offline behavior
    SetMode(mode OperationMode)
    
    // Operations that work offline
    ListLocalCredentials() ([]*Credential, error)
    CreatePresentation(req *PresentationRequest) (*Presentation, error)
    VerifyCredential(cred *Credential) (*VerificationResult, error)
    
    // Operations that require online (or queue for later)
    SyncCredentials(ctx context.Context) error
    SubmitPresentation(ctx context.Context, pres *Presentation) error
}
```

### 7.4 Key Export/Import

**Decision**: Defer to Phase 2, design storage format to support it.

**Rationale**:
- Recovery scenarios are important but not MVP-blocking
- Need to carefully consider security implications
- Format must be compatible with potential future wallet backup standards
- May require additional authentication factors for export

**Future considerations**:
- Encrypted backup format (possibly using second WebAuthn credential)
- Integration with wallet backup protocols (if standardized)
- Hardware security module (HSM) export for enterprise
- Paper backup (BIP39-style) for individual keys

### 7.5 Multi-Wallet Support

**Decision**: Full support for multiple wallet identities on the same device.

**Rationale**:
- Users may have personal and work identities
- Testing and development requires multiple wallets
- Regulatory compliance may require identity separation
- Natural fit for CLI with profile/context switching

**Implementation**:

```
~/.wallet-cli/
├── config.yaml                    # Global configuration
├── profiles/
│   ├── default/
│   │   ├── credentials.db
│   │   ├── session.json
│   │   └── keystore.enc
│   ├── work/
│   │   ├── credentials.db
│   │   ├── session.json
│   │   └── keystore.enc
│   └── testing/
│       └── ...
└── current_profile               # Symlink or file with current profile name
```

**CLI interface**:

```bash
# Profile management
$ wallet-cli profile list
PROFILE     BACKEND                      STATUS
default     https://wallet.example.com   active
work        https://corp.example.com     logged-out
testing     http://localhost:8080        logged-out

$ wallet-cli profile create work --backend https://corp.example.com
Created profile 'work'

$ wallet-cli profile use work
Switched to profile 'work'

# Or use per-command override
$ wallet-cli --profile work credentials list

# Environment variable support
$ WALLET_PROFILE=testing wallet-cli auth login
```

**Profile configuration**:

```yaml
# ~/.wallet-cli/profiles/work/profile.yaml
name: work
backend_url: https://corp.example.com
display_name: "Work Wallet"
created_at: 2025-12-17T10:00:00Z

# Profile-specific settings
auth:
  prefer_native: false      # Company policy: browser only
  credential_id: "abc123"   # Preferred credential for this profile

sync:
  auto_sync: true
  interval: 5m
```

**WebAuthn credential binding**:
- Each profile can be bound to specific WebAuthn credentials
- Or share credentials across profiles (user choice)
- Profile selection can be automatic based on credential used

## 8. References

- [OpenID4VCI Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [WebAuthn PRF Extension](https://w3c.github.io/webauthn/#prf-extension)
- [FIDO2 CTAP hmac-secret](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension)
- [go-webauthn library](https://github.com/go-webauthn/webauthn)
- [go-libfido2](https://github.com/keys-pub/go-libfido2)
