# ADR-009: WebAuthn

## Status

Accepted

## Context

The wallet needs secure user authentication that is:

- Phishing resistant
- Privacy preserving
- Easy to use
- Supports hardware security keys

## Decision

WebAuthn is the only mechanism for end user authentication and is also used for other cryptographic functions such as data encryption via the FIDO PRF extension.

The CLI wallet supports two FIDO2 providers:

1. **Native provider** (libfido2): Direct communication with hardware authenticators
2. **Browser provider**: Fallback using browser WebAuthn API via local HTTP server

The PRF extension (hmac-secret) is used to derive encryption keys for the keystore without exposing secrets to the server.

## Rationale

FIDO/WebAuthn/Passkeys are the most widely deployed phishing-resistant user authentication mechanism available. It provides a perfect balance of cost vs security vs privacy vs ease of use.

The dual-provider approach ensures:

- Best performance with native libfido2 when available
- Universal compatibility through browser fallback
- Support for all FIDO2 authenticators (hardware keys, platform authenticators)

## Consequences

- Users must have a FIDO2-capable authenticator (YubiKey 5+, SoloKey, etc.)
- U2F-only devices (YubiKey 4) are not supported
- PRF extension required for keystore encryption
- Device capability checking helps users understand requirements
