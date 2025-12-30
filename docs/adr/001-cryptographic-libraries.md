# ADR-001: Cryptographic Libraries

## Status

Accepted

## Context

The CLI wallet handles sensitive cryptographic operations including:
- Keystore decryption (HKDF, ECDH, AES-KW, JWE)
- FIDO2/WebAuthn operations
- JWT/SD-JWT handling for credentials
- DID key operations

## Decision

This project avoids implementing cryptographic primitives, favouring the reuse of existing, well-tested libraries:

- **Key derivation**: `golang.org/x/crypto` for HKDF
- **JOSE operations**: `github.com/go-jose/go-jose/v4` for JWE/JWK
- **FIDO2**: `github.com/keys-pub/go-libfido2` for native authenticator access

## Rationale

Cryptography is hard to get right. Making a mistake when implementing a cryptographic primitive will have serious implications for the security of protocols that build upon those primitives.

Using well-tested, widely-adopted libraries:
- Reduces the risk of security vulnerabilities
- Benefits from community review and auditing
- Provides better compatibility with standards
- Simplifies maintenance

## Consequences

- Dependencies on external libraries must be kept up-to-date
- Library choices should be evaluated for security and maintenance status
- Custom crypto code is prohibited without explicit review
