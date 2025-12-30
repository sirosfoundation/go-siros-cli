# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the go-siros-cli project.

Many of these ADRs are shared with the [go-wallet-backend](https://github.com/sirosfoundation/go-wallet-backend) project to maintain consistency across the SIROS wallet ecosystem.

## Index

- [ADR-001: Cryptographic Libraries](001-cryptographic-libraries.md) - Use existing crypto libraries
- [ADR-002: Test Coverage](002-test-coverage.md) - Aim for >70% test coverage
- [ADR-003: Type Conventions](003-type-conventions.md) - Use `any` instead of `interface{}`
- [ADR-007: Error Handling](007-error-handling.md) - Consistent error handling patterns
- [ADR-008: Configuration](008-configuration.md) - YAML + environment variables
- [ADR-009: WebAuthn](009-webauthn.md) - WebAuthn as primary authentication mechanism

## Template

When creating a new ADR, use the following template:

```markdown
# ADR-NNN: Title

## Status

Proposed | Accepted | Deprecated | Superseded

## Context

What is the context for this decision?

## Decision

What is the decision that was made?

## Rationale

Why was this decision made?

## Consequences

What are the consequences of this decision?
```
