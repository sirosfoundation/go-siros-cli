# ADR-002: Test Coverage

## Status

Accepted

## Context

The CLI wallet handles sensitive operations including user authentication, credential management, and cryptographic operations. High reliability is essential.

## Decision

This project will aim for >70% test coverage overall, with higher coverage (>80%) for:

- Keystore operations
- Backend client
- OpenID4VCI/OpenID4VP protocol handlers
- Configuration management

## Rationale

A high degree of test coverage leads to more robust code. Given our use of AI-assisted programming, comprehensive tests help reduce the effect of hallucination and catch regressions early.

Test coverage serves multiple purposes:

- Validates correct behavior
- Documents expected functionality
- Enables safe refactoring
- Catches regressions early

## Consequences

- All new code must include tests
- PRs should not decrease overall coverage
- Test-driven development is encouraged
- Tests should follow each implementation
