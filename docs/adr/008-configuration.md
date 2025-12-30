# ADR-008: Configuration

## Status

Accepted

## Context

The CLI wallet needs configuration for various environments with different backend URLs, profile settings, and FIDO2 options.

## Decision

Configuration is managed through:

1. **YAML files** for structured configuration (`~/.wallet-cli/config.yaml`)
2. **Environment variables** for overrides
3. **Command-line flags** for one-off changes
4. **Defaults** for quick setup

Priority (highest to lowest):

1. Command-line flags
2. Environment variables
3. YAML configuration file
4. Default values

Environment variable naming: `WALLET_<KEY>` or `WALLET_<SECTION>_<KEY>`

## Rationale

- YAML provides readable, structured configuration
- Environment variables support scripting and CI/CD
- Flags enable one-off overrides without changing config
- Defaults enable quick development setup
- Profile support allows multiple wallet identities

## Consequences

- All configuration options documented
- Sensitive values (tokens) stored securely in profile
- Configuration validated at command startup
- Tests can override configuration easily
