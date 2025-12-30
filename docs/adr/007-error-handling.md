# ADR-007: Error Handling

## Status

Accepted

## Context

Consistent error handling is essential for debugging, logging, and user experience.

## Decision

1. **Sentinel errors** for common cases:

   ```go
   var (
       ErrNotFound      = errors.New("not found")
       ErrAlreadyExists = errors.New("already exists")
       ErrUnauthorized  = errors.New("unauthorized")
   )
   ```

2. **Error wrapping** for context:

   ```go
   return fmt.Errorf("failed to create user: %w", err)
   ```

3. **Error checking** with `errors.Is`:

   ```go
   if errors.Is(err, storage.ErrNotFound) {
       return nil, ErrUserNotFound
   }
   ```

4. **CLI errors** with user-friendly messages:

   ```go
   return fmt.Errorf("login failed: %w\n\nTry 'wallet-cli auth register' to create a new wallet", err)
   ```

## Rationale

- Consistent error handling improves debugging
- Error wrapping preserves the error chain
- Sentinel errors enable type-safe error checking
- User-friendly CLI messages improve UX

## Consequences

- All errors should be wrapped with context
- CLI layer provides actionable suggestions
- Logs include full error chains
- Tests verify error conditions
