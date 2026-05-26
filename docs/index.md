# GophKeeper Authenticator

GophKeeper Authenticator is a Go client/server password manager. Clients encrypt vault metadata and payloads locally before sending data to the server.

## Capabilities

- Registration and login with a separate master password.
- Encrypted vault items for text, login/password, bank cards, binary files, and OTP.
- Optimistic version checks for update and delete operations.
- gRPC API with generated OpenAPI documentation.
- CLI and TUI clients.

## Local Quality Gates

```bash
make fmt-check
make lint
make test
make coverage
make security
make docs-build
```
