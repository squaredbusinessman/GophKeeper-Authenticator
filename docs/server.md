# Server

The server exposes authentication and vault APIs over gRPC. Vault data is stored in PostgreSQL as encrypted metadata and encrypted payload fields.

## Vault Consistency

Vault items use optimistic versioning:

- Create starts a new item at the server.
- Update requires the client-provided expected version.
- Delete performs a soft delete and also requires the expected version.
- Conflicting updates return a version conflict instead of silently overwriting data.

## Synchronization

Sync returns items changed after a cursor timestamp and includes tombstones for deleted items.
