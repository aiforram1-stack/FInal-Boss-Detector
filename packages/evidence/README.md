# Evidence package

Phase 2 implements the reusable `StorageBackend` protocol and the local
content-addressed backend here. It uses bounded reads, one-pass SHA-256/SHA-512,
byte-signature media identification, same-filesystem staging, and atomic
hard-link put-if-absent semantics. The original filename is never accepted by
the storage API and therefore cannot influence a physical path.

This is application-enforced append-only local development storage, not
regulatory WORM storage. See `docs/adr/0004-local-content-addressed-storage.md`.
