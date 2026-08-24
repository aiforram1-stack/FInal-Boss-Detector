# ADR 0004: Local content-addressed evidence storage

- Status: accepted for Phase 2 local development
- Date: 2026-08-24

## Context

Evidence intake must preserve exactly the bytes received, prove their identity,
deduplicate safely, and avoid allowing an untrusted filename to select a local
path. Phase 2 runs on a MacBook without cloud object storage or hardware WORM.
SQLite and a local filesystem do not provide a shared transaction.

## Decision

The API streams each upload once in configured bounded chunks to a unique file
under `<root>/.staging/`. During that write it calculates authoritative SHA-256,
SHA-512, and exact byte length. A small byte-signature allowlist identifies the
container family. This is identification, not semantic decoding or validation;
unidentified and disallowed signatures are rejected.

SHA-256 addresses the final path:

```text
<root>/sha256/ab/cd/<complete-lowercase-sha256>
```

SHA-256 is ubiquitous, compact, and sufficient for address partitioning.
SHA-512 is retained independently in metadata as additional integrity evidence.
Neither hash is inferred from a filename, extension, or client MIME declaration.

Promotion uses a same-filesystem hard link from staging to destination. Hard-link
creation fails if the destination exists and therefore cannot silently replace
an original. The staged inode is made read-only before linking. If content
already exists, the backend verifies both hashes and size, returns a deduplicated
result, and removes staging. All ordinary failure paths also remove staging.

The storage interface never accepts a client filename. Original names and
client-declared MIME types are audit metadata on the per-case association only.
External contracts receive `local-sha256://<hash>`, never an absolute path.

Within one case, `(case_id, blob_sha256)` is unique and a repeated upload returns
the existing EvidenceAsset with HTTP 200 plus deduplication headers. Across
cases, the blob is shared while each case receives its own EvidenceAsset and
filename metadata. Identical filenames with different bytes remain distinct.

## Transaction and recovery

Storage promotion precedes the database transaction. A successful API response
requires a committed blob/association record and a final object size check. If
that final check fails, metadata is compensated before an error is returned.

A database failure after promotion can leave an unreferenced content object.
Deleting it automatically would be unsafe during a concurrent race. `make
reconcile` compares stored hashes with database blob records, prints only logical
URIs, and never deletes data. An operator must investigate and authorize any
later cleanup.

## Consequences and limitations

This design prevents application-level replacement and removes write bits where
the operating system permits. A user with filesystem privileges can still alter
or delete data, so this is not regulatory WORM, tamper-proof storage, or a backup.
The signature detector does not prove that an entire media file decodes safely.

A later production phase can replace the backend behind `StorageBackend` with
versioned cloud object storage, retention locks, independent audit logs, and
backup controls while preserving logical hashes and contracts.
