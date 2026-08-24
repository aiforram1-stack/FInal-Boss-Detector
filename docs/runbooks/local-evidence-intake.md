# Local evidence-intake runbook

## Setup and migrate

Use Python 3.11 and run from the repository root:

```bash
make setup
cp .env.example .env
make db-upgrade
make api
```

The defaults use `./var/forensic.db` and `./var/evidence`, both ignored by Git.
Review `.env` before starting. Phase 2 accepts exact configured signatures; it
does not decode, analyze, or execute uploads.

## Create a case

```bash
curl -sS -X POST http://127.0.0.1:8000/v1/cases \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: 8a4a8872-a071-4e07-bf1d-b116532ebf24' \
  -d '{
    "schema_version": "1.0",
    "claim": "Local Phase 2 test case",
    "privacy_mode": "RESTRICTED"
  }'
```

Copy the returned `case_id`. UUID timestamps are UTC. No authentication exists
in this local phase; bind only to the default loopback interface.

## Upload generated test evidence

Use a small file you created for testing, never private user evidence:

```bash
curl -sS -X POST \
  http://127.0.0.1:8000/v1/cases/CASE_ID/evidence \
  -F 'file=@/absolute/path/to/generated-test.png;type=text/plain'
```

The declared type is retained for audit but the returned `mime_type` comes from
the bytes. `X-Content-Deduplicated` reports blob reuse and
`X-Evidence-Association-Reused` reports a same-case idempotent upload.

## Retrieve metadata

```bash
curl -sS http://127.0.0.1:8000/v1/cases/CASE_ID
curl -sS http://127.0.0.1:8000/v1/cases/CASE_ID/evidence/EVIDENCE_ID
curl -sS http://127.0.0.1:8000/health
```

There is intentionally no raw evidence-download route. The SQLite tables can be
inspected locally, but external responses contain only `local-sha256://` URIs.

## Reconcile exceptional orphan blobs

```bash
make reconcile
```

Exit status 1 means unreferenced immutable blobs were reported. The command
prints logical URIs and performs no deletion. Investigate the preceding database
failure and concurrent requests before deciding on any manual action.

## Verify and reset local development state

Run `make test-api` and `make openapi` before relying on a local change. To reset
only the repository's default development state, stop the API, confirm `pwd` is
the Git root, back up anything needed, and use this explicit confirmation guard:

```bash
test "$PWD" = "$(git rev-parse --show-toplevel)" || exit 1
read -r "reply?Type RESET-LOCAL-FORENSIC to remove only ./var/evidence and ./var/forensic.db: "
test "$reply" = "RESET-LOCAL-FORENSIC" || exit 1
rm -rf -- "$PWD/var/evidence"
rm -f -- "$PWD/var/forensic.db"
make db-upgrade
```

Never substitute a user-provided or unresolved path into the removal commands.

## Recorded local smoke test

On 2026-08-24, the Phase 2 branch accepted an 8,388,608-byte generated PNG-like
fixture through the in-process FastAPI client with a configured 65,536-byte
storage chunk. It completed in 0.034 seconds on the development MacBook, created
one content object, and left zero staging files. This is a bounded-behavior smoke
check, not a throughput benchmark; framework multipart buffering is separate
from the storage backend's bounded reads.
