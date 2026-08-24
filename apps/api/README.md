# Local evidence-intake API

This FastAPI application is the Phase 2 CPU-only control plane. It creates
cases, accepts one streamed media upload per request, persists metadata in
SQLite, and returns the shared `forensic_contracts` models. It deliberately has
no raw-evidence download, detector, report, authentication, or cloud endpoint.

Use the root Makefile:

```bash
make db-upgrade
make api
```

Runtime state is written beneath ignored `var/` paths by default. See
`docs/runbooks/local-evidence-intake.md` for setup and verification.
