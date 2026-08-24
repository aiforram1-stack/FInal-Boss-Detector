# Local evidence-intake API

This FastAPI application is the Phase 3 CPU-only control plane. It creates
cases, accepts one streamed media upload per request, verifies immutable
evidence before structural analysis, persists versioned results, and serves
deterministic JSON/HTML reports through shared contracts. It deliberately has no
raw-evidence download, detector inference, authentication, PDF, or cloud
endpoint.

Use the root Makefile:

```bash
make db-upgrade
make structural-check-tools
make api
```

Runtime state is written beneath ignored `var/` paths by default. See
`docs/runbooks/local-evidence-intake.md` and
`docs/runbooks/local-structural-analysis.md` for setup and verification.
