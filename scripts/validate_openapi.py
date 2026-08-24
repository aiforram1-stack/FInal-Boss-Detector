"""Generate the Phase 2 OpenAPI document without starting a server."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from forensic_api.config import Settings
from forensic_api.main import create_app


def main() -> None:
    with TemporaryDirectory(prefix="forensic-openapi-") as temporary:
        root = Path(temporary)
        settings = Settings(
            database_url=f"sqlite:///{root / 'openapi.db'}",
            evidence_storage_root=root / "evidence",
        )
        document = create_app(settings, initialize_schema=True).openapi()
        encoded = json.dumps(document, sort_keys=True)
        required_paths = {
            "/health",
            "/v1/cases",
            "/v1/cases/{case_id}",
            "/v1/cases/{case_id}/evidence",
            "/v1/cases/{case_id}/evidence/{evidence_id}",
        }
        if not required_paths.issubset(document["paths"]):
            raise SystemExit("OpenAPI document is missing required Phase 2 paths")
        if "local-sha256://" in encoded or str(root) in encoded:
            raise SystemExit("OpenAPI document leaked runtime storage details")
    print("Phase 2 OpenAPI generation passed")


if __name__ == "__main__":
    main()
