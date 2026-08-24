"""Report immutable blobs absent from metadata; never delete evidence."""

from __future__ import annotations

import json

from forensic_evidence import LocalContentAddressedStorage

from forensic_api.config import Settings
from forensic_api.db.repositories import Repository
from forensic_api.db.session import build_database


def main() -> int:
    settings = Settings()
    database = build_database(settings.database_url)
    repository = Repository(database.sessions)
    storage = LocalContentAddressedStorage(
        settings.evidence_storage_root,
        max_upload_bytes=settings.max_upload_bytes,
        upload_chunk_bytes=settings.upload_chunk_bytes,
        allowed_media_types=settings.allowed_media_types,
    )
    orphaned = sorted(storage.iter_content_hashes() - repository.referenced_blob_hashes())
    payload = {
        "schema_version": "1.0",
        "unreferenced_objects": [f"local-sha256://{item}" for item in orphaned],
        "automatic_deletion_performed": False,
    }
    print(json.dumps(payload, indent=2))
    return 1 if orphaned else 0


if __name__ == "__main__":
    raise SystemExit(main())
