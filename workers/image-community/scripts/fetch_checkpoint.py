#!/usr/bin/env python3
"""Explicit, pinned and verified future checkpoint acquisition."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_community.config import WORKER_ROOT, ImageCommunitySettings
from forensic_image_community.factory import validated_manifest

HASH_CHUNK_BYTES = 1024 * 1024
REPOSITORY_ROOT = WORKER_ROOT.parents[1]


def _safe_external_cache(value: Path) -> Path:
    unresolved = value.expanduser()
    if unresolved.exists() and unresolved.is_symlink():
        raise SystemExit("model cache cannot be a symbolic link")
    resolved = unresolved.resolve(strict=False)
    if resolved == REPOSITORY_ROOT or REPOSITORY_ROOT in resolved.parents:
        raise SystemExit("model cache must be outside the Git repository")
    return resolved


def _safe_external_receipt(value: Path) -> Path:
    resolved = value.expanduser().resolve(strict=False)
    if resolved == REPOSITORY_ROOT or REPOSITORY_ROOT in resolved.parents:
        raise SystemExit("checkpoint receipt must be outside the Git repository")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_receipt(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temp_name = tempfile.mkstemp(prefix="receipt-", suffix=".part", dir=path.parent)
    temporary = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch the pinned Community Forensics checkpoint")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()

    settings = ImageCommunitySettings()
    manifest = validated_manifest(settings.model_manifest)
    cache = _safe_external_cache(args.cache or settings.model_cache)
    plan = {
        "schema_version": "1.0",
        "repository": manifest.model.repository,
        "revision": manifest.model.revision,
        "filename": manifest.model.filename,
        "expected_byte_length": manifest.model.checkpoint_byte_length,
        "expected_sha256": manifest.model.checkpoint_sha256,
        "cache": str(cache),
        "download_allowed": False,
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return
    if not settings.allow_model_download or os.environ.get("ALLOW_MODEL_DOWNLOAD") != "1":
        raise SystemExit(
            "checkpoint download requires IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=true "
            "and ALLOW_MODEL_DOWNLOAD=1"
        )
    try:
        from huggingface_hub import hf_hub_download  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit("huggingface-hub GPU dependency is unavailable") from exc

    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    downloaded = Path(
        hf_hub_download(
            repo_id=manifest.model.repository,
            filename=manifest.model.filename,
            revision=manifest.model.revision,
            local_dir=cache,
        )
    )
    if (
        downloaded.is_symlink()
        or downloaded.name != manifest.model.filename
        or downloaded.parent.resolve() != cache
    ):
        raise SystemExit("checkpoint provider returned an unexpected local path")
    actual_size = downloaded.stat().st_size
    actual_hash = _sha256(downloaded)
    if (
        actual_size != manifest.model.checkpoint_byte_length
        or actual_hash != manifest.model.checkpoint_sha256
    ):
        downloaded.unlink(missing_ok=True)
        raise SystemExit("downloaded checkpoint failed manifest verification and was removed")
    receipt = {
        **plan,
        "download_allowed": True,
        "verified": True,
        "actual_byte_length": actual_size,
        "actual_sha256": actual_hash,
        "verified_at": datetime.now(UTC).isoformat(),
    }
    receipt_path = _safe_external_receipt(
        args.receipt or cache / "checkpoint-verification-receipt.json"
    )
    _atomic_receipt(receipt_path, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
