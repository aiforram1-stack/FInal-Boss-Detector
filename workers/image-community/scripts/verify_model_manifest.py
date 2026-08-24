#!/usr/bin/env python3
"""Validate and summarize the pinned model manifest without network access."""

from __future__ import annotations

import json

from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.factory import validated_manifest


def main() -> None:
    settings = ImageCommunitySettings()
    manifest = validated_manifest(settings.model_manifest)
    print(
        json.dumps(
            {
                "schema_version": manifest.schema_version,
                "detector_id": manifest.detector.detector_id,
                "source_commit": manifest.source.repository_commit,
                "model_revision": manifest.model.revision,
                "checkpoint_sha256": manifest.model.checkpoint_sha256,
                "checkpoint_hash_status": manifest.model.checkpoint_hash_status,
                "calibrated": manifest.detector.calibrated,
                "probability": manifest.output.probability,
                "valid": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
