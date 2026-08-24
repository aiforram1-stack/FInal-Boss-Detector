#!/usr/bin/env python3
"""Run local/mock or explicitly configured real readiness checks."""

from __future__ import annotations

import json

from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.factory import build_job_service


def main() -> None:
    settings = ImageCommunitySettings()
    _, fitness = build_job_service(settings)
    result = fitness.check()
    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    if not result.ready:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
