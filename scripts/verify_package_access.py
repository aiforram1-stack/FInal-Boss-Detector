#!/usr/bin/env python3
"""Verify GHCR package visibility and source-repository linkage from API JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def verify_package(data: object, expected_repository: str) -> None:
    if not isinstance(data, dict):
        raise ValueError("package API response must be an object")
    if data.get("visibility") != "private":
        raise ValueError("GHCR package visibility is not private")
    repository = data.get("repository")
    if not isinstance(repository, dict) or repository.get("full_name") != expected_repository:
        raise ValueError("GHCR package is not linked to the expected source repository")
    package_type = data.get("package_type")
    if package_type is not None and package_type != "container":
        raise ValueError("package API response is not for a container package")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-json", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.package_json.read_text(encoding="utf-8"))
        verify_package(data, args.repository)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"GHCR package access verification failed: {exc}") from exc
    print("GHCR package is private and linked to the source repository")


if __name__ == "__main__":
    main()
