#!/usr/bin/env python3
"""Verify GHCR package visibility and source-repository linkage evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def verify_package(
    data: object,
    expected_repository: str,
    observed_source_url: str,
) -> None:
    if not isinstance(data, dict):
        raise ValueError("package API response must be an object")
    if data.get("visibility") != "private":
        raise ValueError("GHCR package visibility is not private")
    package_type = data.get("package_type")
    if package_type != "container":
        raise ValueError("package API response is not for a container package")

    expected_source_url = f"https://github.com/{expected_repository}"
    if observed_source_url != expected_source_url:
        raise ValueError("OCI source label does not identify the expected source repository")

    repository = data.get("repository")
    if repository is None:
        return
    if not isinstance(repository, dict) or repository.get("full_name") != expected_repository:
        raise ValueError("GHCR package is not linked to the expected source repository")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-json", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--observed-source-url", required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.package_json.read_text(encoding="utf-8"))
        verify_package(data, args.repository, args.observed_source_url)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"GHCR package access verification failed: {exc}") from exc
    print("GHCR package is private and its OCI source is linked to the source repository")


if __name__ == "__main__":
    main()
