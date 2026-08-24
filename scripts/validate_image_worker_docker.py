#!/usr/bin/env python3
"""CPU-only policy validation for the Phase 4 Docker assets."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "workers" / "image-community"
DOCKERFILE = WORKER / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
EXPECTED_BASE_DIGEST = "sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3"


def main() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    dockerignore = set(DOCKERIGNORE.read_text(encoding="utf-8").splitlines())
    failures: list[str] = []
    required_dockerfile_fragments = {
        "Linux AMD64 target": "FROM --platform=linux/amd64",
        "pinned base digest": f"@{EXPECTED_BASE_DIGEST}",
        "non-root runtime": "USER 10001:10001",
        "explicit entrypoint": "ENTRYPOINT [",
        "model downloading disabled": "IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false",
        "source label": "org.opencontainers.image.source",
        "revision label": "org.opencontainers.image.revision",
        "license label": "org.opencontainers.image.licenses",
        "worker-only locked dependency export": "--only-group image-community-runtime",
        "shared contracts only": "COPY packages/contracts ./packages/contracts",
    }
    for label, fragment in required_dockerfile_fragments.items():
        if fragment not in dockerfile:
            failures.append(f"Dockerfile is missing {label}")
    if re.search(r"(?:^|\s)(?:FROM|image:)\s+\S+:latest(?:\s|$)", dockerfile, re.I | re.M):
        failures.append("Dockerfile uses a mutable latest tag")
    if re.search(r"\b(?:ARG|ENV)\s+\w*(?:TOKEN|SECRET|PASSWORD|API_KEY)\b", dockerfile):
        failures.append("Dockerfile declares a secret-like build argument or environment variable")
    if "ADD " in dockerfile:
        failures.append("Dockerfile must not use ADD")
    if "COPY apps" in dockerfile or "COPY packages ./packages" in dockerfile:
        failures.append("Dockerfile must not copy control-plane packages")

    required_ignores = {
        ".git",
        ".env",
        ".venv",
        "private_cases",
        "var",
        "models",
        "model-cache",
        "checkpoints",
        "*.safetensors",
        "*.pt",
        "*.pth",
        "*.pem",
        "*.key",
    }
    missing_ignores = sorted(required_ignores - dockerignore)
    if missing_ignores:
        failures.append(f".dockerignore is missing: {', '.join(missing_ignores)}")
    for required_file in (
        WORKER / "THIRD_PARTY_NOTICES.md",
        WORKER / "licenses" / "Community-Forensics-LICENSE",
    ):
        if not required_file.is_file():
            failures.append(f"required notice is missing: {required_file.relative_to(ROOT)}")

    if failures:
        raise SystemExit("image worker Docker validation failed:\n- " + "\n- ".join(failures))
    print("image worker Docker assets passed CPU-only policy validation")


if __name__ == "__main__":
    main()
