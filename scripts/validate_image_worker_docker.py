#!/usr/bin/env python3
"""CPU-only policy validation for the Phase 5 image-worker Docker assets."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "workers" / "image-community"
DOCKERFILE = WORKER / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
MOCK_BASE_DIGEST = "sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91"
GPU_BASE_DIGEST = "sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3"
REQUIRED_OCI_LABELS = (
    "org.opencontainers.image.title",
    "org.opencontainers.image.description",
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.created",
    "org.opencontainers.image.version",
    "org.opencontainers.image.licenses",
    "org.opencontainers.image.vendor",
)


def main() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    dockerignore = set(DOCKERIGNORE.read_text(encoding="utf-8").splitlines())
    failures: list[str] = []
    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    if len(from_lines) != 2:
        failures.append("Dockerfile must have exactly the mock-test and gpu-runtime FROM lines")
    for line in from_lines:
        if "--platform=linux/amd64" not in line:
            failures.append(f"base does not select Linux AMD64: {line}")
        if "@sha256:" not in line:
            failures.append(f"base is not digest-pinned: {line}")
        if ":latest" in line.lower() or "${" in line:
            failures.append(f"base is mutable or build-argument controlled: {line}")

    required_fragments = {
        "mock-test target": " AS mock-test",
        "gpu-runtime target": " AS gpu-runtime",
        "pinned CPU base": f"@{MOCK_BASE_DIGEST}",
        "pinned CUDA base": f"@{GPU_BASE_DIGEST}",
        "CPU dependency boundary": "--only-group image-community-mock-runtime",
        "GPU dependency boundary": "--only-group image-community-runtime",
        "dependency export cache disabled": "uv export --no-cache --frozen",
        "uv build cache removal": "rm -rf /root/.cache/uv",
        "build temporary root creation": "RUN mkdir -p /work/tmp",
        "model downloading disabled": "IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false",
        "external temporary root": "TMPDIR=/work/tmp",
        "shared contracts only": "COPY packages/contracts ./packages/contracts",
        "generated mock smoke entrypoint": "scripts/container_smoke.py",
    }
    for label, fragment in required_fragments.items():
        if fragment not in dockerfile:
            failures.append(f"Dockerfile is missing {label}")
    if dockerfile.count("uv export --no-cache --frozen") != 2:
        failures.append("both final targets must disable the uv export cache")
    if dockerfile.count("rm -rf /root/.cache/uv") != 2:
        failures.append("both final targets must remove any uv build cache")
    if dockerfile.count("RUN mkdir -p /work/tmp") != 2:
        failures.append("both final targets must create TMPDIR before dependency export")
    for label in REQUIRED_OCI_LABELS:
        if dockerfile.count(label) != 2:
            failures.append(f"OCI label must be present on both final targets: {label}")
    if dockerfile.count("USER 10001:10001") != 2:
        failures.append("both final targets must use the non-root runtime identity")
    if dockerfile.count("ENTRYPOINT [") != 2:
        failures.append("both final targets must have an explicit entrypoint")
    if re.search(r"\b(?:ARG|ENV)\s+\w*(?:TOKEN|SECRET|PASSWORD|API_KEY)\b", dockerfile):
        failures.append("Dockerfile declares a secret-like build argument or environment variable")
    if "ADD " in dockerfile:
        failures.append("Dockerfile must not use ADD")
    if "COPY apps" in dockerfile or "COPY packages ./packages" in dockerfile:
        failures.append("Dockerfile must not copy control-plane packages")
    if "fetch_checkpoint.py --execute" in dockerfile or "ALLOW_MODEL_DOWNLOAD=1" in dockerfile:
        failures.append("Dockerfile must not download a model checkpoint")

    required_ignores = {
        ".git",
        ".github",
        ".env",
        ".env.*",
        ".venv",
        "private_cases",
        "var",
        "evidence",
        "uploads",
        "data",
        "datasets",
        "models",
        "model-cache",
        "checkpoints",
        "reports/private",
        ".cache",
        ".idea",
        ".vscode",
        ".DS_Store",
        "*.part",
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
        WORKER / "scripts" / "container_smoke.py",
    ):
        if not required_file.is_file():
            failures.append(f"required worker asset is missing: {required_file.relative_to(ROOT)}")

    if failures:
        raise SystemExit("image worker Docker validation failed:\n- " + "\n- ".join(failures))
    print("image worker Docker assets passed Phase 5 CPU-only policy validation")


if __name__ == "__main__":
    main()
