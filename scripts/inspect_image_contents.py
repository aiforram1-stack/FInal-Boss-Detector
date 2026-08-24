#!/usr/bin/env python3
"""Inspect a built container root filesystem without executing the image."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import PurePosixPath
from typing import IO

TEXT_SUFFIXES = {"", ".cfg", ".ini", ".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
MODEL_SUFFIXES = {".ckpt", ".onnx", ".pt", ".pth", ".safetensors"}
MEDIA_SUFFIXES = {".avi", ".flac", ".mkv", ".mov", ".mp3", ".mp4", ".wav"}
SECRET_PATTERNS = {
    "GitHub token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "RunPod token": re.compile(rb"\brpa_[A-Za-z0-9]{24,}\b"),
    "signed URL": re.compile(
        rb"https?://[^\s]+\?[^\s]*X-Amz-Signature=[A-Za-z0-9%]+", re.IGNORECASE
    ),
    "developer home": re.compile(rb"/Users/ramkumar|/home/runner/work", re.IGNORECASE),
}


def path_violation(path: PurePosixPath, is_file: bool) -> str | None:
    parts = tuple(part.lower() for part in path.parts)
    name = path.name.lower()
    if ".git" in parts:
        return ".git content"
    if name == ".env" or name.startswith(".env."):
        return "environment file"
    prohibited_parts = {"private_cases", "evidence", "uploads", "checkpoints", "model-cache"}
    if prohibited_parts.intersection(parts):
        return "private evidence or model-cache path"
    if "reports" in parts and "private" in parts:
        return "private report path"
    if ".cache" in parts and ("huggingface" in parts or "torch" in parts):
        return "model cache path"
    if is_file and parts and parts[0] == "models":
        return "file in external model mount path"
    if is_file and "app" in parts and path.suffix.lower() in MODEL_SUFFIXES:
        return "model/checkpoint file in application"
    if is_file and "app" in parts and path.suffix.lower() in MEDIA_SUFFIXES:
        return "unapproved media in application"
    if is_file and "app" in parts and path.suffix.lower() in {".key", ".pem"}:
        return "credential-like file in application"
    if is_file and name in {"credentials.json", "service-account.json"}:
        return "credential file"
    return None


def scan_export(stream: IO[bytes]) -> tuple[int, list[str]]:
    violations: list[str] = []
    files = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            normalized = member.name[2:] if member.name.startswith("./") else member.name
            path = PurePosixPath(normalized.lstrip("/"))
            violation = path_violation(path, member.isfile())
            if violation:
                violations.append(f"{violation}: {path}")
            if not member.isfile():
                continue
            files += 1
            if "app" not in tuple(part.lower() for part in path.parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES or member.size > 2 * 1024 * 1024:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            content = extracted.read(2 * 1024 * 1024 + 1)
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(content):
                    violations.append(f"{label} content: {path}")
    return files, violations


def inspect_image(image: str) -> tuple[int, list[str]]:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker is required for image-content inspection")
    metadata_result = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", image], check=True, capture_output=True, text=True
    )
    metadata = json.loads(metadata_result.stdout)
    serialized_metadata = metadata_result.stdout.encode()
    violations: list[str] = []
    if not isinstance(metadata, list) or not metadata:
        violations.append("docker inspect returned no image metadata")
    else:
        config = metadata[0].get("Config") or {}
        if config.get("User") != "10001:10001":
            violations.append("image runtime user is not 10001:10001")
        if not config.get("Entrypoint"):
            violations.append("image has no explicit entrypoint")
        for environment in config.get("Env") or []:
            name = str(environment).split("=", maxsplit=1)[0]
            if re.search(r"(?:TOKEN|SECRET|PASSWORD|API_KEY)", name, re.IGNORECASE):
                violations.append(f"secret-like image environment variable: {name}")
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(serialized_metadata):
            violations.append(f"{label} found in image configuration")

    created = subprocess.run(  # noqa: S603
        [docker, "create", image], check=True, capture_output=True, text=True
    ).stdout.strip()
    try:
        exported = subprocess.Popen(  # noqa: S603
            [docker, "export", created], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if exported.stdout is None:
            raise RuntimeError("docker export did not provide a stream")
        file_count, export_violations = scan_export(exported.stdout)
        _, stderr = exported.communicate()
        if exported.returncode != 0:
            raise RuntimeError(f"docker export failed: {stderr.decode(errors='replace')}")
        violations.extend(export_violations)
    finally:
        subprocess.run(  # noqa: S603
            [docker, "rm", "--force", created], check=False, capture_output=True
        )
    return file_count, violations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        files, violations = inspect_image(args.image)
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise SystemExit(f"image-content inspection failed: {exc}") from exc
    if violations:
        raise SystemExit("image-content inspection failed:\n- " + "\n- ".join(violations))
    print(f"image-content inspection passed for {files} regular files")


if __name__ == "__main__":
    main()
