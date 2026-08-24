"""Fail when repository candidates contain prohibited or suspicious artifacts."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_BYTES = 10 * 1024 * 1024
PROHIBITED_SUFFIXES = {
    ".avi",
    ".bin",
    ".ckpt",
    ".flac",
    ".key",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".onnx",
    ".pem",
    ".pt",
    ".pth",
    ".safetensors",
    ".wav",
}
PROHIBITED_NAMES = {".env", "credentials.json", "service-account.json"}
TEXT_SUFFIXES = {
    "",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "OpenAI-style secret": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
MUTABLE_IMAGE_PATTERN = re.compile(r"(?:^|\s)(?:FROM|image:)\s+\S+:latest(?:\s|$)", re.IGNORECASE)


def repository_candidates() -> list[Path]:
    git_executable = shutil.which("git")
    if git_executable is None:
        raise SystemExit("git executable is required for the repository safety check")
    result = subprocess.run(  # noqa: S603 - resolved Git path and constant arguments only
        [git_executable, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> None:
    violations: list[str] = []
    candidates = repository_candidates()
    for path in candidates:
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            violations.append(f"symlink is not allowed: {relative}")
            continue
        if not path.is_file():
            continue
        if path.name in PROHIBITED_NAMES:
            violations.append(f"prohibited secret filename: {relative}")
        if path.suffix.lower() in PROHIBITED_SUFFIXES:
            violations.append(f"prohibited media/model/secret suffix: {relative}")
        if path.stat().st_size > MAX_TRACKED_BYTES:
            violations.append(f"file exceeds {MAX_TRACKED_BYTES} bytes: {relative}")
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append(f"unexpected binary file: {relative}")
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                violations.append(f"{label} pattern found: {relative}")
        if MUTABLE_IMAGE_PATTERN.search(text):
            violations.append(f"mutable latest image reference found: {relative}")

    if violations:
        formatted = "\n".join(f"- {violation}" for violation in violations)
        raise SystemExit(f"repository safety check failed:\n{formatted}")
    print(f"repository safety check passed for {len(candidates)} candidate files")


if __name__ == "__main__":
    main()
