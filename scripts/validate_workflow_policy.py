#!/usr/bin/env python3
"""Fail closed on mutable or over-privileged GitHub workflow policy."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
PR_WORKFLOW = WORKFLOW_DIR / "image-community-container-pr.yml"
PUBLISH_WORKFLOW = WORKFLOW_DIR / "publish-image-community.yml"
ACTION_PATTERN = re.compile(r"^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.+))?$", re.MULTILINE)
FULL_SHA_ACTION = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@/-]+)?@[a-f0-9]{40}$"
)


def action_pin_failures(path: Path, text: str) -> list[str]:
    failures: list[str] = []
    for action, comment in ACTION_PATTERN.findall(text):
        if action.startswith("./"):
            continue
        if action.startswith("docker://"):
            if "@sha256:" not in action:
                failures.append(f"{path.name}: OCI action is not digest-pinned: {action}")
            continue
        if not FULL_SHA_ACTION.fullmatch(action):
            failures.append(f"{path.name}: Action is not pinned to a full commit: {action}")
        if not re.search(r"\bv[0-9]+(?:\.[0-9]+){0,2}\b", comment):
            failures.append(f"{path.name}: Action pin lacks a reviewed release comment: {action}")
    return failures


def main() -> None:
    failures: list[str] = []
    workflows = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        failures.extend(action_pin_failures(path, text))
        if "pull_request_target" in text:
            failures.append(f"{path.name}: pull_request_target is prohibited")
        if re.search(r"\blatest\b", text, re.IGNORECASE):
            failures.append(f"{path.name}: mutable latest reference is prohibited")

    if not PR_WORKFLOW.is_file() or not PUBLISH_WORKFLOW.is_file():
        failures.append("both Phase 5 container workflows must exist")
    else:
        pr_text = PR_WORKFLOW.read_text(encoding="utf-8")
        if not re.search(r"(?m)^permissions:\s*\n\s+contents:\s+read\s*$", pr_text):
            failures.append("PR workflow must declare contents: read as its only token permission")
        for prohibited in (
            "packages: write",
            "id-token: write",
            "attestations: write",
            "push: true",
            "docker/login-action",
            "secrets.GITHUB_TOKEN",
        ):
            if prohibited in pr_text:
                failures.append(f"PR workflow contains prohibited capability: {prohibited}")
        if "platforms: linux/amd64" not in pr_text:
            failures.append("PR workflow must build Linux AMD64 explicitly")
        if "builder: default" not in pr_text:
            failures.append("PR GPU validation must use the native Docker builder")
        if 'docker image rm "$MOCK_IMAGE"' not in pr_text:
            failures.append("PR workflow must reclaim the verified mock image before GPU build")
        if 'test "$GITHUB_ACTIONS" = "true"' not in pr_text:
            failures.append("PR runner cleanup must be guarded as GitHub Actions-only")
        if "/usr/local/lib/android" not in pr_text:
            failures.append("PR workflow must reclaim unused hosted-runner SDK space")

        publish_text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        required_publish_fragments = (
            "workflow_dispatch:",
            "branches: [main]",
            "github.ref == 'refs/heads/main'",
            "contents: read",
            "packages: write",
            "id-token: write",
            "attestations: write",
            "platforms: linux/amd64",
            "push: true",
            "SOURCE_COMMIT: ${{ github.sha }}",
            "tag_reference=$image_repository:sha-$SOURCE_COMMIT",
            "password: ${{ secrets.GITHUB_TOKEN }}",
            'test "$GITHUB_ACTIONS" = "true"',
            "/usr/local/lib/android",
        )
        for fragment in required_publish_fragments:
            if fragment not in publish_text:
                failures.append(f"publish workflow is missing required policy: {fragment}")
        for prohibited in (
            "pull_request:",
            "pull_request_target",
            "contents: write",
            "actions: write",
            "administration: write",
            "secrets: write",
            "PAT",
            "personal access token",
        ):
            if prohibited in publish_text:
                failures.append(f"publish workflow contains prohibited policy: {prohibited}")
        mutable_tag = re.compile(
            r"(?m)^\s+tags:\s+.*:(?:latest|main|master|dev|stable|production)\s*$"
        )
        if mutable_tag.search(publish_text):
            failures.append("publish workflow contains a mutable container tag")
        build_argument_blocks = re.findall(
            r"(?m)^\s+build-args:\s*\|\s*\n((?:\s{12}.+\n)+)", publish_text
        )
        if any(
            re.search(r"(?:TOKEN|SECRET|PASSWORD|API_KEY)", block)
            for block in build_argument_blocks
        ):
            failures.append("publish workflow passes a secret-like Docker build argument")

    if failures:
        raise SystemExit("workflow policy validation failed:\n- " + "\n- ".join(failures))
    print(f"workflow policy passed for {len(workflows)} workflow files")


if __name__ == "__main__":
    main()
