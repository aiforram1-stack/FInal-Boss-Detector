#!/usr/bin/env python3
"""Validate Buildx SBOM and provenance inspection payloads without guessing shape."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SPDX_VERSION = re.compile(r"^SPDX-[0-9]+\.[0-9]+$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
IN_TOTO_STATEMENTS = {
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
}
SLSA_PREDICATE_PREFIX = "https://slsa.dev/provenance/"


class AttestationValidationError(ValueError):
    """Raised when attached supply-chain evidence is absent or malformed."""


def _object(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AttestationValidationError(f"{label} must be a JSON object")
    return value


def _candidate(
    payload: Mapping[str, Any],
    *,
    kind: str,
    platform: str,
) -> Mapping[str, Any]:
    """Select one documented Buildx envelope without recursive permissiveness."""

    wrapper_key = "SPDX" if kind == "SBOM" else "SLSA"
    candidates: list[Mapping[str, Any]] = []
    seen: set[int] = set()

    def add(value: Any) -> None:
        if isinstance(value, Mapping) and id(value) not in seen:
            seen.add(id(value))
            candidates.append(value)

    add(payload)
    add(payload.get(wrapper_key))
    platform_payload = payload.get(platform)
    add(platform_payload)
    if isinstance(platform_payload, Mapping):
        add(platform_payload.get(wrapper_key))

    if kind == "SBOM":
        matches = [item for item in candidates if item.get("SPDXID") == "SPDXRef-DOCUMENT"]
    else:
        matches = [item for item in candidates if _looks_like_provenance(item)]
    if len(matches) != 1:
        raise AttestationValidationError(
            f"attached BuildKit {kind} has {len(matches)} supported payloads; expected exactly one"
        )
    return matches[0]


def _looks_like_provenance(value: Mapping[str, Any]) -> bool:
    if value.get("_type") in IN_TOTO_STATEMENTS:
        return True
    if isinstance(value.get("buildType"), str):
        return True
    build_definition = value.get("buildDefinition")
    return isinstance(build_definition, Mapping) and isinstance(
        build_definition.get("buildType"), str
    )


def validate_sbom(payload: Any, *, platform: str = "linux/amd64") -> Mapping[str, Any]:
    root = _object(payload, label="SBOM inspection payload")
    document = _candidate(root, kind="SBOM", platform=platform)
    version = document.get("spdxVersion")
    if not isinstance(version, str) or SPDX_VERSION.fullmatch(version) is None:
        raise AttestationValidationError("attached SPDX SBOM has an invalid spdxVersion")
    if document.get("dataLicense") != "CC0-1.0":
        raise AttestationValidationError("attached SPDX SBOM must use the CC0-1.0 data license")
    if not isinstance(document.get("name"), str) or not document["name"]:
        raise AttestationValidationError("attached SPDX SBOM has no document name")
    creation_info = document.get("creationInfo")
    if not isinstance(creation_info, Mapping):
        raise AttestationValidationError("attached SPDX SBOM has no creationInfo object")
    creators = creation_info.get("creators")
    if (
        not isinstance(creators, list)
        or not creators
        or not all(isinstance(item, str) and item for item in creators)
    ):
        raise AttestationValidationError("attached SPDX SBOM has no valid creators")
    return document


def _validate_sha256_subjects(subjects: Any) -> None:
    if not isinstance(subjects, list) or not subjects:
        raise AttestationValidationError("SLSA statement has no subjects")
    for subject in subjects:
        if not isinstance(subject, Mapping):
            continue
        digest = subject.get("digest")
        if isinstance(digest, Mapping):
            sha256 = digest.get("sha256")
            if isinstance(sha256, str) and SHA256.fullmatch(sha256):
                return
    raise AttestationValidationError("SLSA statement has no valid SHA-256 subject")


def _validate_legacy_predicate(predicate: Mapping[str, Any]) -> None:
    build_type = predicate.get("buildType")
    if not isinstance(build_type, str) or not build_type.startswith("https://"):
        raise AttestationValidationError("SLSA provenance has no valid buildType URI")
    if not isinstance(predicate.get("builder"), Mapping):
        raise AttestationValidationError("SLSA provenance has no builder object")
    if not isinstance(predicate.get("materials"), list):
        raise AttestationValidationError("SLSA provenance has no materials list")
    if not isinstance(predicate.get("metadata"), Mapping):
        raise AttestationValidationError("SLSA provenance has no metadata object")


def _validate_v1_predicate(predicate: Mapping[str, Any]) -> None:
    build_definition = predicate.get("buildDefinition")
    if not isinstance(build_definition, Mapping):
        raise AttestationValidationError("SLSA v1 provenance has no buildDefinition object")
    build_type = build_definition.get("buildType")
    if not isinstance(build_type, str) or not build_type.startswith("https://"):
        raise AttestationValidationError("SLSA v1 provenance has no valid buildType URI")
    run_details = predicate.get("runDetails")
    if not isinstance(run_details, Mapping) or not isinstance(run_details.get("builder"), Mapping):
        raise AttestationValidationError("SLSA v1 provenance has no runDetails.builder object")


def validate_provenance(
    payload: Any,
    *,
    platform: str = "linux/amd64",
) -> Mapping[str, Any]:
    root = _object(payload, label="provenance inspection payload")
    provenance = _candidate(root, kind="provenance", platform=platform)
    statement_type = provenance.get("_type")
    if statement_type is not None:
        if statement_type not in IN_TOTO_STATEMENTS:
            raise AttestationValidationError("unsupported in-toto statement type")
        predicate_type = provenance.get("predicateType")
        if not isinstance(predicate_type, str) or not predicate_type.startswith(
            SLSA_PREDICATE_PREFIX
        ):
            raise AttestationValidationError("in-toto statement is not SLSA provenance")
        _validate_sha256_subjects(provenance.get("subject"))
        predicate = _object(provenance.get("predicate"), label="SLSA predicate")
        if predicate_type == f"{SLSA_PREDICATE_PREFIX}v1":
            _validate_v1_predicate(predicate)
        else:
            _validate_legacy_predicate(predicate)
        return provenance

    if isinstance(provenance.get("buildDefinition"), Mapping):
        _validate_v1_predicate(provenance)
    else:
        _validate_legacy_predicate(provenance)
    return provenance


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationValidationError(f"cannot read valid JSON from {path}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--platform", default="linux/amd64")
    args = parser.parse_args()
    validate_sbom(load_json(args.sbom), platform=args.platform)
    validate_provenance(load_json(args.provenance), platform=args.platform)
    print(f"attached BuildKit SBOM and provenance passed for {args.platform}")


if __name__ == "__main__":
    main()
