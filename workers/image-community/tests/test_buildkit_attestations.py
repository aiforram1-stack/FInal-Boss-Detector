from __future__ import annotations

import pytest

from scripts.verify_buildkit_attestations import (
    AttestationValidationError,
    validate_provenance,
    validate_sbom,
)


def spdx_document() -> dict[str, object]:
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": "forensic-image-community",
        "creationInfo": {
            "created": "2026-08-25T00:00:00Z",
            "creators": ["Tool: buildkit", "Tool: syft"],
        },
    }


def legacy_provenance() -> dict[str, object]:
    return {
        "builder": {"id": ""},
        "buildType": "https://mobyproject.org/buildkit@v1",
        "materials": [],
        "invocation": {"parameters": {}},
        "metadata": {"reproducible": False},
    }


def slsa_v1_statement() -> dict[str, object]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "name": "pkg:docker/example/image@sha256:digest?platform=linux%2Famd64",
                "digest": {"sha256": "a" * 64},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": (
                    "https://github.com/moby/buildkit/blob/master/"
                    "docs/attestations/slsa-definitions.md"
                ),
                "externalParameters": {},
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {"builder": {"id": "https://github.com/docker/build-push-action"}},
        },
    }


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"SPDX": spdx_document()}, id="documented-wrapper"),
        pytest.param(
            {"linux/amd64": {"SPDX": spdx_document()}},
            id="platform-wrapper",
        ),
        pytest.param(spdx_document(), id="direct-document"),
    ],
)
def test_buildkit_spdx_shapes_validate(payload: dict[str, object]) -> None:
    assert validate_sbom(payload)["SPDXID"] == "SPDXRef-DOCUMENT"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"SLSA": legacy_provenance()}, id="documented-legacy-wrapper"),
        pytest.param(
            {"linux/amd64": {"SLSA": slsa_v1_statement()}},
            id="platform-v1-statement-wrapper",
        ),
        pytest.param(slsa_v1_statement(), id="direct-v1-statement"),
    ],
)
def test_buildkit_provenance_shapes_validate(payload: dict[str, object]) -> None:
    assert validate_provenance(payload)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "expected exactly one"),
        ({"SPDX": {"SPDXID": "SPDXRef-DOCUMENT"}}, "spdxVersion"),
        (
            {
                "SPDX": {
                    **spdx_document(),
                    "creationInfo": {"creators": []},
                }
            },
            "creators",
        ),
    ],
)
def test_malformed_or_absent_spdx_fails_closed(
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(AttestationValidationError, match=message):
        validate_sbom(payload)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "expected exactly one"),
        (
            {
                "SLSA": {
                    **legacy_provenance(),
                    "buildType": "mutable-build-type",
                }
            },
            "buildType URI",
        ),
        (
            {
                "SLSA": {
                    **slsa_v1_statement(),
                    "subject": [],
                }
            },
            "no subjects",
        ),
        (
            {
                "SLSA": {
                    **slsa_v1_statement(),
                    "predicateType": "https://example.invalid/not-slsa",
                }
            },
            "not SLSA provenance",
        ),
    ],
)
def test_malformed_or_absent_provenance_fails_closed(
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(AttestationValidationError, match=message):
        validate_provenance(payload)
