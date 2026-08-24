from __future__ import annotations

import pytest

from scripts.verify_package_access import verify_package


def test_private_linked_container_package_is_accepted() -> None:
    verify_package(
        {
            "package_type": "container",
            "visibility": "private",
            "repository": {"full_name": "example/forensic-platform"},
        },
        "example/forensic-platform",
        "https://github.com/example/forensic-platform",
    )


def test_private_container_uses_oci_source_when_package_api_omits_repository() -> None:
    verify_package(
        {"package_type": "container", "visibility": "private"},
        "example/forensic-platform",
        "https://github.com/example/forensic-platform",
    )


@pytest.mark.parametrize(
    "data",
    [
        {"visibility": "public", "repository": {"full_name": "example/forensic-platform"}},
        {"visibility": "private", "repository": {"full_name": "other/repository"}},
        {"visibility": "private"},
        [],
    ],
)
def test_public_unlinked_or_malformed_package_is_rejected(data: object) -> None:
    with pytest.raises(ValueError):
        verify_package(
            data,
            "example/forensic-platform",
            "https://github.com/example/forensic-platform",
        )


def test_wrong_oci_source_is_rejected_when_package_api_omits_repository() -> None:
    with pytest.raises(ValueError, match="OCI source label"):
        verify_package(
            {"package_type": "container", "visibility": "private"},
            "example/forensic-platform",
            "https://github.com/other/repository",
        )
