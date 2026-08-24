"""Declarative structural-test registry and applicability rules."""

from __future__ import annotations

from forensic_contracts import StructuralTestDefinition

ALL_MEDIA = ["image", "audio", "video"]

STRUCTURAL_TESTS: tuple[StructuralTestDefinition, ...] = (
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.file-signature.v1",
        test_version="1.0.0",
        description="Compare stored byte signature, detected MIME type, and filename extension.",
        applicable_mime_categories=ALL_MEDIA,
        required_tool=None,
        timeout_seconds=5,
        expected_output_type="file signature summary",
        known_limitations=["Signature matching identifies format families, not authenticity."],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.exiftool-metadata.v1",
        test_version="1.0.0",
        description="Extract bounded metadata using ExifTool JSON output.",
        applicable_mime_categories=ALL_MEDIA,
        required_tool="exiftool",
        timeout_seconds=30,
        expected_output_type="metadata object",
        known_limitations=[
            "Metadata may be absent, inaccurate, stripped, or intentionally edited."
        ],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.ffprobe-container.v1",
        test_version="1.0.0",
        description="Inspect container and streams using ffprobe JSON output.",
        applicable_mime_categories=ALL_MEDIA,
        required_tool="ffprobe",
        timeout_seconds=30,
        expected_output_type="format and stream objects",
        known_limitations=["Container metadata is not evidence of authorship or authenticity."],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.mediainfo.v1",
        test_version="1.0.0",
        description="Inspect media tracks using MediaInfo JSON output.",
        applicable_mime_categories=ALL_MEDIA,
        required_tool="mediainfo",
        timeout_seconds=30,
        expected_output_type="media track objects",
        known_limitations=["Parser support varies by container and codec."],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.image-summary.v1",
        test_version="1.0.0",
        description="Normalize image structure from available metadata tools.",
        applicable_mime_categories=["image"],
        required_tool=None,
        timeout_seconds=5,
        expected_output_type="image structural summary",
        known_limitations=["Missing metadata is common and is not an authenticity signal."],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.audio-summary.v1",
        test_version="1.0.0",
        description="Normalize audio container and stream structure.",
        applicable_mime_categories=["audio"],
        required_tool=None,
        timeout_seconds=5,
        expected_output_type="audio structural summary",
        known_limitations=["No waveform or deepfake analysis is performed."],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.video-summary.v1",
        test_version="1.0.0",
        description="Normalize video container and stream structure.",
        applicable_mime_categories=["video"],
        required_tool=None,
        timeout_seconds=5,
        expected_output_type="video structural summary",
        known_limitations=["No frame extraction, scene analysis, or inference is performed."],
    ),
    StructuralTestDefinition(
        schema_version="1.0",
        test_id="structural.metadata-consistency.v1",
        test_version="1.0.0",
        description="Compare deterministic values reported by storage and metadata parsers.",
        applicable_mime_categories=ALL_MEDIA,
        required_tool=None,
        timeout_seconds=5,
        expected_output_type="consistency findings",
        known_limitations=["A mismatch is a review lead, not a conclusion about authenticity."],
    ),
)


class StructuralTestRegistry:
    def __init__(
        self, definitions: tuple[StructuralTestDefinition, ...] = STRUCTURAL_TESTS
    ) -> None:
        identifiers = [item.test_id for item in definitions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("structural test IDs must be unique")
        self.definitions = definitions

    def get(self, test_id: str) -> StructuralTestDefinition:
        for definition in self.definitions:
            if definition.test_id == test_id:
                return definition
        raise KeyError(test_id)

    @staticmethod
    def category_for_mime(mime_type: str) -> str | None:
        category = mime_type.partition("/")[0]
        return category if category in {"image", "audio", "video"} else None

    def is_applicable(self, test_id: str, mime_type: str) -> bool:
        category = self.category_for_mime(mime_type)
        return category is not None and category in self.get(test_id).applicable_mime_categories
