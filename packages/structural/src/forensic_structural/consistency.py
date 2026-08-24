"""Deterministic cross-tool consistency findings with non-conclusive wording."""

from __future__ import annotations

from forensic_contracts import (
    ConsistencyFinding,
    EvidenceAsset,
    FindingSeverity,
    IntegrityVerification,
    StructuralSummary,
)
from pydantic import JsonValue

FILE_TEST = "structural.file-signature.v1"
EXIF_TEST = "structural.exiftool-metadata.v1"
FFPROBE_TEST = "structural.ffprobe-container.v1"
MEDIAINFO_TEST = "structural.mediainfo.v1"
CONSISTENCY_TEST = "structural.metadata-consistency.v1"


def _finding(
    identifier: str,
    severity: FindingSeverity,
    description: str,
    fields: list[str],
    values: dict[str, JsonValue],
    tools: list[str],
    source_tests: list[str],
    limitations: list[str] | None = None,
) -> ConsistencyFinding:
    return ConsistencyFinding(
        schema_version="1.0",
        finding_id=f"structural.finding.{identifier}.v1",
        severity=severity,
        description=description,
        compared_fields=fields,
        observed_values=values,
        tool_sources=tools,
        source_test_ids=[*source_tests, CONSISTENCY_TEST],
        limitations=limitations or [],
    )


def _float(value: object) -> float | None:
    try:
        return float(str(value)) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _exif_value(metadata: dict[str, JsonValue], *names: str) -> JsonValue:
    targets = {item.lower() for item in names}
    for key, value in metadata.items():
        if key.rsplit(":", 1)[-1].lower() in targets:
            return value
    return None


def build_consistency_findings(
    *,
    evidence: EvidenceAsset,
    client_mime_type: str | None,
    integrity: IntegrityVerification,
    summary: StructuralSummary,
    outputs: dict[str, dict[str, JsonValue]],
) -> list[ConsistencyFinding]:
    findings: list[ConsistencyFinding] = []
    signature = outputs.get(FILE_TEST, {})
    extension_mime = signature.get("extension_mime_type")
    if extension_mime is not None and extension_mime != evidence.mime_type:
        findings.append(
            _finding(
                "extension-mime-mismatch",
                FindingSeverity.WARNING,
                (
                    "The filename extension and detected byte signature identify "
                    "different media types."
                ),
                ["filename extension", "detected MIME type"],
                {"extension_mime_type": extension_mime, "detected_mime_type": evidence.mime_type},
                ["internal file-signature adapter"],
                [FILE_TEST],
                ["Renaming or an uncommon extension can cause this mismatch."],
            )
        )
    if client_mime_type and client_mime_type != evidence.mime_type:
        findings.append(
            _finding(
                "client-mime-mismatch",
                FindingSeverity.INFO,
                "The upload-declared media type differs from the detected byte signature.",
                ["client MIME type", "detected MIME type"],
                {"client_mime_type": client_mime_type, "detected_mime_type": evidence.mime_type},
                ["upload metadata", "internal file-signature adapter"],
                [FILE_TEST],
                ["Client MIME values are untrusted hints."],
            )
        )
    if integrity.verified_byte_length != evidence.byte_length:
        findings.append(
            _finding(
                "byte-size-mismatch",
                FindingSeverity.ERROR,
                "The recomputed object size differs from the database byte length.",
                ["database byte length", "verified byte length"],
                {
                    "database_byte_length": evidence.byte_length,
                    "verified_byte_length": integrity.verified_byte_length,
                },
                ["evidence database", "integrity verifier"],
                [FILE_TEST],
            )
        )

    ffprobe = outputs.get(FFPROBE_TEST, {})
    format_data = ffprobe.get("format") if isinstance(ffprobe.get("format"), dict) else {}
    ffprobe_size = None if not isinstance(format_data, dict) else format_data.get("size")
    if ffprobe_size is not None and str(ffprobe_size) != str(evidence.byte_length):
        findings.append(
            _finding(
                "ffprobe-size-mismatch",
                FindingSeverity.WARNING,
                "ffprobe-reported size differs from the verified object size.",
                ["ffprobe format size", "verified byte length"],
                {"ffprobe_size": str(ffprobe_size), "verified_byte_length": evidence.byte_length},
                ["ffprobe", "integrity verifier"],
                [FFPROBE_TEST],
            )
        )

    exif_width = _exif_value(summary.metadata, "imagewidth", "exifimagewidth")
    exif_height = _exif_value(summary.metadata, "imageheight", "exifimageheight")
    ff_streams_value = ffprobe.get("streams")
    ff_streams = (
        [item for item in ff_streams_value if isinstance(item, dict)]
        if isinstance(ff_streams_value, list)
        else []
    )
    visual_stream = next((item for item in ff_streams if item.get("codec_type") == "video"), {})
    stream_width = visual_stream.get("width")
    stream_height = visual_stream.get("height")
    if exif_width is not None and stream_width is not None and str(exif_width) != str(stream_width):
        findings.append(
            _finding(
                "dimension-mismatch",
                FindingSeverity.WARNING,
                "Metadata tools report different image widths.",
                ["ExifTool width", "stream width"],
                {"exiftool_width": exif_width, "stream_width": stream_width},
                ["ExifTool", "ffprobe or MediaInfo"],
                [EXIF_TEST, FFPROBE_TEST, MEDIAINFO_TEST],
            )
        )
    if (
        exif_height is not None
        and stream_height is not None
        and str(exif_height) != str(stream_height)
    ):
        findings.append(
            _finding(
                "height-mismatch",
                FindingSeverity.WARNING,
                "Metadata tools report different image heights.",
                ["ExifTool height", "stream height"],
                {"exiftool_height": exif_height, "stream_height": stream_height},
                ["ExifTool", "ffprobe or MediaInfo"],
                [EXIF_TEST, FFPROBE_TEST, MEDIAINFO_TEST],
            )
        )

    _add_media_info_comparisons(findings, summary, outputs)
    category = evidence.mime_type.partition("/")[0]
    expected_present = (
        summary.image is not None and summary.image.width is not None
        if category == "image"
        else summary.audio is not None and summary.audio.codec is not None
        if category == "audio"
        else summary.video is not None and summary.video.video_codec is not None
    )
    if not expected_present:
        findings.append(
            _finding(
                "expected-structure-missing",
                FindingSeverity.INFO,
                "Expected structural values were not available from the installed parsers.",
                ["detected MIME category", "normalized structural fields"],
                {"mime_category": category, "expected_values_available": False},
                ["normalization service"],
                [FILE_TEST, EXIF_TEST, FFPROBE_TEST, MEDIAINFO_TEST],
                ["Corruption, parser coverage, or absent metadata can leave fields unavailable."],
            )
        )
    software = (
        summary.image.editing_software
        if summary.image
        else next(
            (str(value) for key, value in summary.metadata.items() if "software" in key.lower()),
            None,
        )
    )
    if software:
        findings.append(
            _finding(
                "software-tag-present",
                FindingSeverity.INFO,
                "Software or exporter metadata is present and requires contextual review.",
                ["software/exporter metadata"],
                {"software_tag": software},
                ["ExifTool or container metadata"],
                [EXIF_TEST, FFPROBE_TEST, MEDIAINFO_TEST],
                [
                    "Software tags may reflect routine capture, editing, transcoding, "
                    "or metadata copying."
                ],
            )
        )
    return sorted(findings, key=lambda item: item.finding_id)


def _add_media_info_comparisons(
    findings: list[ConsistencyFinding],
    summary: StructuralSummary,
    outputs: dict[str, dict[str, JsonValue]],
) -> None:
    ffprobe = outputs.get(FFPROBE_TEST, {})
    format_data = ffprobe.get("format") if isinstance(ffprobe.get("format"), dict) else {}
    ff_duration = _float(format_data.get("duration")) if isinstance(format_data, dict) else None
    mediainfo = outputs.get(MEDIAINFO_TEST, {})
    media = mediainfo.get("media") if isinstance(mediainfo.get("media"), dict) else {}
    tracks = media.get("track") if isinstance(media, dict) else None
    track_list = (
        [item for item in tracks if isinstance(item, dict)] if isinstance(tracks, list) else []
    )
    general = next((item for item in track_list if item.get("@type") == "General"), {})
    mi_duration = _float(general.get("Duration"))
    if (
        ff_duration is not None
        and mi_duration is not None
        and abs(ff_duration - mi_duration) > 0.05
    ):
        findings.append(
            _finding(
                "duration-mismatch",
                FindingSeverity.WARNING,
                "ffprobe and MediaInfo report different durations beyond the comparison tolerance.",
                ["ffprobe duration", "MediaInfo duration"],
                {"ffprobe_seconds": ff_duration, "mediainfo_seconds": mi_duration},
                ["ffprobe", "MediaInfo"],
                [FFPROBE_TEST, MEDIAINFO_TEST],
                ["Container time bases and rounding can create small differences."],
            )
        )
    ff_streams = ffprobe.get("streams")
    ff_count = len(ff_streams) if isinstance(ff_streams, list) else None
    mi_count = len([item for item in track_list if item.get("@type") != "General"])
    if ff_count is not None and track_list and ff_count != mi_count:
        findings.append(
            _finding(
                "stream-count-mismatch",
                FindingSeverity.WARNING,
                "ffprobe and MediaInfo report different media-stream counts.",
                ["ffprobe stream count", "MediaInfo track count"],
                {"ffprobe_stream_count": ff_count, "mediainfo_track_count": mi_count},
                ["ffprobe", "MediaInfo"],
                [FFPROBE_TEST, MEDIAINFO_TEST],
                ["Tools can classify attachment and data streams differently."],
            )
        )
    exif_time = _exif_value(summary.metadata, "datetimeoriginal", "createdate")
    tags = format_data.get("tags") if isinstance(format_data, dict) else None
    ff_time = tags.get("creation_time") if isinstance(tags, dict) else None
    mi_time = general.get("Encoded_Date") or general.get("Tagged_Date")
    observed = [str(item) for item in (exif_time, ff_time, mi_time) if item not in (None, "")]
    if len(set(observed)) > 1:
        findings.append(
            _finding(
                "creation-time-mismatch",
                FindingSeverity.WARNING,
                "Available creation timestamp fields disagree across metadata sources.",
                ["ExifTool creation time", "ffprobe creation time", "MediaInfo creation time"],
                {"exiftool": exif_time, "ffprobe": ff_time, "mediainfo": mi_time},
                ["ExifTool", "ffprobe", "MediaInfo"],
                [EXIF_TEST, FFPROBE_TEST, MEDIAINFO_TEST],
                ["Timestamp semantics and time zones vary between metadata fields."],
            )
        )
