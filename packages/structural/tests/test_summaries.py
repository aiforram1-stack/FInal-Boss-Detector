from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from forensic_contracts import ToolAvailabilityStatus, ToolInventoryEntry
from forensic_structural.summaries import build_structural_summary

from .helpers import stored_evidence


def inventory() -> list[ToolInventoryEntry]:
    return [
        ToolInventoryEntry(
            schema_version="1.0",
            tool_name="controlled",
            status=ToolAvailabilityStatus.AVAILABLE,
            version="1.0.0",
        )
    ]


def test_image_summary_from_controlled_exif_and_stream_output(tmp_path: Path) -> None:
    _, evidence, _ = stored_evidence(tmp_path)
    now = datetime.now(UTC)
    summary = build_structural_summary(
        evidence=evidence,
        client_mime_type="image/png",
        tool_inventory=inventory(),
        started_at=now,
        completed_at=now,
        outputs={
            "structural.file-signature.v1": {"extension_signature_consistent": True},
            "structural.exiftool-metadata.v1": {
                "File:FileType": "PNG",
                "EXIF:ImageWidth": 640,
                "EXIF:ImageHeight": 480,
                "EXIF:Make": "Synthetic",
                "EXIF:Model": "Fixture",
                "EXIF:Software": "Routine Exporter",
                "EXIF:GPSLatitude": 1.0,
            },
            "structural.ffprobe-container.v1": {
                "format": {"format_name": "png_pipe"},
                "streams": [{"codec_type": "video", "width": 640, "height": 480}],
            },
        },
        warnings=[],
    )
    assert summary.image is not None
    assert summary.image.width == 640
    assert summary.image.height == 480
    assert summary.image.camera_make == "Synthetic"
    assert summary.image.gps_present is True
    assert summary.audio is None and summary.video is None


@pytest.mark.parametrize(
    ("mime_type", "expected_kind"),
    [("audio/wav", "audio"), ("video/mp4", "video")],
)
def test_audio_and_video_summaries(tmp_path: Path, mime_type: str, expected_kind: str) -> None:
    _, evidence, _ = stored_evidence(tmp_path)
    evidence = evidence.model_copy(update={"mime_type": mime_type})
    now = datetime.now(UTC)
    summary = build_structural_summary(
        evidence=evidence,
        client_mime_type=mime_type,
        tool_inventory=inventory(),
        started_at=now,
        completed_at=now,
        outputs={
            "structural.file-signature.v1": {"extension_signature_consistent": False},
            "structural.ffprobe-container.v1": {
                "format": {"format_name": "fixture", "duration": "2.5", "bit_rate": "8000"},
                "streams": [
                    {
                        "codec_type": "video",
                        "codec_name": "h264",
                        "width": 320,
                        "height": 240,
                        "r_frame_rate": "30/1",
                    },
                    {
                        "codec_type": "audio",
                        "codec_name": "pcm_s16le",
                        "sample_rate": "16000",
                        "channels": 1,
                        "channel_layout": "mono",
                    },
                ],
            },
        },
        warnings=[],
    )
    if expected_kind == "audio":
        assert summary.audio is not None
        assert summary.audio.codec == "pcm_s16le"
        assert summary.audio.sample_rate == 16000
        assert summary.video is None
    else:
        assert summary.video is not None
        assert summary.video.video_codec == "h264"
        assert summary.video.audio_codecs == ["pcm_s16le"]
        assert summary.audio is None
