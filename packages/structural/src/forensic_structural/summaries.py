"""Normalize controlled metadata-tool output into stable structural summaries."""

from __future__ import annotations

from datetime import datetime

from forensic_contracts import (
    AudioStructuralSummary,
    EvidenceAsset,
    ImageStructuralSummary,
    StructuralCommonSummary,
    StructuralSummary,
    ToolInventoryEntry,
    VideoStructuralSummary,
)
from pydantic import JsonValue


def _value(mapping: dict[str, JsonValue], *names: str) -> JsonValue:
    targets = {name.lower() for name in names}
    for key, value in mapping.items():
        tail = key.rsplit(":", 1)[-1].rsplit("]", 1)[-1].lower()
        if tail in targets or key.lower() in targets:
            return value
    return None


def _integer(value: object) -> int | None:
    try:
        return int(float(str(value))) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _number(value: object) -> float | None:
    try:
        return float(str(value)) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _text(value: object) -> str | None:
    return None if value in (None, "") else str(value)


def _boolean_present(value: object) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    return str(value).lower() not in {"false", "no", "0", "none"}


def _ffprobe_parts(
    output: dict[str, JsonValue],
) -> tuple[dict[str, JsonValue], list[dict[str, JsonValue]]]:
    format_value = output.get("format")
    streams_value = output.get("streams")
    format_data = format_value if isinstance(format_value, dict) else {}
    streams = (
        [item for item in streams_value if isinstance(item, dict)]
        if isinstance(streams_value, list)
        else []
    )
    return format_data, streams


def _mediainfo_tracks(output: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    media = output.get("media")
    if not isinstance(media, dict):
        return []
    tracks = media.get("track")
    if not isinstance(tracks, list):
        return []
    return [item for item in tracks if isinstance(item, dict)]


def build_structural_summary(
    *,
    evidence: EvidenceAsset,
    client_mime_type: str | None,
    tool_inventory: list[ToolInventoryEntry],
    started_at: datetime,
    completed_at: datetime,
    outputs: dict[str, dict[str, JsonValue]],
    warnings: list[str],
) -> StructuralSummary:
    signature = outputs.get("structural.file-signature.v1", {})
    exif = outputs.get("structural.exiftool-metadata.v1", {})
    ffprobe = outputs.get("structural.ffprobe-container.v1", {})
    mediainfo = outputs.get("structural.mediainfo.v1", {})
    format_data, streams = _ffprobe_parts(ffprobe)
    category = evidence.mime_type.partition("/")[0]

    common = StructuralCommonSummary(
        schema_version="1.0",
        original_filename=evidence.filename,
        detected_mime_type=evidence.mime_type,
        client_mime_type=client_mime_type,
        byte_length=evidence.byte_length,
        sha256=evidence.sha256,
        sha512=evidence.sha512,
        storage_uri=evidence.storage_uri,
        extension_signature_consistent=(
            signature.get("extension_signature_consistent")
            if isinstance(signature.get("extension_signature_consistent"), bool)
            else None
        ),
        tool_availability=tool_inventory,
        analysis_started_at=started_at,
        analysis_completed_at=completed_at,
        warnings=warnings,
    )

    image = _image_summary(exif, format_data, streams) if category == "image" else None
    audio = _audio_summary(format_data, streams, mediainfo) if category == "audio" else None
    video = _video_summary(format_data, streams, mediainfo) if category == "video" else None
    metadata = dict(exif)
    normalized_streams = [{str(key): value for key, value in stream.items()} for stream in streams]
    return StructuralSummary(
        schema_version="1.0",
        common=common,
        image=image,
        audio=audio,
        video=video,
        metadata=metadata,
        streams=normalized_streams,
    )


def _image_summary(
    exif: dict[str, JsonValue],
    format_data: dict[str, JsonValue],
    streams: list[dict[str, JsonValue]],
) -> ImageStructuralSummary:
    video_stream = next((item for item in streams if item.get("codec_type") == "video"), {})
    bits = _value(exif, "bitspersample", "bitdepth")
    return ImageStructuralSummary(
        schema_version="1.0",
        format=_text(_value(exif, "filetype", "fileformat"))
        or _text(format_data.get("format_name")),
        width=_integer(_value(exif, "imagewidth", "exifimagewidth"))
        or _integer(video_stream.get("width")),
        height=_integer(_value(exif, "imageheight", "exifimageheight"))
        or _integer(video_stream.get("height")),
        orientation=_text(_value(exif, "orientation")),
        color_space=_text(_value(exif, "colorspace")),
        bit_depth=_integer(bits),
        alpha_channel=_boolean_present(_value(exif, "alphachannels", "alpha")),
        icc_profile=_boolean_present(_value(exif, "profiledescription", "icc_profile")),
        exif_present=any("exif" in key.lower() for key in exif),
        camera_make=_text(_value(exif, "make")),
        camera_model=_text(_value(exif, "model")),
        capture_timestamp=_text(_value(exif, "datetimeoriginal", "createdate", "datetimecreated")),
        gps_present=any("gps" in key.lower() for key in exif),
        editing_software=_text(_value(exif, "software", "creatortool")),
        embedded_thumbnail=any("thumbnail" in key.lower() for key in exif),
        compression={
            "compression": _value(exif, "compression"),
            "quality": _value(exif, "quality", "jpegqualityestimate"),
        },
    )


def _audio_summary(
    format_data: dict[str, JsonValue],
    streams: list[dict[str, JsonValue]],
    mediainfo: dict[str, JsonValue],
) -> AudioStructuralSummary:
    audio_streams = [item for item in streams if item.get("codec_type") == "audio"]
    stream = audio_streams[0] if audio_streams else {}
    tags_value = stream.get("tags")
    tags: dict[str, JsonValue] = tags_value if isinstance(tags_value, dict) else {}
    media_tracks = _mediainfo_tracks(mediainfo)
    track = next((item for item in media_tracks if item.get("@type") == "Audio"), {})
    return AudioStructuralSummary(
        schema_version="1.0",
        container=_text(format_data.get("format_name")),
        codec=_text(stream.get("codec_name")) or _text(track.get("Format")),
        duration_seconds=_number(format_data.get("duration")) or _number(track.get("Duration")),
        bit_rate=_integer(format_data.get("bit_rate")) or _integer(track.get("BitRate")),
        sample_rate=_integer(stream.get("sample_rate")) or _integer(track.get("SamplingRate")),
        bit_depth=_integer(stream.get("bits_per_sample")) or _integer(track.get("BitDepth")),
        channel_count=_integer(stream.get("channels")) or _integer(track.get("Channels")),
        channel_layout=_text(stream.get("channel_layout")) or _text(track.get("ChannelLayout")),
        encoder=_text(tags.get("encoder")) or _text(track.get("Encoded_Library")),
        metadata_tags={str(key): value for key, value in tags.items()},
        start_time_seconds=_number(stream.get("start_time")),
        audio_stream_count=len(audio_streams),
    )


def _video_summary(
    format_data: dict[str, JsonValue],
    streams: list[dict[str, JsonValue]],
    mediainfo: dict[str, JsonValue],
) -> VideoStructuralSummary:
    video_streams = [item for item in streams if item.get("codec_type") == "video"]
    audio_streams = [item for item in streams if item.get("codec_type") == "audio"]
    subtitle_streams = [item for item in streams if item.get("codec_type") == "subtitle"]
    video = video_streams[0] if video_streams else {}
    tags_value = format_data.get("tags")
    tags: dict[str, JsonValue] = tags_value if isinstance(tags_value, dict) else {}
    media_tracks = _mediainfo_tracks(mediainfo)
    general = next((item for item in media_tracks if item.get("@type") == "General"), {})
    starts = [_number(item.get("start_time")) for item in streams]
    numeric_starts = [item for item in starts if item is not None]
    first = numeric_starts[0] if numeric_starts else None
    differences = [round(item - first, 6) for item in numeric_starts] if first is not None else []
    return VideoStructuralSummary(
        schema_version="1.0",
        container=_text(format_data.get("format_name")) or _text(general.get("Format")),
        duration_seconds=_number(format_data.get("duration")) or _number(general.get("Duration")),
        file_bit_rate=_integer(format_data.get("bit_rate"))
        or _integer(general.get("OverallBitRate")),
        video_stream_count=len(video_streams),
        audio_stream_count=len(audio_streams),
        subtitle_stream_count=len(subtitle_streams),
        video_codec=_text(video.get("codec_name")),
        codec_profile=_text(video.get("profile")),
        width=_integer(video.get("width")),
        height=_integer(video.get("height")),
        pixel_format=_text(video.get("pix_fmt")),
        nominal_frame_rate=_text(video.get("r_frame_rate")),
        average_frame_rate=_text(video.get("avg_frame_rate")),
        time_base=_text(video.get("time_base")),
        color_primaries=_text(video.get("color_primaries")),
        transfer_characteristics=_text(video.get("color_transfer")),
        audio_codecs=[str(item["codec_name"]) for item in audio_streams if item.get("codec_name")],
        audio_sample_rates=[
            rate
            for item in audio_streams
            if (rate := _integer(item.get("sample_rate"))) is not None
        ],
        channel_layouts=[
            str(item["channel_layout"]) for item in audio_streams if item.get("channel_layout")
        ],
        encoder_tags={str(key): value for key, value in tags.items()},
        start_time_differences=differences,
    )
