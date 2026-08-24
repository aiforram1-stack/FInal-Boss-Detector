"""Small signature allowlist for Phase 2 media intake.

This identifies container/file families from bytes. It does not decode media or
claim that the complete file is semantically valid.
"""

from __future__ import annotations

SUPPORTED_MEDIA_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "audio/mpeg",
        "audio/wav",
        "audio/flac",
        "video/mp4",
        "video/quicktime",
        "video/webm",
    }
)


def detect_media_type(prefix: bytes) -> str | None:
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"WEBP":
        return "image/webp"
    if len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"WAVE":
        return "audio/wav"
    if prefix.startswith(b"fLaC"):
        return "audio/flac"
    if prefix.startswith(b"ID3") or (
        len(prefix) >= 2 and prefix[0] == 0xFF and prefix[1] & 0xE0 == 0xE0
    ):
        return "audio/mpeg"
    if len(prefix) >= 12 and prefix[4:8] == b"ftyp":
        major_brand = prefix[8:12]
        if major_brand == b"qt  ":
            return "video/quicktime"
        return "video/mp4"
    if prefix.startswith(b"\x1aE\xdf\xa3") and b"webm" in prefix[:8192].lower():
        return "video/webm"
    return None
