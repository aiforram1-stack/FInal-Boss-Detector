"""Adapters for deterministic local metadata tools."""

from forensic_structural.adapters.base import AdapterResult
from forensic_structural.adapters.exiftool import ExifToolAdapter
from forensic_structural.adapters.ffprobe import FfprobeAdapter
from forensic_structural.adapters.file_signature import FileSignatureAdapter
from forensic_structural.adapters.mediainfo import MediaInfoAdapter

__all__ = [
    "AdapterResult",
    "ExifToolAdapter",
    "FfprobeAdapter",
    "FileSignatureAdapter",
    "MediaInfoAdapter",
]
