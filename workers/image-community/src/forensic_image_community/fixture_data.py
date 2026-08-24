"""Programmatically generated, rights-clear tiny local fixture bytes."""

from __future__ import annotations

import struct
import zlib


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))


def generated_rgb_png() -> bytes:
    """Return a deterministic 4x3 RGB PNG without reading a media file."""

    width, height = 4, 3
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            row.extend(((x * 53 + y * 7) % 256, (y * 79 + x * 11) % 256, (x + y) * 31))
        rows.append(bytes(row))
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        signature
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(b"".join(rows), level=9))
        + _png_chunk(b"IEND", b"")
    )
