from __future__ import annotations

from pathlib import Path

import pytest
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.image_decoder import PillowImageDecoder
from helpers import fetched_file, generated_image_bytes
from PIL import features


def decoder(**overrides: int) -> PillowImageDecoder:
    values = {
        "max_width": 1024,
        "max_height": 1024,
        "max_pixels": 1024 * 1024,
        "max_decoded_memory_bytes": 4 * 1024 * 1024,
    }
    values.update(overrides)
    return PillowImageDecoder(**values)


@pytest.mark.parametrize(
    ("image_format", "mime_type", "expected_format"),
    [
        ("JPEG", "image/jpeg", "JPEG"),
        ("PNG", "image/png", "PNG"),
        pytest.param(
            "WEBP",
            "image/webp",
            "WEBP",
            marks=pytest.mark.skipif(not features.check("webp"), reason="Pillow WebP unavailable"),
        ),
    ],
)
def test_valid_supported_images_are_verified_reopened_and_converted_to_rgb(
    tmp_path: Path, image_format: str, mime_type: str, expected_format: str
) -> None:
    content = generated_image_bytes(image_format, mode="RGB")
    fetched = fetched_file(tmp_path, content, mime_type)
    decoded = decoder().decode(fetched, expected_mime_type=mime_type)
    try:
        assert decoded.metadata.detected_format == expected_format
        assert decoded.metadata.detected_mime_type == mime_type
        assert decoded.metadata.output_color_mode == "RGB"
        assert decoded.image.mode == "RGB"
        assert decoded.image.size == (8, 6)
    finally:
        decoded.close()


@pytest.mark.parametrize(
    "content",
    [
        b"not an image",
        generated_image_bytes("JPEG")[:24],
    ],
)
def test_invalid_and_truncated_images_are_rejected(tmp_path: Path, content: bytes) -> None:
    fetched = fetched_file(tmp_path, content, "image/jpeg")
    with pytest.raises(WorkerError) as raised:
        decoder().decode(fetched, expected_mime_type="image/jpeg")
    assert raised.value.code == WorkerErrorCode.IMAGE_DECODE_FAILED


def test_decompression_bomb_and_pixel_limits_are_errors(tmp_path: Path) -> None:
    content = generated_image_bytes("PNG", size=(20, 20))
    fetched = fetched_file(tmp_path, content, "image/png")
    with pytest.raises(WorkerError) as raised:
        decoder(max_pixels=100).decode(fetched, expected_mime_type="image/png")
    assert raised.value.code == WorkerErrorCode.IMAGE_DIMENSIONS_EXCEEDED


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_width": 7},
        {"max_height": 5},
        {"max_decoded_memory_bytes": 8 * 6 * 4 - 1},
    ],
)
def test_dimensions_and_decoded_memory_are_bounded(
    tmp_path: Path, overrides: dict[str, int]
) -> None:
    content = generated_image_bytes("PNG")
    with pytest.raises(WorkerError) as raised:
        decoder(**overrides).decode(
            fetched_file(tmp_path, content, "image/png"), expected_mime_type="image/png"
        )
    assert raised.value.code == WorkerErrorCode.IMAGE_DIMENSIONS_EXCEEDED


def test_unsupported_format_and_mime_disagreement_are_rejected(tmp_path: Path) -> None:
    gif = generated_image_bytes("GIF")
    with pytest.raises(WorkerError):
        decoder().decode(fetched_file(tmp_path, gif, "image/png"), expected_mime_type="image/png")

    png = generated_image_bytes("PNG")
    with pytest.raises(WorkerError) as raised:
        decoder().decode(fetched_file(tmp_path, png, "image/jpeg"), expected_mime_type="image/jpeg")
    assert raised.value.code == WorkerErrorCode.UNSUPPORTED_MIME_TYPE


def test_exif_orientation_is_applied_before_rgb_conversion(tmp_path: Path) -> None:
    jpeg = generated_image_bytes("JPEG", size=(3, 2), exif_orientation=6)
    decoded = decoder().decode(
        fetched_file(tmp_path, jpeg, "image/jpeg"), expected_mime_type="image/jpeg"
    )
    try:
        assert decoded.metadata.original_width == 3
        assert decoded.metadata.original_height == 2
        assert decoded.image.size == (2, 3)
        assert decoded.metadata.orientation_handling == "exif_transpose_applied_orientation_6"
    finally:
        decoded.close()


def test_rgb_conversion_is_deterministic_and_file_handle_is_closed(tmp_path: Path) -> None:
    content = generated_image_bytes("PNG", mode="L")
    first_fetched = fetched_file(tmp_path, content, "image/png", name="first.part")
    second_fetched = fetched_file(tmp_path, content, "image/png", name="second.part")
    first = decoder().decode(first_fetched, expected_mime_type="image/png")
    second = decoder().decode(second_fetched, expected_mime_type="image/png")
    try:
        assert first.image.tobytes() == second.image.tobytes()
        assert first.image.mode == "RGB"
        first_fetched.path.unlink()
        second_fetched.path.unlink()
    finally:
        first.close()
        second.close()
