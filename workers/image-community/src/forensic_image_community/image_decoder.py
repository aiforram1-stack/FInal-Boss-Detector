"""Bounded Pillow decoding for hostile JPEG, PNG and WebP inputs."""

from __future__ import annotations

import warnings
from typing import Protocol

import PIL
from PIL import Image, ImageFile, ImageOps, UnidentifiedImageError

from forensic_image_community.contracts import DecodedImage, DecodeMetadata, FetchedInput
from forensic_image_community.errors import WorkerError, WorkerErrorCode

FORMAT_TO_MIME = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
}
SUPPORTED_MODES = frozenset({"RGB", "RGBA", "L", "LA", "P", "CMYK"})
EXIF_ORIENTATION_TAG = 274


class ImageDecoder(Protocol):
    def decode(self, fetched: FetchedInput, *, expected_mime_type: str) -> DecodedImage: ...


class PillowImageDecoder:
    def __init__(
        self,
        *,
        max_width: int,
        max_height: int,
        max_pixels: int,
        max_decoded_memory_bytes: int,
    ) -> None:
        self.max_width = max_width
        self.max_height = max_height
        self.max_pixels = max_pixels
        self.max_decoded_memory_bytes = max_decoded_memory_bytes
        Image.MAX_IMAGE_PIXELS = max_pixels
        ImageFile.LOAD_TRUNCATED_IMAGES = False

    def _validate_dimensions(self, width: int, height: int) -> None:
        pixels = width * height
        decoded_estimate = pixels * 4
        if (
            width < 1
            or height < 1
            or width > self.max_width
            or height > self.max_height
            or pixels > self.max_pixels
            or decoded_estimate > self.max_decoded_memory_bytes
        ):
            raise WorkerError(
                WorkerErrorCode.IMAGE_DIMENSIONS_EXCEEDED,
                "Decoded image dimensions exceed the configured policy.",
            )

    def decode(self, fetched: FetchedInput, *, expected_mime_type: str) -> DecodedImage:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(fetched.path) as probe:
                    detected_format = (probe.format or "").upper()
                    width, height = probe.size
                    self._validate_dimensions(width, height)
                    if detected_format not in FORMAT_TO_MIME:
                        raise WorkerError(
                            WorkerErrorCode.IMAGE_DECODE_FAILED,
                            "Decoded image format is not supported.",
                        )
                    probe.verify()

                with Image.open(fetched.path) as source:
                    detected_format = (source.format or "").upper()
                    detected_mime = FORMAT_TO_MIME.get(detected_format, "")
                    width, height = source.size
                    self._validate_dimensions(width, height)
                    if (
                        detected_mime != expected_mime_type
                        or detected_mime != fetched.response_mime_type
                    ):
                        raise WorkerError(
                            WorkerErrorCode.UNSUPPORTED_MIME_TYPE,
                            "Decoded image format does not match approved MIME metadata.",
                        )
                    if source.mode not in SUPPORTED_MODES:
                        raise WorkerError(
                            WorkerErrorCode.IMAGE_DECODE_FAILED,
                            "Decoded image color mode is not supported.",
                        )
                    if int(getattr(source, "n_frames", 1)) != 1:
                        raise WorkerError(
                            WorkerErrorCode.IMAGE_DECODE_FAILED,
                            "Animated or multi-frame images are not supported.",
                        )
                    original_mode = source.mode
                    orientation = source.getexif().get(EXIF_ORIENTATION_TAG)
                    source.load()
                    oriented = ImageOps.exif_transpose(source)
                    try:
                        converted = oriented.convert("RGB")
                        try:
                            detached = converted.copy()
                        finally:
                            converted.close()
                    finally:
                        if oriented is not source:
                            oriented.close()
        except WorkerError:
            raise
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise WorkerError(
                WorkerErrorCode.IMAGE_DIMENSIONS_EXCEEDED,
                "Decoded image dimensions exceed the configured policy.",
                internal_detail=type(exc).__name__,
            ) from exc
        except (
            UnidentifiedImageError,
            OSError,
            SyntaxError,
            ValueError,
        ) as exc:
            raise WorkerError(
                WorkerErrorCode.IMAGE_DECODE_FAILED,
                "Image could not be safely decoded.",
                internal_detail=type(exc).__name__,
            ) from exc

        orientation_handling = (
            f"exif_transpose_applied_orientation_{orientation}"
            if orientation not in {None, 1}
            else "exif_orientation_absent_or_normal"
        )
        return DecodedImage(
            image=detached,
            metadata=DecodeMetadata(
                decoder_name="Pillow",
                decoder_version=PIL.__version__,
                detected_format=detected_format,
                detected_mime_type=detected_mime,
                original_width=width,
                original_height=height,
                original_color_mode=original_mode,
                orientation_handling=orientation_handling,
                output_color_mode="RGB",
            ),
        )
