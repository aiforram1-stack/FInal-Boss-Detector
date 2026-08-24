from __future__ import annotations

import sys

import numpy as np
from forensic_image_community.contracts import DecodedImage, DecodeMetadata
from forensic_image_community.mock_backend import MockCommunityBackend
from forensic_image_community.preprocessing import CommunityForensicsPreprocessor
from helpers import manifest
from PIL import Image


def decoded_rgb(color: tuple[int, int, int], size: tuple[int, int] = (500, 440)) -> DecodedImage:
    return DecodedImage(
        image=Image.new("RGB", size, color),
        metadata=DecodeMetadata(
            decoder_name="generated",
            decoder_version="1",
            detected_format="PNG",
            detected_mime_type="image/png",
            original_width=size[0],
            original_height=size[1],
            original_color_mode="RGB",
            orientation_handling="exif_orientation_absent_or_normal",
            output_color_mode="RGB",
        ),
    )


def test_exact_output_shape_channel_order_scaling_and_normalization() -> None:
    decoded = decoded_rgb((255, 0, 128))
    try:
        output = CommunityForensicsPreprocessor(manifest()).preprocess(decoded)
    finally:
        decoded.close()
    assert output.tensor.shape == (1, 3, 384, 384)
    assert output.tensor.dtype == np.float32
    expected = np.asarray(
        [
            (1.0 - 0.485) / 0.229,
            (0.0 - 0.456) / 0.224,
            ((128 / 255) - 0.406) / 0.225,
        ],
        dtype=np.float32,
    )
    np.testing.assert_allclose(output.tensor[0, :, 0, 0], expected, rtol=1e-6, atol=1e-6)
    assert output.record.resize_short_edge == 440
    assert output.record.crop_strategy == "center_384x384"
    assert output.record.tensor_layout == "NCHW"


def test_transform_and_fingerprint_are_deterministic() -> None:
    processor = CommunityForensicsPreprocessor(manifest())
    first_image = decoded_rgb((20, 40, 60), (441, 700))
    second_image = decoded_rgb((20, 40, 60), (441, 700))
    try:
        first = processor.preprocess(first_image)
        second = processor.preprocess(second_image)
    finally:
        first_image.close()
        second_image.close()
    assert np.array_equal(first.tensor, second.tensor)
    assert first.record.preprocessing_sha256 == second.record.preprocessing_sha256
    assert first.record.preprocessing_sha256 == processor.fingerprint()
    assert first.record.upstream_revision == "3540a3f0d688f8bf492a8aed48613b891f88047e"


def test_mock_backend_is_deterministic_distinct_and_never_imports_torch() -> None:
    assert "torch" not in sys.modules
    processor = CommunityForensicsPreprocessor(manifest())
    first_image = decoded_rgb((1, 2, 3))
    second_image = decoded_rgb((3, 2, 1))
    try:
        first_input = processor.preprocess(first_image)
        second_input = processor.preprocess(second_image)
    finally:
        first_image.close()
        second_image.close()
    backend = MockCommunityBackend()
    first = backend.infer(first_input)
    repeated = backend.infer(first_input)
    different = backend.infer(second_input)
    assert first == repeated
    assert first.raw_logit != different.raw_logit
    assert first.mock_backend is True
    assert first.raw_outputs["mock_backend"] is True
    assert "torch" not in sys.modules


def test_mock_identity_is_complete_and_unmistakable() -> None:
    identity = MockCommunityBackend().identity()
    assert identity.detector_name.endswith("-mock")
    assert identity.model_revision.startswith("mock-")
    assert identity.checkpoint_sha256
    assert identity.container_digest.startswith("sha256:")
    assert identity.model_extra == {"mock_backend": True}
