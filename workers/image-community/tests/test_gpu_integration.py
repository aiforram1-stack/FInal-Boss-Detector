from __future__ import annotations

import os

import pytest
from forensic_image_community.community_backend import CommunityForensicsBackend
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.errors import WorkerError
from forensic_image_community.fitness import WorkerFitnessCheck
from helpers import manifest


@pytest.mark.gpu
@pytest.mark.integration
def test_real_gpu_fitness_and_output_shape() -> None:
    if os.environ.get("RUN_GPU_TESTS") != "1":
        pytest.skip("RUN_GPU_TESTS=1 is required for the explicit GPU integration test")
    try:
        import torch  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("PyTorch GPU runtime is unavailable")
    if not torch.cuda.is_available():
        pytest.skip("CUDA is unavailable")
    configured = ImageCommunitySettings()
    if configured.backend != "community":
        pytest.skip("IMAGE_COMMUNITY_BACKEND=community is required")
    if configured.container_digest is None:
        pytest.skip("a verified IMAGE_COMMUNITY_CONTAINER_DIGEST is required")
    loaded = manifest()
    checkpoint = configured.model_cache / loaded.model.filename
    backend = CommunityForensicsBackend(
        manifest=loaded,
        checkpoint_path=checkpoint,
        container_digest=configured.container_digest,
        min_free_vram_bytes=configured.min_free_vram_bytes,
    )
    try:
        backend.verify_checkpoint()
    except WorkerError as exc:
        pytest.skip(f"verified checkpoint prerequisite is unmet: {exc.code.value}")
    fitness = WorkerFitnessCheck(settings=configured, manifest=loaded, backend=backend)
    readiness = fitness.check()
    assert readiness.ready is True, readiness.model_dump(mode="json")
    assert backend._model is not None
    assert backend._model.training is False
