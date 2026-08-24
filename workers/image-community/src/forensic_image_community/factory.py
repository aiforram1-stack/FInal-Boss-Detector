"""Compose worker services without importing RunPod in the core path."""

from __future__ import annotations

from pathlib import Path

import httpx
from pydantic import ValidationError

from forensic_image_community.cache_resolver import (
    CachedCheckpoint,
    RunPodModelCacheResolver,
)
from forensic_image_community.community_backend import CommunityForensicsBackend
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.fitness import WorkerFitnessCheck
from forensic_image_community.image_decoder import PillowImageDecoder
from forensic_image_community.input_fetcher import (
    HttpsInputFetcher,
    InputFetcher,
    SocketHostResolver,
)
from forensic_image_community.job_service import ImageCommunityJobService
from forensic_image_community.manifest import ModelManifest, load_model_manifest
from forensic_image_community.mock_backend import MockCommunityBackend
from forensic_image_community.model_backend import DetectorBackend
from forensic_image_community.phase6_validation import Phase6ValidationService
from forensic_image_community.preprocessing import CommunityForensicsPreprocessor
from forensic_image_community.result_builder import ResultBuilder
from forensic_image_community.secure_transport import PinnedHTTPTransport


def validated_manifest(path: Path) -> ModelManifest:
    try:
        return load_model_manifest(path)
    except (ValueError, ValidationError) as exc:
        raise WorkerError(
            WorkerErrorCode.MODEL_MANIFEST_INVALID,
            "Pinned model manifest is invalid.",
            internal_detail=type(exc).__name__,
        ) from exc


def resolve_runpod_checkpoint(
    settings: ImageCommunitySettings, manifest: ModelManifest
) -> CachedCheckpoint:
    if settings.require_verified_checkpoint_hash and (
        manifest.model.checkpoint_hash_status != "OBSERVED_BOOTSTRAP_HASH"
    ):
        raise WorkerError(
            WorkerErrorCode.WORKER_NOT_READY,
            "Verified mode requires an observed bootstrap checkpoint hash.",
        )
    expected_byte_length: int | None = manifest.model.checkpoint_byte_length
    expected_sha256: str | None = manifest.model.checkpoint_sha256
    if settings.checkpoint_bootstrap_mode:
        expected_byte_length = None
        expected_sha256 = None
    return RunPodModelCacheResolver(settings.model_cache_root).resolve(
        repository=manifest.model.repository,
        revision=manifest.model.revision,
        filename=manifest.model.filename,
        expected_byte_length=expected_byte_length,
        expected_sha256=expected_sha256,
    )


def build_job_service(
    settings: ImageCommunitySettings,
    *,
    input_fetcher: InputFetcher | None = None,
    http_client: httpx.Client | None = None,
) -> tuple[ImageCommunityJobService, WorkerFitnessCheck]:
    manifest = validated_manifest(settings.model_manifest)
    temp_root = settings.ensure_temp_root()
    if input_fetcher is None:
        resolver = SocketHostResolver()
        client = http_client or httpx.Client(
            transport=PinnedHTTPTransport(
                resolver=resolver,
                allowed_hosts=settings.allowed_input_hosts,
            ),
            trust_env=False,
        )
        input_fetcher = HttpsInputFetcher(
            client=client,
            resolver=resolver,
            allowed_hosts=settings.allowed_input_hosts,
            temp_root=temp_root,
            max_bytes=settings.max_input_bytes,
            chunk_bytes=settings.download_chunk_bytes,
            connect_timeout_seconds=settings.connect_timeout_seconds,
            read_timeout_seconds=settings.read_timeout_seconds,
            total_timeout_seconds=settings.total_timeout_seconds,
            allow_redirects=settings.allow_redirects,
            max_redirects=settings.max_redirects,
        )
    backend: DetectorBackend
    if settings.backend == "mock":
        backend = MockCommunityBackend()
    else:
        checkpoint_path = settings.model_cache / manifest.model.filename
        if settings.environment == "production":
            checkpoint_path = resolve_runpod_checkpoint(settings, manifest).checkpoint_path
        backend = CommunityForensicsBackend(
            manifest=manifest,
            checkpoint_path=checkpoint_path,
            container_digest=settings.container_digest,
            min_free_vram_bytes=settings.min_free_vram_bytes,
        )
    service = ImageCommunityJobService(
        manifest=manifest,
        input_fetcher=input_fetcher,
        image_decoder=PillowImageDecoder(
            max_width=settings.max_width,
            max_height=settings.max_height,
            max_pixels=settings.max_pixels,
            max_decoded_memory_bytes=settings.max_decoded_memory_bytes,
        ),
        preprocessor=CommunityForensicsPreprocessor(manifest),
        backend=backend,
        result_builder=ResultBuilder(),
    )
    return service, WorkerFitnessCheck(settings=settings, manifest=manifest, backend=backend)


def build_phase6_validation_service(
    settings: ImageCommunitySettings,
) -> Phase6ValidationService:
    if settings.environment != "production" or settings.backend != "community":
        raise WorkerError(
            WorkerErrorCode.WORKER_NOT_READY,
            "Phase 6 control jobs require the real production backend.",
        )
    manifest = validated_manifest(settings.model_manifest)
    checkpoint = resolve_runpod_checkpoint(settings, manifest)
    backend = CommunityForensicsBackend(
        manifest=manifest,
        checkpoint_path=checkpoint.checkpoint_path,
        container_digest=settings.container_digest,
        min_free_vram_bytes=settings.min_free_vram_bytes,
        checkpoint_expected_sha256=checkpoint.sha256,
        checkpoint_expected_byte_length=checkpoint.byte_length,
    )
    decoder = PillowImageDecoder(
        max_width=settings.max_width,
        max_height=settings.max_height,
        max_pixels=settings.max_pixels,
        max_decoded_memory_bytes=settings.max_decoded_memory_bytes,
    )
    preprocessor = CommunityForensicsPreprocessor(manifest)
    fitness = WorkerFitnessCheck(settings=settings, manifest=manifest, backend=backend)
    return Phase6ValidationService(
        settings=settings,
        manifest=manifest,
        checkpoint=checkpoint,
        backend=backend,
        fitness=fitness,
        decoder=decoder,
        preprocessor=preprocessor,
    )
