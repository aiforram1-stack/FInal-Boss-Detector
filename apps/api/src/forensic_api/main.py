"""FastAPI application factory for Phase 2 local evidence intake."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from forensic_evidence import LocalContentAddressedStorage, StorageBackend
from forensic_structural import LocalResultStorage, SafeSubprocessRunner
from forensic_structural.service import StructuralAnalysisEngine
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from forensic_api.config import Settings
from forensic_api.db.repositories import Repository
from forensic_api.db.session import Database, build_database
from forensic_api.errors import ApiError
from forensic_api.logging_config import (
    configure_logging,
    request_id_context,
    safe_request_id,
)
from forensic_api.routes import cases, evidence, health, structural
from forensic_api.schemas import ErrorDetail, ErrorEnvelope
from forensic_api.services.cases import CaseService
from forensic_api.services.evidence_intake import EvidenceIntakeService
from forensic_api.services.structural import StructuralAnalysisService

logger = logging.getLogger(__name__)


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    envelope = ErrorEnvelope(
        error=ErrorDetail(
            code=code,
            message=message,
            request_id=request_id_context.get(),
        )
    )
    return JSONResponse(status_code=status_code, content=envelope.model_dump(mode="json"))


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    storage: StorageBackend | None = None,
    result_storage: LocalResultStorage | None = None,
    structural_engine: StructuralAnalysisEngine | None = None,
    initialize_schema: bool = False,
) -> FastAPI:
    configured = settings or Settings()
    configure_logging(configured.log_level)
    configured_database = database or build_database(configured.database_url)
    configured_storage = storage or LocalContentAddressedStorage(
        configured.evidence_storage_root,
        max_upload_bytes=configured.max_upload_bytes,
        upload_chunk_bytes=configured.upload_chunk_bytes,
        allowed_media_types=configured.allowed_media_types,
    )
    configured_result_storage = result_storage or LocalResultStorage(
        configured.structural_result_root
    )
    runner = SafeSubprocessRunner(
        timeout_seconds=configured.structural_tool_timeout_seconds,
        max_output_bytes=configured.structural_max_output_bytes,
    )
    configured_engine = structural_engine or StructuralAnalysisEngine(
        runner=runner,
        exiftool_binary=configured.exiftool_binary,
        ffprobe_binary=configured.ffprobe_binary,
        mediainfo_binary=configured.mediainfo_binary,
    )
    if initialize_schema:
        configured_database.create_schema_for_tests()

    repository = Repository(configured_database.sessions)
    app = FastAPI(
        title="Multimedia Forensic Platform — Local Structural Analysis",
        version="0.3.0",
        description=(
            "CPU-only Phase 3 API with immutable evidence intake and deterministic "
            "structural reporting. No evidence download or detector inference."
        ),
    )
    app.state.settings = configured
    app.state.database = configured_database
    app.state.storage = configured_storage
    app.state.result_storage = configured_result_storage
    app.state.repository = repository
    app.state.case_service = CaseService(repository)
    app.state.evidence_service = EvidenceIntakeService(repository, configured_storage)
    app.state.structural_service = StructuralAnalysisService(
        repository=repository,
        evidence_storage=configured_storage,
        result_storage=configured_result_storage,
        engine=configured_engine,
        template_directory=configured.report_template_dir,
        enabled=configured.structural_analysis_enabled,
        git_commit=configured.structural_git_commit,
    )

    @app.middleware("http")
    async def correlation_id(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = safe_request_id(request.headers.get("X-Request-ID"))
        token = request_id_context.set(request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_context.reset(token)

    @app.exception_handler(ApiError)
    async def handle_api_error(_: Request, exc: ApiError) -> JSONResponse:
        logger.warning("request failed code=%s", exc.code)
        return _error_response(exc.status_code, exc.code, exc.public_message)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
        return _error_response(422, "VALIDATION_ERROR", "The request did not validate.")

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        message = "The request could not be processed."
        if exc.status_code == 404:
            message = "The requested resource was not found."
        return _error_response(exc.status_code, "HTTP_ERROR", message)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, __: Exception) -> JSONResponse:
        logger.error("unexpected request failure", exc_info=False)
        return _error_response(500, "INTERNAL_ERROR", "An internal error occurred.")

    app.include_router(health.router)
    app.include_router(cases.router)
    app.include_router(evidence.router)
    app.include_router(structural.router)
    return app
