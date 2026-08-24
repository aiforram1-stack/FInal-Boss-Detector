"""Dependency-aware health response without internal path details."""

from fastapi import APIRouter, Request, Response, status

from forensic_api.schemas import DependencyHealth, HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(request: Request, response: Response) -> HealthResponse:
    database_ok: bool = request.app.state.database.healthcheck()
    storage_ok: bool = request.app.state.storage.healthcheck()
    results_ok: bool = request.app.state.result_storage.healthcheck()
    healthy = database_ok and storage_ok and results_ok
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="healthy" if healthy else "degraded",
        dependencies=DependencyHealth(
            database="healthy" if database_ok else "unavailable",
            storage="healthy" if storage_ok else "unavailable",
            results="healthy" if results_ok else "unavailable",
        ),
    )
