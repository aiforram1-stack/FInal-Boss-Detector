"""Integrity-gated structural analysis and deterministic report routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from forensic_contracts import StructuralAnalysisRun, StructuralReport

from forensic_api.dependencies import structural_service
from forensic_api.schemas import ErrorEnvelope, StructuralAnalysisCollection
from forensic_api.services.structural import StructuralAnalysisService

router = APIRouter(tags=["structural-analysis"])


@router.post(
    "/v1/cases/{case_id}/evidence/{evidence_id}/structural-analysis",
    response_model=StructuralAnalysisRun,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"model": ErrorEnvelope},
        409: {"model": ErrorEnvelope},
        500: {"model": ErrorEnvelope},
        503: {"model": ErrorEnvelope},
    },
)
def start_structural_analysis(
    case_id: UUID,
    evidence_id: UUID,
    service: Annotated[StructuralAnalysisService, Depends(structural_service)],
) -> StructuralAnalysisRun:
    return service.start(case_id, evidence_id)


@router.get(
    "/v1/cases/{case_id}/evidence/{evidence_id}/structural-analysis",
    response_model=StructuralAnalysisCollection,
    responses={404: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope}},
)
def get_structural_analysis(
    case_id: UUID,
    evidence_id: UUID,
    service: Annotated[StructuralAnalysisService, Depends(structural_service)],
) -> StructuralAnalysisCollection:
    return StructuralAnalysisCollection(
        case_id=case_id,
        evidence_id=evidence_id,
        runs=service.list_runs(case_id, evidence_id),
    )


@router.get(
    "/v1/cases/{case_id}/reports/structural.json",
    responses={
        200: {"model": StructuralReport, "content": {"application/json": {}}},
        404: {"model": ErrorEnvelope},
        503: {"model": ErrorEnvelope},
    },
)
def get_structural_json_report(
    case_id: UUID,
    service: Annotated[StructuralAnalysisService, Depends(structural_service)],
) -> Response:
    content, media_type = service.report_bytes(case_id, html=False)
    return Response(content=content, media_type=media_type)


@router.get(
    "/v1/cases/{case_id}/reports/structural.html",
    response_class=Response,
    responses={
        200: {"content": {"text/html": {}}},
        404: {"model": ErrorEnvelope},
        503: {"model": ErrorEnvelope},
    },
)
def get_structural_html_report(
    case_id: UUID,
    service: Annotated[StructuralAnalysisService, Depends(structural_service)],
) -> Response:
    content, media_type = service.report_bytes(case_id, html=True)
    return Response(content=content, media_type=media_type)
