"""Case creation and metadata retrieval routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from forensic_contracts import Case

from forensic_api.dependencies import case_service
from forensic_api.schemas import CaseCreateRequest, CaseDetailResponse, ErrorEnvelope
from forensic_api.services.cases import CaseService

router = APIRouter(prefix="/v1/cases", tags=["cases"])


@router.post(
    "",
    response_model=Case,
    status_code=status.HTTP_201_CREATED,
    responses={422: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope}},
)
def create_case(
    request: CaseCreateRequest,
    service: Annotated[CaseService, Depends(case_service)],
) -> Case:
    return service.create(request.claim, request.privacy_mode)


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    responses={404: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope}},
)
def get_case(
    case_id: UUID,
    service: Annotated[CaseService, Depends(case_service)],
) -> CaseDetailResponse:
    case, evidence = service.detail(case_id)
    return CaseDetailResponse(case=case, evidence=evidence)
