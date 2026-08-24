"""Evidence upload and metadata-only retrieval routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Response, UploadFile, status
from forensic_contracts import EvidenceAsset

from forensic_api.dependencies import case_service, evidence_service
from forensic_api.schemas import ErrorEnvelope
from forensic_api.services.cases import CaseService
from forensic_api.services.evidence_intake import EvidenceIntakeService

router = APIRouter(prefix="/v1/cases/{case_id}/evidence", tags=["evidence"])


@router.post(
    "",
    response_model=EvidenceAsset,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorEnvelope},
        404: {"model": ErrorEnvelope},
        413: {"model": ErrorEnvelope},
        415: {"model": ErrorEnvelope},
        422: {"model": ErrorEnvelope},
        503: {"model": ErrorEnvelope},
    },
)
def upload_evidence(
    case_id: UUID,
    response: Response,
    file: Annotated[UploadFile, File()],
    service: Annotated[EvidenceIntakeService, Depends(evidence_service)],
) -> EvidenceAsset:
    result = service.ingest(
        case_id=case_id,
        stream=file.file,
        original_filename=file.filename,
        client_mime_type=file.content_type,
    )
    response.headers["X-Content-Deduplicated"] = str(result.content_deduplicated).lower()
    response.headers["X-Evidence-Association-Reused"] = str(result.association_reused).lower()
    if result.association_reused:
        response.status_code = status.HTTP_200_OK
    return result.evidence


@router.get(
    "/{evidence_id}",
    response_model=EvidenceAsset,
    responses={404: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope}},
)
def get_evidence(
    case_id: UUID,
    evidence_id: UUID,
    cases: Annotated[CaseService, Depends(case_service)],
) -> EvidenceAsset:
    return cases.evidence(case_id, evidence_id)
