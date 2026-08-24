"""Typed access to application dependencies."""

from fastapi import Request

from forensic_api.services.cases import CaseService
from forensic_api.services.evidence_intake import EvidenceIntakeService


def case_service(request: Request) -> CaseService:
    service: CaseService = request.app.state.case_service
    return service


def evidence_service(request: Request) -> EvidenceIntakeService:
    service: EvidenceIntakeService = request.app.state.evidence_service
    return service
