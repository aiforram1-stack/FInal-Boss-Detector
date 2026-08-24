"""Typed access to application dependencies."""

from fastapi import Request

from forensic_api.services.cases import CaseService
from forensic_api.services.evidence_intake import EvidenceIntakeService
from forensic_api.services.structural import StructuralAnalysisService


def case_service(request: Request) -> CaseService:
    service: CaseService = request.app.state.case_service
    return service


def evidence_service(request: Request) -> EvidenceIntakeService:
    service: EvidenceIntakeService = request.app.state.evidence_service
    return service


def structural_service(request: Request) -> StructuralAnalysisService:
    service: StructuralAnalysisService = request.app.state.structural_service
    return service
