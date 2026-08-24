"""API-only request and envelope models around the shared contracts."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from forensic_contracts import Case, EvidenceAsset, PrivacyMode, StructuralAnalysisRun
from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CaseCreateRequest(ApiModel):
    schema_version: Literal["1.0"] = "1.0"
    claim: str | None = Field(default=None, max_length=4000)
    privacy_mode: PrivacyMode = PrivacyMode.RESTRICTED


class CaseDetailResponse(ApiModel):
    schema_version: Literal["1.0"] = "1.0"
    case: Case
    evidence: list[EvidenceAsset]


class ErrorDetail(ApiModel):
    code: str
    message: str
    request_id: UUID


class ErrorEnvelope(ApiModel):
    schema_version: Literal["1.0"] = "1.0"
    error: ErrorDetail


class DependencyHealth(ApiModel):
    database: Literal["healthy", "unavailable"]
    storage: Literal["healthy", "unavailable"]
    results: Literal["healthy", "unavailable"]


class HealthResponse(ApiModel):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["healthy", "degraded"]
    dependencies: DependencyHealth


class StructuralAnalysisCollection(ApiModel):
    schema_version: Literal["1.0"] = "1.0"
    case_id: UUID
    evidence_id: UUID
    runs: list[StructuralAnalysisRun]
