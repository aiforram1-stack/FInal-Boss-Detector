"""Internal SQLAlchemy records; API routes return shared contracts instead."""

from __future__ import annotations

from sqlalchemy import BigInteger, ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class CaseRecord(Base):
    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    claim: Mapped[str | None] = mapped_column(Text, nullable=True)
    privacy_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class EvidenceBlobRecord(Base):
    __tablename__ = "evidence_blobs"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detected_mime_type: Mapped[str] = mapped_column(String(127), nullable=False)
    storage_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    object_version: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class EvidenceAssetRecord(Base):
    __tablename__ = "evidence_assets"
    __table_args__ = (UniqueConstraint("case_id", "blob_sha256", name="uq_evidence_case_blob"),)

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.case_id", ondelete="RESTRICT"), nullable=False
    )
    blob_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"), nullable=False
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    client_mime_type: Mapped[str | None] = mapped_column(String(127), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class StructuralAnalysisRunRecord(Base):
    __tablename__ = "structural_analysis_runs"
    __table_args__ = (
        Index(
            "uq_structural_active_evidence_profile",
            "evidence_id",
            "analysis_profile",
            unique=True,
            sqlite_where=text("status = 'RUNNING'"),
        ),
    )

    analysis_run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.case_id", ondelete="RESTRICT"), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_assets.evidence_id", ondelete="RESTRICT"), nullable=False
    )
    analysis_profile: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    software_version: Mapped[str] = mapped_column(String(255), nullable=False)
    git_commit: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    terminal_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class StructuralTestResultRecord(Base):
    __tablename__ = "structural_test_results"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "test_id", name="uq_structural_run_test"),
    )

    result_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("structural_analysis_runs.analysis_run_id", ondelete="RESTRICT"),
        nullable=False,
    )
    test_id: Mapped[str] = mapped_column(String(255), nullable=False)
    test_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(500), nullable=True)
    runtime_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class StructuralArtifactRecord(Base):
    __tablename__ = "structural_artifacts"

    artifact_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("structural_analysis_runs.analysis_run_id", ondelete="RESTRICT"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    storage_uri: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(127), nullable=False)
    tool_source: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class StructuralReportRecord(Base):
    __tablename__ = "structural_reports"

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    analysis_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("structural_analysis_runs.analysis_run_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.case_id", ondelete="RESTRICT"), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_assets.evidence_id", ondelete="RESTRICT"), nullable=False
    )
    report_json_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    report_json_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    report_json_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    report_html_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    report_html_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    report_html_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
