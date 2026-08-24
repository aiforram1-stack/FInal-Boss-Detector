"""Internal SQLAlchemy records; API routes return shared contracts instead."""

from __future__ import annotations

from sqlalchemy import BigInteger, ForeignKey, String, Text, UniqueConstraint
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
