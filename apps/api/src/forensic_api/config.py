"""Validated local API configuration."""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_MEDIA_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "audio/mpeg",
        "audio/wav",
        "audio/flac",
        "video/mp4",
        "video/quicktime",
        "video/webm",
    }
)


class Settings(BaseSettings):
    """Application settings loaded from environment variables or `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
        case_sensitive=True,
    )

    database_url: str = Field(
        default="sqlite:///./var/forensic.db",
        validation_alias=AliasChoices("DATABASE_URL", "database_url"),
    )
    evidence_storage_root: Path = Field(
        default=Path("./var/evidence"),
        validation_alias=AliasChoices("EVIDENCE_STORAGE_ROOT", "evidence_storage_root"),
    )
    max_upload_bytes: int = Field(
        default=100 * 1024 * 1024,
        ge=1,
        validation_alias=AliasChoices("MAX_UPLOAD_BYTES", "max_upload_bytes"),
    )
    upload_chunk_bytes: int = Field(
        default=1024 * 1024,
        ge=1,
        validation_alias=AliasChoices("UPLOAD_CHUNK_BYTES", "upload_chunk_bytes"),
    )
    allowed_media_types: frozenset[str] = Field(
        default=DEFAULT_MEDIA_TYPES,
        validation_alias=AliasChoices("ALLOWED_MEDIA_TYPES", "allowed_media_types"),
    )
    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("LOG_LEVEL", "log_level"),
    )

    @field_validator("database_url")
    @classmethod
    def require_sqlite(cls, value: str) -> str:
        if not value.startswith("sqlite:///"):
            raise ValueError("Phase 2 supports only SQLite database URLs")
        return value

    @field_validator("allowed_media_types", mode="before")
    @classmethod
    def parse_media_types(cls, value: object) -> object:
        if isinstance(value, str):
            return frozenset(item.strip() for item in value.split(",") if item.strip())
        return value

    @field_validator("allowed_media_types")
    @classmethod
    def validate_media_types(cls, value: frozenset[str]) -> frozenset[str]:
        if not value:
            raise ValueError("at least one allowed media type is required")
        invalid = {item for item in value if "/" not in item or "*" in item}
        if invalid:
            raise ValueError("media allowlist entries must be exact MIME types")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in logging.getLevelNamesMapping():
            raise ValueError("invalid log level")
        return normalized

    @model_validator(mode="after")
    def validate_chunking_and_root(self) -> Settings:
        if self.upload_chunk_bytes > self.max_upload_bytes:
            raise ValueError("UPLOAD_CHUNK_BYTES cannot exceed MAX_UPLOAD_BYTES")
        root = self.evidence_storage_root.expanduser().resolve(strict=False)
        if root in {Path("/"), Path.home().resolve()}:
            raise ValueError("EVIDENCE_STORAGE_ROOT is too broad")
        self.evidence_storage_root = root
        return self
