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
    structural_analysis_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("STRUCTURAL_ANALYSIS_ENABLED", "structural_analysis_enabled"),
    )
    structural_tool_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=300,
        validation_alias=AliasChoices(
            "STRUCTURAL_TOOL_TIMEOUT_SECONDS", "structural_tool_timeout_seconds"
        ),
    )
    structural_max_output_bytes: int = Field(
        default=1024 * 1024,
        ge=1024,
        le=16 * 1024 * 1024,
        validation_alias=AliasChoices("STRUCTURAL_MAX_OUTPUT_BYTES", "structural_max_output_bytes"),
    )
    structural_result_root: Path = Field(
        default=Path("./var/results"),
        validation_alias=AliasChoices("STRUCTURAL_RESULT_ROOT", "structural_result_root"),
    )
    exiftool_binary: str = Field(
        default="exiftool",
        validation_alias=AliasChoices("EXIFTOOL_BINARY", "exiftool_binary"),
    )
    ffprobe_binary: str = Field(
        default="ffprobe",
        validation_alias=AliasChoices("FFPROBE_BINARY", "ffprobe_binary"),
    )
    mediainfo_binary: str = Field(
        default="mediainfo",
        validation_alias=AliasChoices("MEDIAINFO_BINARY", "mediainfo_binary"),
    )
    report_template_dir: Path = Field(
        default=Path("./packages/structural/src/forensic_structural/templates"),
        validation_alias=AliasChoices("REPORT_TEMPLATE_DIR", "report_template_dir"),
    )
    structural_git_commit: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{40}$",
        validation_alias=AliasChoices("GIT_COMMIT", "structural_git_commit"),
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

    @field_validator("exiftool_binary", "ffprobe_binary", "mediainfo_binary")
    @classmethod
    def validate_binary_name(cls, value: str) -> str:
        if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("tool binary configuration contains invalid characters")
        return value

    @model_validator(mode="after")
    def validate_chunking_and_root(self) -> Settings:
        if self.upload_chunk_bytes > self.max_upload_bytes:
            raise ValueError("UPLOAD_CHUNK_BYTES cannot exceed MAX_UPLOAD_BYTES")
        root = self.evidence_storage_root.expanduser().resolve(strict=False)
        if root in {Path("/"), Path.home().resolve()}:
            raise ValueError("EVIDENCE_STORAGE_ROOT is too broad")
        self.evidence_storage_root = root
        result_root = self.structural_result_root.expanduser().resolve(strict=False)
        if result_root in {Path("/"), Path.home().resolve()}:
            raise ValueError("STRUCTURAL_RESULT_ROOT is too broad")
        self.structural_result_root = result_root
        self.report_template_dir = self.report_template_dir.expanduser().resolve(strict=False)
        return self
