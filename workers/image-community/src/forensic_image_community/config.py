"""Environment configuration with safe local defaults."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

WORKER_ROOT = Path(__file__).resolve().parents[2]
CONTAINER_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


def _parse_hosts(value: object) -> object:
    if isinstance(value, str):
        return frozenset(
            item.strip().lower().rstrip(".") for item in value.split(",") if item.strip()
        )
    return value


HostSet = Annotated[frozenset[str], NoDecode, BeforeValidator(_parse_hosts)]


class ImageCommunitySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="IMAGE_COMMUNITY_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["local", "test", "production"] = "local"
    backend: Literal["mock", "community"] = "mock"
    model_manifest: Path = WORKER_ROOT / "model-manifest.yaml"
    model_cache: Path = Path("/models/community-forensics")
    allow_model_download: bool = False
    max_input_bytes: int = Field(default=25 * 1024 * 1024, gt=0, le=1024 * 1024 * 1024)
    max_width: int = Field(default=16_384, gt=0, le=100_000)
    max_height: int = Field(default=16_384, gt=0, le=100_000)
    max_pixels: int = Field(default=40_000_000, gt=0, le=500_000_000)
    max_decoded_memory_bytes: int = Field(default=160_000_000, gt=0)
    download_chunk_bytes: int = Field(default=65_536, gt=0, le=4 * 1024 * 1024)
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=120)
    read_timeout_seconds: float = Field(default=20.0, gt=0, le=600)
    total_timeout_seconds: float = Field(default=30.0, gt=0, le=900)
    allowed_input_hosts: HostSet = frozenset()
    allow_redirects: bool = False
    max_redirects: int = Field(default=0, ge=0, le=5)
    temp_root: Path = Path(tempfile.gettempdir()) / "forensic-image-community"
    device: Literal["cuda"] = "cuda"
    precision: Literal["float32"] = "float32"
    require_cuda: bool = True
    min_free_vram_bytes: int = Field(default=1024 * 1024 * 1024, ge=0)
    container_digest: str | None = None

    @field_validator("allowed_input_hosts")
    @classmethod
    def validate_hosts(cls, value: frozenset[str]) -> frozenset[str]:
        for host in value:
            if not host or "/" in host or ":" in host or "@" in host or host.startswith("."):
                raise ValueError("allowed input hosts must be exact bare hostnames")
        return value

    @field_validator("container_digest")
    @classmethod
    def validate_container_digest(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not CONTAINER_DIGEST_RE.fullmatch(value):
            raise ValueError("container digest must be an immutable sha256 digest")
        return value

    @model_validator(mode="after")
    def validate_mode(self) -> Self:
        if self.download_chunk_bytes > self.max_input_bytes:
            raise ValueError("download chunk size cannot exceed maximum input bytes")
        if self.total_timeout_seconds < max(
            self.connect_timeout_seconds, self.read_timeout_seconds
        ):
            raise ValueError("total timeout must cover connect and read timeouts")
        if self.allow_redirects != (self.max_redirects > 0):
            raise ValueError("redirects require an explicit positive maximum")
        if self.environment == "production" and self.backend == "mock":
            raise ValueError("mock backend is prohibited in production")
        if self.environment == "production" and self.container_digest is None:
            raise ValueError("production requires a container digest")
        if self.backend == "community" and not self.require_cuda:
            raise ValueError("the Community Forensics production backend requires CUDA")
        return self

    def ensure_temp_root(self) -> Path:
        unresolved = self.temp_root.expanduser()
        if unresolved.exists() and unresolved.is_symlink():
            raise ValueError("temporary root cannot be a symbolic link")
        unresolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved = unresolved.resolve()
        if not resolved.is_dir():
            raise ValueError("temporary root is not a directory")
        return resolved
