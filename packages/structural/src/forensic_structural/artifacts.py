"""Create-only local result artifacts addressed through logical URIs."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class StoredResultArtifact:
    storage_uri: str
    sha256: str
    byte_length: int


class LocalResultStorage:
    """Append-only report/artifact storage outside the repository."""

    def __init__(self, root: Path) -> None:
        unresolved = root.expanduser()
        if unresolved.exists() and unresolved.is_symlink():
            raise ValueError("result root cannot be a symbolic link")
        unresolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = unresolved.resolve()
        if self.root in {Path("/"), Path.home().resolve()}:
            raise ValueError("result root is too broad")

    def put_bytes(
        self, case_id: UUID, run_id: UUID, name: str, content: bytes
    ) -> StoredResultArtifact:
        if not SAFE_NAME.fullmatch(name):
            raise ValueError("invalid result artifact name")
        directory = self._directory(case_id, run_id)
        self._ensure_directory(directory)
        destination = self._safe_path(directory / name)
        sha256 = hashlib.sha256(content).hexdigest()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(destination, flags, 0o600)
        except FileExistsError as exc:
            read_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                read_flags |= os.O_NOFOLLOW
            try:
                existing_descriptor = os.open(destination, read_flags)
                with os.fdopen(existing_descriptor, "rb") as existing_file:
                    mode = os.fstat(existing_file.fileno()).st_mode
                    if not stat.S_ISREG(mode):
                        raise RuntimeError(
                            "existing result artifact is not a regular file"
                        ) from exc
                    existing = existing_file.read(len(content) + 1)
            except OSError as read_error:
                raise RuntimeError("existing result artifact cannot be verified") from read_error
            if existing != content:
                raise RuntimeError("result artifact already exists with different content") from exc
        else:
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return StoredResultArtifact(
            storage_uri=f"local-result://{case_id}/{run_id}/{name}",
            sha256=sha256,
            byte_length=len(content),
        )

    def read_bytes(self, storage_uri: str, *, max_bytes: int = 64 * 1024 * 1024) -> bytes:
        path = self.resolve_uri(storage_uri)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            mode = os.fstat(source.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise ValueError("result artifact is not a regular file")
            content = source.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise ValueError("result artifact exceeds read limit")
        return content

    def resolve_uri(self, storage_uri: str) -> Path:
        prefix = "local-result://"
        if not storage_uri.startswith(prefix):
            raise ValueError("unsupported result storage URI")
        parts = storage_uri.removeprefix(prefix).split("/")
        if len(parts) != 3:
            raise ValueError("invalid result storage URI")
        case_id = UUID(parts[0])
        run_id = UUID(parts[1])
        name = parts[2]
        if not SAFE_NAME.fullmatch(name):
            raise ValueError("invalid result artifact name")
        path = self._safe_path(self._directory(case_id, run_id) / name)
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise ValueError("result artifact is not a regular file")
        resolved = path.resolve(strict=True)
        if self.root not in resolved.parents:
            raise ValueError("result artifact escaped configured root")
        return resolved

    def healthcheck(self) -> bool:
        return self.root.is_dir() and not self.root.is_symlink() and os.access(self.root, os.W_OK)

    def _directory(self, case_id: UUID, run_id: UUID) -> Path:
        return self._safe_path(self.root / str(case_id) / str(run_id))

    def _ensure_directory(self, directory: Path) -> None:
        relative = directory.relative_to(self.root)
        current = self.root
        for part in relative.parts:
            current = current / part
            current.mkdir(mode=0o700, exist_ok=True)
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ValueError("result path contains a non-directory component")

    def _safe_path(self, path: Path) -> Path:
        path.relative_to(self.root)
        resolved_parent = path.parent.resolve(strict=False)
        if resolved_parent != self.root and self.root not in resolved_parent.parents:
            raise ValueError("result path escaped configured root")
        return path
