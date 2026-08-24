"""Detector backend interface shared by mock and real implementations."""

from __future__ import annotations

from typing import Protocol

from forensic_contracts import DetectorIdentity

from forensic_image_community.contracts import BackendOutput, PreprocessedImage


class DetectorBackend(Protocol):
    @property
    def mock_backend(self) -> bool: ...

    def identity(self) -> DetectorIdentity: ...

    def infer(self, preprocessed: PreprocessedImage) -> BackendOutput: ...
