"""Stable, path-safe API errors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ApiError(Exception):
    status_code: int
    code: str
    public_message: str

    def __str__(self) -> str:
        return self.code
