"""Small monotonic stage timer with no input or secret data."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager


class StageTelemetry:
    def __init__(self) -> None:
        self.started = time.perf_counter()
        self.durations_ms: dict[str, int] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.durations_ms[name] = max(0, round((time.perf_counter() - started) * 1000))

    def total_ms(self) -> int:
        return max(0, round((time.perf_counter() - self.started) * 1000))
