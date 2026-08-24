"""ffprobe JSON adapter."""

from __future__ import annotations

from pathlib import Path

from forensic_structural.adapters.base import AdapterResult, parse_json_result
from forensic_structural.runner import SafeSubprocessRunner


class FfprobeAdapter:
    test_id = "structural.ffprobe-container.v1"

    def __init__(self, runner: SafeSubprocessRunner, binary: str) -> None:
        self.runner = runner
        self.binary = binary

    def execute(self, evidence_path: Path) -> AdapterResult:
        result = self.runner.run(
            binary=self.binary,
            arguments=[
                "-v",
                "error",
                "-show_format",
                "-show_streams",
                "-of",
                "json",
            ],
            version_arguments=["-version"],
            evidence_path=evidence_path,
        )
        return parse_json_result(result, evidence_path)
