"""MediaInfo JSON adapter."""

from __future__ import annotations

from pathlib import Path

from forensic_structural.adapters.base import AdapterResult, parse_json_result
from forensic_structural.runner import SafeSubprocessRunner


class MediaInfoAdapter:
    test_id = "structural.mediainfo.v1"

    def __init__(self, runner: SafeSubprocessRunner, binary: str) -> None:
        self.runner = runner
        self.binary = binary

    def execute(self, evidence_path: Path) -> AdapterResult:
        result = self.runner.run(
            binary=self.binary,
            arguments=["--Output=JSON"],
            version_arguments=["--Version"],
            evidence_path=evidence_path,
        )
        return parse_json_result(result, evidence_path)
