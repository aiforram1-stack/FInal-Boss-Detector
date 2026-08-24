"""ExifTool JSON adapter."""

from __future__ import annotations

from pathlib import Path

from forensic_structural.adapters.base import AdapterResult, parse_json_result
from forensic_structural.runner import SafeSubprocessRunner


class ExifToolAdapter:
    test_id = "structural.exiftool-metadata.v1"

    def __init__(self, runner: SafeSubprocessRunner, binary: str) -> None:
        self.runner = runner
        self.binary = binary

    def execute(self, evidence_path: Path) -> AdapterResult:
        result = self.runner.run(
            binary=self.binary,
            arguments=["-json", "-G1", "-n"],
            version_arguments=["-ver"],
            evidence_path=evidence_path,
        )
        parsed = parse_json_result(result, evidence_path)
        output = parsed.structured_output
        if parsed.status.value == "EXECUTED":
            rows = output.get("value")
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                output = {str(key): value for key, value in rows[0].items()}
            elif isinstance(output, dict) and len(output) == 1:
                only = next(iter(output.values()))
                if isinstance(only, list) and only and isinstance(only[0], dict):
                    output = {str(key): value for key, value in only[0].items()}
        return AdapterResult(
            status=parsed.status,
            structured_output=output,
            warnings=parsed.warnings,
            status_reason=parsed.status_reason,
            runtime_ms=parsed.runtime_ms,
            tool_version=parsed.tool_version,
            raw_artifact=parsed.raw_artifact,
            error_code=parsed.error_code,
        )
