"""Shared adapter result shape and bounded JSON parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from forensic_contracts import ForensicTestStatus
from pydantic import JsonValue

from forensic_structural.reporting import canonical_json_bytes, sanitize_report_text
from forensic_structural.runner import CommandOutcome, CommandResult

PATH_KEYS = {
    "completename",
    "complete_name",
    "directory",
    "file_name",
    "filename",
    "foldername",
    "folder_name",
    "sourcefile",
    "source_file",
}


@dataclass(frozen=True, slots=True)
class AdapterResult:
    status: ForensicTestStatus
    structured_output: dict[str, JsonValue] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    status_reason: str | None = None
    runtime_ms: int | None = None
    tool_version: str | None = None
    raw_artifact: bytes | None = None
    error_code: str | None = None


def parse_json_result(result: CommandResult, evidence_path: Path) -> AdapterResult:
    if result.outcome == CommandOutcome.EXECUTABLE_MISSING:
        return AdapterResult(
            status=ForensicTestStatus.PROVIDER_UNAVAILABLE,
            status_reason="The configured metadata tool is unavailable.",
            runtime_ms=result.runtime_ms,
            error_code=result.outcome.value,
        )
    if result.outcome != CommandOutcome.SUCCEEDED:
        reason = {
            CommandOutcome.TIMED_OUT: "The metadata tool exceeded its configured timeout.",
            CommandOutcome.OUTPUT_LIMIT_EXCEEDED: (
                "The metadata tool exceeded its configured output limit."
            ),
            CommandOutcome.NONZERO_EXIT: "The metadata tool could not parse this input.",
            CommandOutcome.START_FAILED: "The configured metadata tool could not be started.",
        }.get(result.outcome, "The metadata tool failed.")
        warnings = [result.stderr[:500]] if result.stderr else []
        return AdapterResult(
            status=ForensicTestStatus.FAILED,
            status_reason=reason,
            warnings=warnings,
            runtime_ms=result.runtime_ms,
            tool_version=result.tool_version,
            error_code=result.outcome.value,
        )
    try:
        parsed = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeError):
        return AdapterResult(
            status=ForensicTestStatus.FAILED,
            status_reason="The metadata tool returned invalid JSON.",
            runtime_ms=result.runtime_ms,
            tool_version=result.tool_version,
            error_code="INVALID_JSON",
        )
    sanitized = sanitize_json(parsed, evidence_path)
    if not isinstance(sanitized, dict):
        sanitized = {"value": sanitized}
    output = {str(key): value for key, value in sanitized.items()}
    return AdapterResult(
        status=ForensicTestStatus.EXECUTED,
        structured_output=output,
        runtime_ms=result.runtime_ms,
        tool_version=result.tool_version,
        raw_artifact=canonical_json_bytes(output),
    )


def sanitize_json(value: object, evidence_path: Path) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_report_text(value.replace(str(evidence_path), "<evidence-object>"))
    if isinstance(value, list):
        return [sanitize_json(item, evidence_path) for item in value]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            normalized = str(key)
            if normalized.lower().replace(" ", "_") in PATH_KEYS:
                continue
            result[normalized] = sanitize_json(item, evidence_path)
        return result
    return sanitize_report_text(str(value).replace(str(evidence_path), "<evidence-object>"))
