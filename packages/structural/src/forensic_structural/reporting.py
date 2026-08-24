"""Canonical JSON and escaped self-contained HTML report rendering."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from forensic_contracts import StructuralReport
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
ABSOLUTE_PATH_FRAGMENT = re.compile(r"(?:(?<=\s)|^)/(?:Users|home|tmp|var|private)/[^\s,;]+")


def sanitize_report_text(value: str) -> str:
    sanitized = value
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub("<redacted-secret>", sanitized)
    return ABSOLUTE_PATH_FRAGMENT.sub("<redacted-path>", sanitized)


def _sanitize_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_payload(item) for item in value]
    if isinstance(value, str):
        return sanitize_report_text(value)
    return value


def canonical_json_bytes(value: StructuralReport | dict[str, Any]) -> bytes:
    raw_payload = value.model_dump(mode="json") if isinstance(value, StructuralReport) else value
    payload = _sanitize_payload(raw_payload)
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def render_structural_html(report_json: bytes, template_directory: Path) -> bytes:
    """Render only from validated stored JSON, never from database objects."""

    report = StructuralReport.model_validate_json(report_json)
    environment = Environment(
        loader=FileSystemLoader(str(template_directory)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.get_template("structural_report.html.j2")
    rendered = template.render(report=report.model_dump(mode="json"))
    return rendered.encode("utf-8")
