from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from uuid import uuid4

import pytest
from forensic_contracts import StructuralReport
from forensic_structural.artifacts import LocalResultStorage
from forensic_structural.reporting import canonical_json_bytes, render_structural_html

from .helpers import PNG, sample_report

TEMPLATE_DIR = Path(__file__).parents[1] / "src" / "forensic_structural" / "templates"


def test_result_storage_is_create_only_hashes_and_uses_logical_uris(tmp_path: Path) -> None:
    storage = LocalResultStorage(tmp_path / "results")
    case_id = uuid4()
    run_id = uuid4()
    stored = storage.put_bytes(case_id, run_id, "report.json", b"{}\n")
    assert stored.storage_uri == f"local-result://{case_id}/{run_id}/report.json"
    assert stored.sha256 == hashlib.sha256(b"{}\n").hexdigest()
    assert str(tmp_path) not in stored.storage_uri
    assert storage.read_bytes(stored.storage_uri) == b"{}\n"
    path = storage.resolve_uri(stored.storage_uri)
    assert path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0

    repeated = storage.put_bytes(case_id, run_id, "report.json", b"{}\n")
    assert repeated == stored
    with pytest.raises(RuntimeError, match="different content"):
        storage.put_bytes(case_id, run_id, "report.json", b'{"different":true}\n')
    with pytest.raises(ValueError, match="name"):
        storage.put_bytes(case_id, run_id, "../escape.json", b"unsafe")


def test_canonical_json_is_stable_valid_and_hash_reproducible() -> None:
    report = sample_report()
    first = canonical_json_bytes(report)
    second = canonical_json_bytes(report)
    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()
    restored = StructuralReport.model_validate_json(first)
    assert restored.report_id == report.report_id
    assert first.endswith(b"\n")


def test_html_is_rendered_from_json_escaped_self_contained_and_path_safe() -> None:
    attack = '<script>alert("x")</script> /Users/private/evidence.png'
    report = sample_report(filename="<img src=x onerror=alert(1)>.png", metadata_value=attack)
    report_json = canonical_json_bytes(report)
    html = render_structural_html(report_json, TEMPLATE_DIR).decode("utf-8")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html
    assert "/Users/private" not in report_json.decode()
    assert "/Users/private" not in html
    assert "&lt;redacted-path&gt;" in html
    assert "http://" not in html and "https://" not in html
    assert "<script src=" not in html
    assert "<th scope=" in html


def test_reports_redact_secret_patterns_and_exclude_raw_evidence() -> None:
    synthetic_token = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
    report_json = canonical_json_bytes(sample_report(metadata_value=synthetic_token))
    html = render_structural_html(report_json, TEMPLATE_DIR)
    assert synthetic_token.encode() not in report_json
    assert synthetic_token.encode() not in html
    assert b"<redacted-secret>" in report_json
    assert PNG not in report_json
    assert PNG not in html
    combined = (report_json + html).upper()
    assert b'"VERDICT"' not in combined
    assert b'"CONFIDENCE"' not in combined
    assert b'"PROBABILITY"' not in combined
