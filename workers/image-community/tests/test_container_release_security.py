from __future__ import annotations

import io
import json
import tarfile
from datetime import date
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from scripts.evaluate_vulnerabilities import evaluate, load_exceptions
from scripts.inspect_image_contents import path_violation, scan_export
from scripts.validate_workflow_policy import main as validate_workflow_policy


def trivy_report(*findings: tuple[str, str]) -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "generated",
                "Vulnerabilities": [
                    {"VulnerabilityID": identifier, "Severity": severity}
                    for identifier, severity in findings
                ],
            }
        ],
    }


def write_exceptions(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(
        yaml.safe_dump({"schema_version": "1.0", "exceptions": entries}),
        encoding="utf-8",
    )


def test_unexcepted_critical_fails_and_high_is_summarized(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text(json.dumps(trivy_report(("CVE-CRITICAL", "CRITICAL"), ("CVE-HIGH", "HIGH"))))
    exceptions = tmp_path / "exceptions.yaml"
    write_exceptions(exceptions, [])
    summary_path = tmp_path / "summary.json"
    summary = evaluate([report], exceptions, summary_path, date(2026, 8, 24))
    assert summary["status"] == "failed"
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["unexcepted_critical_ids"] == ["CVE-CRITICAL"]


def test_reviewed_unexpired_exception_is_narrow_and_expiry_is_required(tmp_path: Path) -> None:
    exceptions = tmp_path / "exceptions.yaml"
    entry = {
        "finding_id": "CVE-CONTROLLED",
        "justification": "No affected execution path is present.",
        "owner": "security-team",
        "expires_on": "2026-09-30",
        "compensating_control": "The affected package is not invoked.",
    }
    write_exceptions(exceptions, [entry])
    assert set(load_exceptions(exceptions, date(2026, 8, 24))) == {"CVE-CONTROLLED"}

    del entry["expires_on"]
    write_exceptions(exceptions, [entry])
    with pytest.raises(ValidationError):
        load_exceptions(exceptions, date(2026, 8, 24))


def test_expired_or_duplicate_exceptions_fail_closed(tmp_path: Path) -> None:
    exceptions = tmp_path / "exceptions.yaml"
    entry = {
        "finding_id": "CVE-CONTROLLED",
        "justification": "A temporary reviewed exception exists.",
        "owner": "security-team",
        "expires_on": "2026-08-24",
        "compensating_control": "The affected package is not invoked.",
    }
    write_exceptions(exceptions, [entry])
    with pytest.raises(ValueError, match="expired"):
        load_exceptions(exceptions, date(2026, 8, 24))
    entry["expires_on"] = "2026-09-30"
    write_exceptions(exceptions, [entry, entry])
    with pytest.raises(ValueError, match="duplicate"):
        load_exceptions(exceptions, date(2026, 8, 24))


@pytest.mark.parametrize(
    "name",
    [
        "app/.git/config",
        "app/.env",
        "models/community-forensics/model.safetensors",
        "app/evidence/private.png",
        "app/checkpoints/model.ckpt",
    ],
)
def test_prohibited_image_paths_are_detected(name: str) -> None:
    from pathlib import PurePosixPath

    assert path_violation(PurePosixPath(name), True) is not None


def test_streaming_image_export_inspection_detects_secret_content() -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        payload = b"rpa_" + (b"A" * 40)
        info = tarfile.TarInfo("app/config.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    archive_bytes.seek(0)
    files, violations = scan_export(archive_bytes)
    assert files == 1
    assert any("RunPod token" in violation for violation in violations)


def test_all_workflows_satisfy_phase_5_trigger_permission_and_pin_policy() -> None:
    validate_workflow_policy()
