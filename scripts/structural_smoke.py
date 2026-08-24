"""Temporary CPU-only end-to-end structural analysis smoke test."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient
from forensic_api.config import Settings
from forensic_api.main import create_app
from forensic_contracts import StructuralAnalysisRun, StructuralReport

GENERATED_PNG = b"\x89PNG\r\n\x1a\n" + b"phase-three-smoke" * 16
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class SmokeResult:
    run_status: str
    json_sha256: str
    html_sha256: str
    test_count: int


def run_smoke() -> SmokeResult:
    with TemporaryDirectory(prefix="forensic-structural-smoke-") as temporary:
        root = Path(temporary)
        settings = Settings(
            database_url=f"sqlite:///{root / 'smoke.db'}",
            evidence_storage_root=root / "evidence",
            structural_result_root=root / "results",
            max_upload_bytes=4096,
            upload_chunk_bytes=31,
            allowed_media_types="image/png",
            exiftool_binary="phase3-smoke-missing-exiftool",
            ffprobe_binary="phase3-smoke-missing-ffprobe",
            mediainfo_binary="phase3-smoke-missing-mediainfo",
            report_template_dir=(
                ROOT / "packages" / "structural" / "src" / "forensic_structural" / "templates"
            ),
            log_level="CRITICAL",
        )
        app = create_app(settings, initialize_schema=True)
        with TestClient(app, raise_server_exceptions=False) as client:
            case_response = client.post(
                "/v1/cases", json={"claim": "Generated smoke", "privacy_mode": "RESTRICTED"}
            )
            if case_response.status_code != 201:
                raise RuntimeError("case creation smoke failed")
            case_id = case_response.json()["case_id"]
            upload = client.post(
                f"/v1/cases/{case_id}/evidence",
                files={"file": ("generated.png", GENERATED_PNG, "image/png")},
            )
            if upload.status_code != 201:
                raise RuntimeError("evidence upload smoke failed")
            evidence_id = upload.json()["evidence_id"]
            analysis = client.post(
                f"/v1/cases/{case_id}/evidence/{evidence_id}/structural-analysis"
            )
            if analysis.status_code != 201:
                raise RuntimeError("structural analysis smoke failed")
            run = StructuralAnalysisRun.model_validate(analysis.json())
            report_response = client.get(f"/v1/cases/{case_id}/reports/structural.json")
            html_response = client.get(f"/v1/cases/{case_id}/reports/structural.html")
            if report_response.status_code != 200 or html_response.status_code != 200:
                raise RuntimeError("report retrieval smoke failed")
            StructuralReport.model_validate_json(report_response.content)
            if run.report_manifest is None:
                raise RuntimeError("smoke analysis did not create a report manifest")
            expected = {item.format: item.sha256 for item in run.report_manifest.artifacts}
            json_hash = hashlib.sha256(report_response.content).hexdigest()
            html_hash = hashlib.sha256(html_response.content).hexdigest()
            if expected != {"json": json_hash, "html": html_hash}:
                raise RuntimeError("report artifact hashes did not verify")
            return SmokeResult(
                run_status=run.status.value,
                json_sha256=json_hash,
                html_sha256=html_hash,
                test_count=len(run.test_results),
            )


def main() -> None:
    result = run_smoke()
    print(
        "structural smoke passed "
        f"status={result.run_status} tests={result.test_count} "
        f"json_sha256={result.json_sha256} html_sha256={result.html_sha256}"
    )


if __name__ == "__main__":
    main()
