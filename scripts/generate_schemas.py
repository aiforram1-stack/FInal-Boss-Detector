"""Generate deterministic JSON Schema documents from Phase 1 contracts."""

from __future__ import annotations

import json
from pathlib import Path

from forensic_contracts import (
    Case,
    ContainerReleaseManifest,
    DetectorIdentity,
    DetectorJob,
    DetectorResult,
    DetectorRun,
    EvidenceAsset,
    EvidenceDerivative,
    ForensicTestResult,
    ReportManifest,
    StructuralAnalysisRun,
    StructuralReport,
)
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
MODELS: tuple[type[BaseModel], ...] = (
    Case,
    EvidenceAsset,
    EvidenceDerivative,
    DetectorJob,
    DetectorIdentity,
    DetectorRun,
    DetectorResult,
    ForensicTestResult,
    ReportManifest,
    StructuralAnalysisRun,
    StructuralReport,
)


def generate_schema_documents() -> dict[str, str]:
    documents = {
        f"{model.__name__}.schema.json": (
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        )
        for model in MODELS
    }
    documents["container-release.schema.json"] = (
        json.dumps(ContainerReleaseManifest.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
    return documents


def main() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    for filename, body in generate_schema_documents().items():
        (SCHEMA_DIR / filename).write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
