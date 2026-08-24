from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from forensic_contracts import DetectorResult
from helpers import WORKER_ROOT


def load_container_smoke() -> ModuleType:
    path = WORKER_ROOT / "scripts" / "container_smoke.py"
    spec = importlib.util.spec_from_file_location("container_smoke", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_container_smoke_uses_normal_contract_path_and_cleans(tmp_path: Path) -> None:
    module = load_container_smoke()
    response = module.run_smoke(tmp_path)
    result = DetectorResult.model_validate(response["result"])
    assert result.detector.detector_name.endswith("-mock")
    assert result.calibrated_score is None
    assert result.preprocessing["preprocessing_sha256"]
    assert list(tmp_path.iterdir()) == []
