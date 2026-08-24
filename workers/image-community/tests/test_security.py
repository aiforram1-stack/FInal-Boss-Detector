from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.input_fetcher import HttpsInputFetcher
from forensic_image_community.manifest import load_model_manifest
from helpers import WORKER_ROOT, settings
from pydantic import ValidationError

from scripts.validate_image_worker_docker import main as validate_docker_assets


def python_sources() -> list[Path]:
    return sorted((WORKER_ROOT / "src").rglob("*.py")) + sorted(
        (WORKER_ROOT / "scripts").rglob("*.py")
    )


def test_worker_has_no_shell_true_os_system_eval_or_exec() -> None:
    prohibited_attribute_calls = {"system", "popen"}
    prohibited_builtin_calls = {"eval", "exec"}
    for path in python_sources():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert ("shell" + "=True") not in source.replace(" ", "")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                assert node.func.id not in prohibited_builtin_calls
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in prohibited_attribute_calls


def test_external_worker_errors_never_expose_internal_detail_url_token_or_path() -> None:
    error = WorkerError(
        code=WorkerErrorCode.INPUT_FETCH_FAILED,
        message="Input could not be retrieved.",
        internal_detail=(
            "/private/cache/model.safetensors "
            "https://objects.example/input?X-Amz-Signature=secret token=secret"
        ),
    )
    serialized = json.dumps(error.external_dict())
    assert "/private/cache" not in serialized
    assert "X-Amz" not in serialized
    assert "secret" not in serialized


@pytest.mark.parametrize(
    "host",
    ["../objects.example", "objects.example/path", "objects.example:443", "user@objects.example"],
)
def test_allowed_host_configuration_rejects_path_and_authority_injection(host: str) -> None:
    with pytest.raises(ValidationError):
        ImageCommunitySettings(allowed_input_hosts={host})


def test_input_fetcher_source_revalidates_redirects_and_forbids_non_global_addresses() -> None:
    source = Path(HttpsInputFetcher.__module__.replace(".", "/"))
    assert source.name == "input_fetcher"
    text = (WORKER_ROOT / "src/forensic_image_community/input_fetcher.py").read_text(
        encoding="utf-8"
    )
    assert "self._validate_destination(current)" in text
    assert "not address.is_global" in text
    assert "follow_redirects=False" in text
    assert '"Accept-Encoding": "identity"' in text


def test_manifest_and_docker_references_are_immutable() -> None:
    loaded = load_model_manifest(WORKER_ROOT / "model-manifest.yaml")
    immutable_values = {
        loaded.source.repository_commit,
        loaded.model.revision,
        loaded.preprocessing.revision,
        loaded.runtime.base_image_digest,
    }
    assert not immutable_values.intersection({"main", "master", "latest"})
    validate_docker_assets()


def test_checkpoint_acquisition_is_double_opt_in_and_dry_run_is_download_free() -> None:
    source = (WORKER_ROOT / "scripts/fetch_checkpoint.py").read_text(encoding="utf-8")
    assert "settings.allow_model_download" in source
    assert 'os.environ.get("ALLOW_MODEL_DOWNLOAD") != "1"' in source
    dry_run_block = source.index("if args.dry_run")
    import_block = source.index("from huggingface_hub import hf_hub_download")
    assert dry_run_block < import_block


def test_temp_and_model_paths_are_outside_tracked_worker_paths(tmp_path: Path) -> None:
    configured = settings(tmp_path)
    assert WORKER_ROOT not in configured.ensure_temp_root().parents
    assert str(configured.model_cache).startswith("/models/")
