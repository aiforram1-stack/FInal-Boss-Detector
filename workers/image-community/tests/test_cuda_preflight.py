from __future__ import annotations

from pathlib import Path

import pytest
from forensic_image_community import cuda_preflight
from forensic_image_community.cuda_preflight import (
    CudaDiagnosis,
    CudaPreflightReport,
    LibraryDiagnostics,
    TorchChildCheck,
)
from pydantic import ValidationError


def _runtime(*, available: bool, succeeded: bool = False) -> TorchChildCheck:
    return TorchChildCheck(
        mode="runtime",
        process_return_code=0,
        python_version="3.11.13",
        torch_version="2.7.1+cu126",
        torch_cuda_version="12.6",
        torchvision_version="0.22.1+cu126",
        pytorch_cpu_only=False,
        device_count=1 if available else 0,
        cuda_available=available,
        operation_succeeded=succeeded,
        exception_type=None if succeeded else "RuntimeError",
        exception_message=None if succeeded else "CUDA initialization failed",
    )


def _libraries(*, loadable: bool = True, compat_first: bool | None = False) -> LibraryDiagnostics:
    return LibraryDiagnostics(
        libcuda_loadable=loadable,
        cuda_compat_exists=True,
        compat_libraries_precede_host_driver=compat_first,
    )


def test_diagnosis_prefers_specific_fail_closed_causes() -> None:
    runtime = _runtime(available=False)
    assert (
        cuda_preflight._diagnose(
            runtime=runtime,
            cuda_disabled=True,
            nvidia_disabled=False,
            compute_available=True,
            required_nodes_present=True,
            libraries=_libraries(),
        )
        == CudaDiagnosis.GPU_HIDDEN_BY_ENVIRONMENT
    )
    assert (
        cuda_preflight._diagnose(
            runtime=runtime,
            cuda_disabled=False,
            nvidia_disabled=False,
            compute_available=True,
            required_nodes_present=True,
            libraries=_libraries(compat_first=True),
        )
        == CudaDiagnosis.CUDA_COMPAT_LIBRARY_CONFLICT
    )
    assert (
        cuda_preflight._diagnose(
            runtime=runtime,
            cuda_disabled=False,
            nvidia_disabled=False,
            compute_available=True,
            required_nodes_present=True,
            libraries=_libraries(),
        )
        == CudaDiagnosis.CUDA_RUNTIME_INITIALIZATION_FAILED
    )


def test_environment_values_are_sanitized() -> None:
    assert cuda_preflight._visible_value("CUDA_VISIBLE_DEVICES", "0,1").model_dump() == {
        "state": "ordinal_list",
        "value": "0,1",
    }
    gpu_uuid = cuda_preflight._visible_value("NVIDIA_VISIBLE_DEVICES", "GPU-private-value")
    assert gpu_uuid.value == "1 GPU UUID(s)"
    redacted = cuda_preflight._visible_value("CUDA_VISIBLE_DEVICES", "secret=value")
    assert redacted.value == "<redacted>"
    path = cuda_preflight._path_value("/usr/local/cuda/compat:/private/user/path")
    assert path.value == "/usr/local/cuda/compat:<redacted-path>"


def test_run_preflight_uses_separate_children_and_reports_nvml_disagreement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    modes: list[str] = []

    def fake_child(mode: cuda_preflight.ChildMode, environ: object) -> TorchChildCheck:
        del environ
        modes.append(mode)
        if mode == "runtime":
            return _runtime(available=False)
        if mode == "nvml":
            return TorchChildCheck(
                mode="nvml",
                process_return_code=0,
                torch_version="2.7.1+cu126",
                torch_cuda_version="12.6",
                pytorch_cpu_only=False,
                device_count=1,
                cuda_available=True,
                operation_succeeded=True,
            )
        return TorchChildCheck(
            mode=mode,
            process_return_code=0,
            torch_version="2.7.1+cu126",
            torch_cuda_version="12.6",
            pytorch_cpu_only=False,
            operation_succeeded=False,
            exception_type="RuntimeError",
            exception_message="CUDA initialization failed",
        )

    monkeypatch.setattr(cuda_preflight, "_run_child", fake_child)
    monkeypatch.setattr(cuda_preflight, "_device_nodes", lambda _: ())
    monkeypatch.setattr(cuda_preflight, "_required_nodes_present", lambda _: True)
    monkeypatch.setattr(
        cuda_preflight,
        "_load_libcuda",
        lambda: (True, "libcuda.so.1", "/usr/lib/libcuda.so.1", None),
    )
    monkeypatch.setattr(cuda_preflight, "_ldconfig_entries", lambda: ((), None))
    monkeypatch.setattr(cuda_preflight, "_compat_entries", lambda: (False, ()))
    report = cuda_preflight.run_preflight(
        environ={
            "NVIDIA_DRIVER_CAPABILITIES": "compute,utility",
            "LD_LIBRARY_PATH": "/usr/lib",
        },
        device_root=tmp_path,
    )
    assert modes == ["runtime", "current_device", "device_properties", "nvml"]
    assert report.primary_diagnosis == CudaDiagnosis.CUDA_RUNTIME_INITIALIZATION_FAILED
    assert report.nvml_runtime_disagree is True


def test_cuda_preflight_schema_is_strict_and_versioned() -> None:
    schema = CudaPreflightReport.model_json_schema()
    assert schema["properties"]["schema_version"]["const"] == "1.0"
    assert schema["additionalProperties"] is False
    with pytest.raises(ValidationError):
        CudaPreflightReport.model_validate({"schema_version": "2.0"})
