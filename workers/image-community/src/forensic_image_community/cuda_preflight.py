"""Model-free, fail-closed CUDA diagnostics for controlled GPU validation.

The parent process never imports PyTorch. CUDA initialization variants run in
separate bounded child processes so one failed initialization cannot poison the
remaining observations.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_TEXT_LENGTH = 16_000
MAX_LDCONFIG_LINES = 32
CHILD_TIMEOUT_SECONDS = 30
SAFE_LIBRARY_ROOTS = ("/lib", "/usr/lib", "/usr/local", "/opt/conda/lib")
DISABLED_VISIBLE_VALUES = {"", "-1", "none", "void"}
ChildMode = Literal["runtime", "current_device", "device_properties", "nvml"]
CHILD_MODES: tuple[ChildMode, ...] = (
    "runtime",
    "current_device",
    "device_properties",
    "nvml",
)
SECRET_RE = re.compile(
    r"(?i)(authorization|bearer|api[_-]?key|password|secret|token)"
    r"([=: ]+)([^\s,;]+)"
)
SIGNED_QUERY_RE = re.compile(r"(https?://[^?\s]+)\?[^\s]+")


class CudaDiagnosis(StrEnum):
    CUDA_AVAILABLE = "CUDA_AVAILABLE"
    GPU_HIDDEN_BY_ENVIRONMENT = "GPU_HIDDEN_BY_ENVIRONMENT"
    COMPUTE_CAPABILITY_NOT_MOUNTED = "COMPUTE_CAPABILITY_NOT_MOUNTED"
    CUDA_DEVICE_NODES_MISSING = "CUDA_DEVICE_NODES_MISSING"
    LIBCUDA_NOT_LOADABLE = "LIBCUDA_NOT_LOADABLE"
    CUDA_COMPAT_LIBRARY_CONFLICT = "CUDA_COMPAT_LIBRARY_CONFLICT"
    PYTORCH_CPU_BUILD = "PYTORCH_CPU_BUILD"
    CUDA_RUNTIME_INITIALIZATION_FAILED = "CUDA_RUNTIME_INITIALIZATION_FAILED"
    UNKNOWN = "UNKNOWN"


class PreflightRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )


class SanitizedEnvironmentValue(PreflightRecord):
    state: Literal[
        "unset",
        "empty",
        "disabled",
        "all",
        "ordinal_list",
        "gpu_uuid_list",
        "mig_uuid_list",
        "capability_list",
        "path_list",
        "other_redacted",
    ]
    value: str | None = None


class DeviceNodeRecord(PreflightRecord):
    path: str
    present: bool
    character_device: bool
    mode: str | None = Field(default=None, pattern=r"^[0-7]{4}$")
    readable: bool
    writable: bool


class LibraryDiagnostics(PreflightRecord):
    libcuda_loadable: bool
    libcuda_error: str | None = None
    find_library_result: str | None = None
    resolved_libcuda_location: str | None = None
    ldconfig_entries: tuple[str, ...] = ()
    ldconfig_error: str | None = None
    cuda_compat_exists: bool
    cuda_compat_entries: tuple[str, ...] = ()
    compat_libraries_precede_host_driver: bool | None = None


class TorchChildCheck(PreflightRecord):
    mode: ChildMode
    process_return_code: int | None = None
    timed_out: bool = False
    python_version: str | None = None
    torch_version: str | None = None
    torch_cuda_version: str | None = None
    torchvision_version: str | None = None
    pytorch_cpu_only: bool | None = None
    device_count: int | None = Field(default=None, ge=0)
    cuda_available: bool | None = None
    operation_succeeded: bool = False
    exception_type: str | None = None
    exception_message: str | None = None
    traceback: str | None = None
    stderr: str | None = None


class CudaPreflightReport(PreflightRecord):
    schema_version: Literal["1.0"]
    created_at: datetime
    status: Literal["PASSED", "FAILED"]
    primary_diagnosis: CudaDiagnosis
    python_version: str
    environment: dict[str, SanitizedEnvironmentValue]
    cuda_home: str | None = None
    device_nodes: tuple[DeviceNodeRecord, ...]
    required_device_nodes_present: bool
    driver_capabilities_include_compute: bool | None = None
    cuda_visible_devices_disables_access: bool
    nvidia_visible_devices_disables_access: bool
    libraries: LibraryDiagnostics
    child_checks: tuple[TorchChildCheck, ...]
    nvml_runtime_disagree: bool | None = None
    warnings: tuple[str, ...] = ()


CHILD_SCRIPT = r"""
import json
import platform
import sys
import traceback

mode = sys.argv[1]
result = {
    "mode": mode,
    "python_version": platform.python_version(),
    "torch_version": None,
    "torch_cuda_version": None,
    "torchvision_version": None,
    "pytorch_cpu_only": None,
    "device_count": None,
    "cuda_available": None,
    "operation_succeeded": False,
    "exception_type": None,
    "exception_message": None,
    "traceback": None,
}
try:
    import torch
    import torchvision
    result["torch_version"] = str(torch.__version__)
    result["torch_cuda_version"] = (
        None if torch.version.cuda is None else str(torch.version.cuda)
    )
    result["torchvision_version"] = str(torchvision.__version__)
    result["pytorch_cpu_only"] = torch.version.cuda is None
    if mode in {"runtime", "nvml"}:
        result["device_count"] = int(torch.cuda.device_count())
        result["cuda_available"] = bool(torch.cuda.is_available())
    if mode == "runtime":
        torch.cuda.init()
    elif mode == "current_device":
        torch.cuda.current_device()
    elif mode == "device_properties":
        properties = torch.cuda.get_device_properties(0)
        result["device_count"] = int(torch.cuda.device_count())
        result["cuda_available"] = bool(torch.cuda.is_available())
        result["device_name"] = str(properties.name)
        result["total_memory"] = int(properties.total_memory)
    elif mode != "nvml":
        raise ValueError("unsupported child check mode")
    result["operation_succeeded"] = True
except BaseException as exc:
    result["exception_type"] = type(exc).__name__
    result["exception_message"] = str(exc)
    result["traceback"] = traceback.format_exc()
print(json.dumps(result, sort_keys=True, allow_nan=False))
"""


def _sanitize_text(value: str | None) -> str | None:
    if value is None:
        return None
    sanitized = value.replace("\x00", "<NUL>")
    sanitized = SIGNED_QUERY_RE.sub(r"\1?<redacted>", sanitized)
    sanitized = SECRET_RE.sub(r"\1\2<redacted>", sanitized)
    if len(sanitized) > MAX_TEXT_LENGTH:
        sanitized = sanitized[:MAX_TEXT_LENGTH] + "<truncated>"
    return sanitized


def _sanitize_path(value: str | None) -> str | None:
    if value is None:
        return None
    path = os.path.normpath(value)
    if not path.startswith(SAFE_LIBRARY_ROOTS):
        return "<redacted-path>"
    return _sanitize_text(path)


def _visible_value(name: str, raw: str | None) -> SanitizedEnvironmentValue:
    if raw is None:
        return SanitizedEnvironmentValue(state="unset")
    stripped = raw.strip()
    lowered = stripped.lower()
    if stripped == "":
        return SanitizedEnvironmentValue(state="empty", value="")
    if lowered in DISABLED_VISIBLE_VALUES:
        return SanitizedEnvironmentValue(state="disabled", value=lowered)
    if lowered == "all":
        return SanitizedEnvironmentValue(state="all", value="all")
    values = tuple(part.strip() for part in stripped.split(","))
    if name == "NVIDIA_DRIVER_CAPABILITIES":
        safe = tuple(sorted({part.lower() for part in values if re.fullmatch(r"[a-z]+", part)}))
        if len(safe) == len(values):
            return SanitizedEnvironmentValue(state="capability_list", value=",".join(safe))
    if all(re.fullmatch(r"\d+", part) for part in values):
        return SanitizedEnvironmentValue(state="ordinal_list", value=",".join(values))
    if all(re.fullmatch(r"GPU-[A-Za-z0-9-]+", part) for part in values):
        return SanitizedEnvironmentValue(state="gpu_uuid_list", value=f"{len(values)} GPU UUID(s)")
    if all(re.fullmatch(r"MIG-[A-Za-z0-9-]+", part) for part in values):
        return SanitizedEnvironmentValue(state="mig_uuid_list", value=f"{len(values)} MIG UUID(s)")
    return SanitizedEnvironmentValue(state="other_redacted", value="<redacted>")


def _path_value(raw: str | None) -> SanitizedEnvironmentValue:
    if raw is None:
        return SanitizedEnvironmentValue(state="unset")
    if raw.strip() == "":
        return SanitizedEnvironmentValue(state="empty", value="")
    entries = tuple(_sanitize_path(entry) or "<redacted-path>" for entry in raw.split(":"))
    return SanitizedEnvironmentValue(state="path_list", value=":".join(entries))


def _device_nodes(device_root: Path) -> tuple[DeviceNodeRecord, ...]:
    paths = set(device_root.glob("nvidia*"))
    caps = device_root / "nvidia-caps"
    if caps.is_dir():
        paths.update(caps.glob("*"))
    records: list[DeviceNodeRecord] = []
    for path in sorted(paths)[:64]:
        try:
            metadata = path.stat()
        except OSError:
            records.append(
                DeviceNodeRecord(
                    path=str(path),
                    present=False,
                    character_device=False,
                    readable=False,
                    writable=False,
                )
            )
            continue
        records.append(
            DeviceNodeRecord(
                path=str(path),
                present=True,
                character_device=stat.S_ISCHR(metadata.st_mode),
                mode=f"{stat.S_IMODE(metadata.st_mode):04o}",
                readable=os.access(path, os.R_OK),
                writable=os.access(path, os.W_OK),
            )
        )
    return tuple(records)


def _required_nodes_present(nodes: Sequence[DeviceNodeRecord]) -> bool:
    paths = {node.path for node in nodes if node.present and node.character_device}
    has_control = any(path.endswith("/nvidiactl") for path in paths)
    has_gpu = any(re.search(r"/nvidia\d+$", path) for path in paths)
    return has_control and has_gpu


def _load_libcuda() -> tuple[bool, str | None, str | None, str | None]:
    found = _sanitize_text(ctypes.util.find_library("cuda"))
    try:
        ctypes.CDLL("libcuda.so.1")
    except OSError as exc:
        return False, found, None, _sanitize_text(f"{type(exc).__name__}: {exc}")
    resolved: str | None = None
    maps = Path("/proc/self/maps")
    if maps.is_file():
        try:
            for line in maps.read_text(encoding="utf-8", errors="replace").splitlines():
                if "libcuda.so" in line:
                    candidate = line.rsplit(maxsplit=1)[-1]
                    resolved = _sanitize_path(candidate)
                    break
        except OSError:
            resolved = None
    return True, found, resolved, None


def _ldconfig_entries() -> tuple[tuple[str, ...], str | None]:
    try:
        completed = subprocess.run(
            ["/sbin/ldconfig", "-p"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (), _sanitize_text(f"{type(exc).__name__}: {exc}")
    lines = []
    for line in completed.stdout.splitlines():
        if "libcuda.so" not in line and "libnvidia-ml.so" not in line:
            continue
        left, separator, right = line.partition(" => ")
        safe_right = _sanitize_path(right.strip()) if separator else None
        lines.append(f"{left.strip()} => {safe_right or '<unresolved>'}")
        if len(lines) >= MAX_LDCONFIG_LINES:
            break
    error = None if completed.returncode == 0 else _sanitize_text(completed.stderr)
    return tuple(lines), error


def _compat_entries() -> tuple[bool, tuple[str, ...]]:
    compat = Path("/usr/local/cuda/compat")
    if not compat.is_dir():
        return False, ()
    entries = tuple(str(path) for path in sorted(compat.glob("libcuda.so*"))[:16])
    return True, entries


def _compat_precedes_host(ld_library_path: str | None, resolved: str | None) -> bool | None:
    if resolved and "/cuda/compat/" in resolved:
        return True
    if not ld_library_path:
        return None
    paths = ld_library_path.split(":")
    compat_indices = [index for index, path in enumerate(paths) if "/cuda/compat" in path]
    host_indices = [
        index
        for index, path in enumerate(paths)
        if "/nvidia/" in path or path.startswith(("/usr/lib", "/lib"))
    ]
    if not compat_indices:
        return False
    if not host_indices:
        return True
    return min(compat_indices) < min(host_indices)


def _run_child(
    mode: ChildMode,
    environ: Mapping[str, str],
) -> TorchChildCheck:
    child_env = dict(environ)
    if mode == "nvml":
        child_env["PYTORCH_NVML_BASED_CUDA_CHECK"] = "1"
    else:
        child_env.pop("PYTORCH_NVML_BASED_CUDA_CHECK", None)
    try:
        completed = subprocess.run(  # noqa: S603 - interpreter and child source are trusted
            [sys.executable, "-c", CHILD_SCRIPT, mode],
            check=False,
            capture_output=True,
            text=True,
            timeout=CHILD_TIMEOUT_SECONDS,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        return TorchChildCheck(
            mode=mode,
            timed_out=True,
            exception_type=type(exc).__name__,
            exception_message=f"child check exceeded {CHILD_TIMEOUT_SECONDS} seconds",
            stderr=_sanitize_text(exc.stderr if isinstance(exc.stderr, str) else None),
        )
    except OSError as exc:
        return TorchChildCheck(
            mode=mode,
            exception_type=type(exc).__name__,
            exception_message=_sanitize_text(str(exc)),
        )
    try:
        payload = json.loads(completed.stdout)
        if not isinstance(payload, dict):
            raise ValueError("child output is not an object")
        return TorchChildCheck(
            mode=mode,
            process_return_code=completed.returncode,
            python_version=_string_or_none(payload.get("python_version")),
            torch_version=_string_or_none(payload.get("torch_version")),
            torch_cuda_version=_string_or_none(payload.get("torch_cuda_version")),
            torchvision_version=_string_or_none(payload.get("torchvision_version")),
            pytorch_cpu_only=_bool_or_none(payload.get("pytorch_cpu_only")),
            device_count=_int_or_none(payload.get("device_count")),
            cuda_available=_bool_or_none(payload.get("cuda_available")),
            operation_succeeded=payload.get("operation_succeeded") is True,
            exception_type=_sanitize_text(_string_or_none(payload.get("exception_type"))),
            exception_message=_sanitize_text(_string_or_none(payload.get("exception_message"))),
            traceback=_sanitize_text(_string_or_none(payload.get("traceback"))),
            stderr=_sanitize_text(completed.stderr) or None,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return TorchChildCheck(
            mode=mode,
            process_return_code=completed.returncode,
            exception_type=type(exc).__name__,
            exception_message="child check returned invalid JSON",
            stderr=_sanitize_text(completed.stderr) or None,
        )


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _diagnose(
    *,
    runtime: TorchChildCheck,
    cuda_disabled: bool,
    nvidia_disabled: bool,
    compute_available: bool | None,
    required_nodes_present: bool,
    libraries: LibraryDiagnostics,
) -> CudaDiagnosis:
    if runtime.pytorch_cpu_only is True:
        return CudaDiagnosis.PYTORCH_CPU_BUILD
    if cuda_disabled or nvidia_disabled:
        return CudaDiagnosis.GPU_HIDDEN_BY_ENVIRONMENT
    if compute_available is False:
        return CudaDiagnosis.COMPUTE_CAPABILITY_NOT_MOUNTED
    if not required_nodes_present:
        return CudaDiagnosis.CUDA_DEVICE_NODES_MISSING
    if not libraries.libcuda_loadable:
        return CudaDiagnosis.LIBCUDA_NOT_LOADABLE
    if runtime.operation_succeeded and runtime.cuda_available and (runtime.device_count or 0) > 0:
        return CudaDiagnosis.CUDA_AVAILABLE
    if libraries.compat_libraries_precede_host_driver is True:
        return CudaDiagnosis.CUDA_COMPAT_LIBRARY_CONFLICT
    if runtime.torch_version is not None:
        return CudaDiagnosis.CUDA_RUNTIME_INITIALIZATION_FAILED
    return CudaDiagnosis.UNKNOWN


def run_preflight(
    *,
    environ: Mapping[str, str] | None = None,
    device_root: Path = Path("/dev"),
) -> CudaPreflightReport:
    source_env = os.environ if environ is None else environ
    environment = {
        "CUDA_VISIBLE_DEVICES": _visible_value(
            "CUDA_VISIBLE_DEVICES", source_env.get("CUDA_VISIBLE_DEVICES")
        ),
        "NVIDIA_VISIBLE_DEVICES": _visible_value(
            "NVIDIA_VISIBLE_DEVICES", source_env.get("NVIDIA_VISIBLE_DEVICES")
        ),
        "NVIDIA_DRIVER_CAPABILITIES": _visible_value(
            "NVIDIA_DRIVER_CAPABILITIES", source_env.get("NVIDIA_DRIVER_CAPABILITIES")
        ),
        "LD_LIBRARY_PATH": _path_value(source_env.get("LD_LIBRARY_PATH")),
    }
    cuda_disabled = environment["CUDA_VISIBLE_DEVICES"].state in {"empty", "disabled"}
    nvidia_disabled = environment["NVIDIA_VISIBLE_DEVICES"].state in {"empty", "disabled"}
    driver_caps = environment["NVIDIA_DRIVER_CAPABILITIES"]
    compute_available: bool | None = None
    if driver_caps.state == "capability_list" and driver_caps.value is not None:
        capabilities = set(driver_caps.value.split(","))
        compute_available = "compute" in capabilities or "all" in capabilities
    elif driver_caps.state == "all":
        compute_available = True

    nodes = _device_nodes(device_root)
    required_nodes = _required_nodes_present(nodes)
    libcuda_loadable, found, resolved, libcuda_error = _load_libcuda()
    ldconfig, ldconfig_error = _ldconfig_entries()
    compat_exists, compat_entries = _compat_entries()
    libraries = LibraryDiagnostics(
        libcuda_loadable=libcuda_loadable,
        libcuda_error=libcuda_error,
        find_library_result=found,
        resolved_libcuda_location=resolved,
        ldconfig_entries=ldconfig,
        ldconfig_error=ldconfig_error,
        cuda_compat_exists=compat_exists,
        cuda_compat_entries=compat_entries,
        compat_libraries_precede_host_driver=_compat_precedes_host(
            source_env.get("LD_LIBRARY_PATH"), resolved
        ),
    )
    child_checks = tuple(_run_child(mode, source_env) for mode in CHILD_MODES)
    runtime = child_checks[0]
    nvml = child_checks[-1]
    nvml_runtime_disagree = None
    if runtime.cuda_available is not None and nvml.cuda_available is not None:
        nvml_runtime_disagree = runtime.cuda_available != nvml.cuda_available
    diagnosis = _diagnose(
        runtime=runtime,
        cuda_disabled=cuda_disabled,
        nvidia_disabled=nvidia_disabled,
        compute_available=compute_available,
        required_nodes_present=required_nodes,
        libraries=libraries,
    )
    warnings = []
    if nvml_runtime_disagree:
        warnings.append("NVML-based and CUDA-runtime availability checks disagree.")
    if runtime.stderr:
        warnings.append("The runtime child emitted sanitized stderr; inspect its check record.")
    cuda_home_raw = source_env.get("CUDA_HOME")
    cuda_home = _sanitize_path(cuda_home_raw)
    if cuda_home_raw is None and Path("/usr/local/cuda").exists():
        cuda_home = "/usr/local/cuda"
    return CudaPreflightReport(
        schema_version="1.0",
        created_at=datetime.now(UTC),
        status="PASSED" if diagnosis == CudaDiagnosis.CUDA_AVAILABLE else "FAILED",
        primary_diagnosis=diagnosis,
        python_version=sys.version.split()[0],
        environment=environment,
        cuda_home=cuda_home,
        device_nodes=nodes,
        required_device_nodes_present=required_nodes,
        driver_capabilities_include_compute=compute_available,
        cuda_visible_devices_disables_access=cuda_disabled,
        nvidia_visible_devices_disables_access=nvidia_disabled,
        libraries=libraries,
        child_checks=child_checks,
        nvml_runtime_disagree=nvml_runtime_disagree,
        warnings=tuple(warnings),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a model-free CUDA preflight")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_preflight()
    body = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    try:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(body)
    except OSError as exc:
        raise SystemExit(
            f"CUDA preflight output could not be created: {type(exc).__name__}"
        ) from exc
    print(body, end="")
    raise SystemExit(0 if report.status == "PASSED" else 1)


if __name__ == "__main__":
    main()
