from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from forensic_structural.runner import CommandOutcome, SafeSubprocessRunner


def fake_tool(tmp_path: Path) -> Path:
    tool = tmp_path / "fake structural tool.py"
    tool.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
import time

if len(sys.argv) == 2 and sys.argv[1] == "--version":
    print("fake-tool 1.2.3")
    raise SystemExit(0)
mode = sys.argv[1]
if mode == "success":
    print(json.dumps({"arguments": sys.argv[1:-1], "path": sys.argv[-1]}))
elif mode == "nonzero":
    print(f"cannot parse {sys.argv[-1]}", file=sys.stderr)
    raise SystemExit(7)
elif mode == "sleep":
    time.sleep(2)
elif mode == "stdout":
    os.write(1, b"x" * 4096)
elif mode == "stderr":
    os.write(2, b"y" * 4096)
""",
        encoding="utf-8",
    )
    tool.chmod(0o700)
    return tool


def test_argument_array_path_spaces_metacharacters_and_version(tmp_path: Path) -> None:
    tool = fake_tool(tmp_path)
    evidence = tmp_path / "evidence ; $(touch should-not-run) [space].png"
    evidence.write_bytes(b"synthetic")
    runner = SafeSubprocessRunner(timeout_seconds=1, max_output_bytes=4096)
    result = runner.run(
        binary=str(tool),
        arguments=["success", "--literal=;$(touch never)"],
        version_arguments=["--version"],
        evidence_path=evidence,
    )
    assert result.outcome == CommandOutcome.SUCCEEDED
    assert result.tool_version == "fake-tool 1.2.3"
    payload = json.loads(result.stdout)
    assert payload["arguments"] == ["success", "--literal=;$(touch never)"]
    assert payload["path"] == "<evidence-object>"
    assert not (tmp_path / "should-not-run").exists()
    assert not (tmp_path / "never").exists()


def test_nonzero_exit_and_error_path_are_sanitized(tmp_path: Path) -> None:
    tool = fake_tool(tmp_path)
    evidence = tmp_path / "private evidence.png"
    evidence.write_bytes(b"synthetic")
    result = SafeSubprocessRunner(timeout_seconds=1, max_output_bytes=4096).run(
        binary=str(tool),
        arguments=["nonzero"],
        version_arguments=["--version"],
        evidence_path=evidence,
    )
    assert result.outcome == CommandOutcome.NONZERO_EXIT
    assert result.exit_code == 7
    assert str(evidence) not in result.stderr
    assert "<evidence-object>" in result.stderr


def test_timeout_terminates_process(tmp_path: Path) -> None:
    tool = fake_tool(tmp_path)
    evidence = tmp_path / "generated.png"
    evidence.write_bytes(b"synthetic")
    result = SafeSubprocessRunner(timeout_seconds=0.05, max_output_bytes=4096).run(
        binary=str(tool),
        arguments=["sleep"],
        version_arguments=["--version"],
        evidence_path=evidence,
    )
    assert result.outcome == CommandOutcome.TIMED_OUT
    assert result.runtime_ms < 1000


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_limits_terminate_process(tmp_path: Path, stream: str) -> None:
    tool = fake_tool(tmp_path)
    evidence = tmp_path / "generated.png"
    evidence.write_bytes(b"synthetic")
    result = SafeSubprocessRunner(timeout_seconds=1, max_output_bytes=64).run(
        binary=str(tool),
        arguments=[stream],
        version_arguments=["--version"],
        evidence_path=evidence,
    )
    assert result.outcome == CommandOutcome.OUTPUT_LIMIT_EXCEEDED
    assert len(result.stdout.encode()) <= 64
    assert len(result.stderr.encode()) <= 64


def test_missing_executable_is_structured(tmp_path: Path) -> None:
    evidence = tmp_path / "generated.png"
    evidence.write_bytes(b"synthetic")
    result = SafeSubprocessRunner(timeout_seconds=1, max_output_bytes=64).run(
        binary=str(tmp_path / "missing-tool"),
        arguments=["success"],
        version_arguments=["--version"],
        evidence_path=evidence,
    )
    assert result.outcome == CommandOutcome.EXECUTABLE_MISSING
    assert result.exit_code is None


def test_runner_source_has_no_shell_true_or_command_joining() -> None:
    source = Path(__file__).parents[1] / "src" / "forensic_structural" / "runner.py"
    text = source.read_text(encoding="utf-8")
    assert "shell=True" not in text
    assert "shell=False" in text
    assert "' '.join" not in text
    assert '" ".join' not in text


@pytest.mark.tool_integration
@pytest.mark.parametrize(
    ("tool_name", "version_arguments"),
    [
        ("file", ["--version"]),
        ("exiftool", ["-ver"]),
        ("ffprobe", ["-version"]),
        ("mediainfo", ["--Version"]),
    ],
)
def test_optional_local_tool_probe(tool_name: str, version_arguments: list[str]) -> None:
    binary = shutil.which(tool_name)
    if binary is None:
        pytest.skip(f"optional {tool_name} tool is unavailable")
    result = SafeSubprocessRunner(timeout_seconds=2, max_output_bytes=4096).probe(
        binary=binary, version_arguments=version_arguments
    )
    assert result.outcome == CommandOutcome.SUCCEEDED
    assert result.tool_version
