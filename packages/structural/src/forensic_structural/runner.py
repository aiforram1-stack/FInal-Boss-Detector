"""One bounded, shell-free subprocess boundary for trusted structural tools."""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

from forensic_structural.reporting import sanitize_report_text


class CommandOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    EXECUTABLE_MISSING = "EXECUTABLE_MISSING"
    NONZERO_EXIT = "NONZERO_EXIT"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    START_FAILED = "START_FAILED"


@dataclass(frozen=True, slots=True)
class CommandResult:
    outcome: CommandOutcome
    stdout: str
    stderr: str
    exit_code: int | None
    runtime_ms: int
    tool_version: str | None


@dataclass(frozen=True, slots=True)
class _Execution:
    outcome: CommandOutcome
    stdout: str
    stderr: str
    exit_code: int | None
    runtime_ms: int


class SafeSubprocessRunner:
    """Runs configured metadata binaries without a shell or unbounded capture."""

    def __init__(self, *, timeout_seconds: float, max_output_bytes: int) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def run(
        self,
        *,
        binary: str,
        arguments: Sequence[str],
        version_arguments: Sequence[str],
        evidence_path: Path,
    ) -> CommandResult:
        """Run one tool command; the resolved evidence path is exactly one argument."""

        version = self._execute([binary, *version_arguments], evidence_path=None)
        if version.outcome == CommandOutcome.EXECUTABLE_MISSING:
            return CommandResult(
                outcome=version.outcome,
                stdout="",
                stderr="Configured tool is unavailable.",
                exit_code=None,
                runtime_ms=version.runtime_ms,
                tool_version=None,
            )
        version_text = self._version_text(version) or f"version-unavailable:{version.outcome.value}"
        command = [binary, *arguments, str(evidence_path)]
        execution = self._execute(command, evidence_path=evidence_path)
        return CommandResult(
            outcome=execution.outcome,
            stdout=execution.stdout,
            stderr=execution.stderr,
            exit_code=execution.exit_code,
            runtime_ms=execution.runtime_ms,
            tool_version=version_text,
        )

    def probe(self, *, binary: str, version_arguments: Sequence[str]) -> CommandResult:
        execution = self._execute([binary, *version_arguments], evidence_path=None)
        return CommandResult(
            outcome=execution.outcome,
            stdout=execution.stdout,
            stderr=execution.stderr,
            exit_code=execution.exit_code,
            runtime_ms=execution.runtime_ms,
            tool_version=self._version_text(execution),
        )

    @staticmethod
    def _version_text(execution: _Execution) -> str | None:
        if execution.outcome != CommandOutcome.SUCCEEDED:
            return None
        text = execution.stdout.strip() or execution.stderr.strip()
        return text.splitlines()[0][:500] if text else "version not reported"

    def _execute(self, command: list[str], evidence_path: Path | None) -> _Execution:
        started = time.monotonic()
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C",
            "LC_ALL": "C",
        }
        try:
            process = subprocess.Popen(  # noqa: S603 - trusted configured tool, no shell
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=environment,
                close_fds=True,
            )
        except FileNotFoundError:
            return self._early(CommandOutcome.EXECUTABLE_MISSING, started)
        except OSError:
            return self._early(CommandOutcome.START_FAILED, started)

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_fd = process.stdout.fileno()
        stderr_fd = process.stderr.fileno()
        os.set_blocking(stdout_fd, False)
        os.set_blocking(stderr_fd, False)
        buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
        selector = selectors.DefaultSelector()
        selector.register(stdout_fd, selectors.EVENT_READ)
        selector.register(stderr_fd, selectors.EVENT_READ)
        outcome: CommandOutcome | None = None

        try:
            while selector.get_map():
                remaining = self.timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    outcome = CommandOutcome.TIMED_OUT
                    self._terminate(process)
                    break
                events = selector.select(timeout=min(remaining, 0.05))
                if not events and process.poll() is not None:
                    for descriptor_value in tuple(selector.get_map()):
                        descriptor = cast(int, descriptor_value)
                        self._read_ready(selector, buffers, descriptor)
                    continue
                for key, _ in events:
                    descriptor = int(key.fd)
                    if not self._read_ready(selector, buffers, descriptor):
                        continue
                    if len(buffers[descriptor]) > self.max_output_bytes:
                        outcome = CommandOutcome.OUTPUT_LIMIT_EXCEEDED
                        self._terminate(process)
                        break
                if outcome is not None:
                    break
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0.05, self.timeout_seconds / 10))
                except subprocess.TimeoutExpired:
                    outcome = outcome or CommandOutcome.TIMED_OUT
                    self._terminate(process)
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()

        stdout = bytes(buffers[stdout_fd][: self.max_output_bytes])
        stderr = bytes(buffers[stderr_fd][: self.max_output_bytes])
        decoded_stdout = self._sanitize(stdout.decode("utf-8", errors="replace"), evidence_path)
        decoded_stderr = self._sanitize(stderr.decode("utf-8", errors="replace"), evidence_path)
        exit_code = process.returncode
        if outcome is None:
            outcome = CommandOutcome.SUCCEEDED if exit_code == 0 else CommandOutcome.NONZERO_EXIT
        return _Execution(
            outcome=outcome,
            stdout=decoded_stdout,
            stderr=decoded_stderr,
            exit_code=exit_code,
            runtime_ms=max(0, round((time.monotonic() - started) * 1000)),
        )

    def _read_ready(
        self,
        selector: selectors.BaseSelector,
        buffers: dict[int, bytearray],
        descriptor: int,
    ) -> bool:
        try:
            chunk = os.read(descriptor, 8192)
        except (BlockingIOError, OSError):
            chunk = b""
        if not chunk:
            try:
                selector.unregister(descriptor)
            except KeyError:
                pass
            return False
        buffers[descriptor].extend(chunk)
        return True

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=0.5)

    @staticmethod
    def _sanitize(text: str, evidence_path: Path | None) -> str:
        if evidence_path is not None:
            text = text.replace(str(evidence_path), "<evidence-object>")
        sanitized = "".join(
            character if character in "\n\r\t" or ord(character) >= 32 else "?"
            for character in text
        )
        return sanitize_report_text(sanitized)

    @staticmethod
    def _early(outcome: CommandOutcome, started: float) -> _Execution:
        return _Execution(
            outcome=outcome,
            stdout="",
            stderr="Configured tool could not be started.",
            exit_code=None,
            runtime_ms=max(0, round((time.monotonic() - started) * 1000)),
        )
