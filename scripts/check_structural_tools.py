"""Report optional structural-tool availability without installing anything."""

from __future__ import annotations

import json
import os

from forensic_structural.runner import CommandOutcome, SafeSubprocessRunner


def main() -> None:
    runner = SafeSubprocessRunner(timeout_seconds=5, max_output_bytes=16 * 1024)
    configured = (
        ("file", os.environ.get("FILE_BINARY", "file"), ["--version"]),
        ("exiftool", os.environ.get("EXIFTOOL_BINARY", "exiftool"), ["-ver"]),
        ("ffprobe", os.environ.get("FFPROBE_BINARY", "ffprobe"), ["-version"]),
        ("mediainfo", os.environ.get("MEDIAINFO_BINARY", "mediainfo"), ["--Version"]),
    )
    inventory: list[dict[str, str | None]] = []
    for name, binary, version_arguments in configured:
        result = runner.probe(binary=binary, version_arguments=version_arguments)
        inventory.append(
            {
                "tool": name,
                "configured_binary": binary,
                "status": (
                    "AVAILABLE" if result.outcome == CommandOutcome.SUCCEEDED else "UNAVAILABLE"
                ),
                "version": result.tool_version,
                "detail": None
                if result.outcome == CommandOutcome.SUCCEEDED
                else result.outcome.value,
            }
        )
    print(json.dumps(inventory, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
