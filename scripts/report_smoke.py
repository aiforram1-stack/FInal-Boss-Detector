"""Verify deterministic JSON/HTML report generation through the local API."""

from __future__ import annotations

from scripts.structural_smoke import run_smoke


def main() -> None:
    result = run_smoke()
    if result.test_count != 8:
        raise SystemExit("report smoke did not cover every registered test")
    print(f"report smoke passed json_sha256={result.json_sha256} html_sha256={result.html_sha256}")


if __name__ == "__main__":
    main()
