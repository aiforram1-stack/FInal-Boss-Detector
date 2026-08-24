#!/usr/bin/env python3
"""Validate Trivy reports and fail on unexcepted critical findings."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class VulnerabilityException(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    finding_id: str = Field(min_length=3)
    justification: str = Field(min_length=12)
    owner: str = Field(min_length=2)
    expires_on: date
    compensating_control: str = Field(min_length=12)

    @field_validator("finding_id")
    @classmethod
    def normalize_finding_id(cls, value: str) -> str:
        return value.upper()


class VulnerabilityExceptionFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^1\.[0-9]+$")
    exceptions: tuple[VulnerabilityException, ...] = ()


def load_exceptions(path: Path, today: date) -> dict[str, VulnerabilityException]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    policy = VulnerabilityExceptionFile.model_validate(loaded)
    exceptions: dict[str, VulnerabilityException] = {}
    for item in policy.exceptions:
        if item.finding_id in exceptions:
            raise ValueError(f"duplicate vulnerability exception: {item.finding_id}")
        if item.expires_on <= today:
            raise ValueError(f"expired vulnerability exception: {item.finding_id}")
        exceptions[item.finding_id] = item
    return exceptions


def finding_ids(report: object, severity: str) -> set[str]:
    if not isinstance(report, dict):
        raise ValueError("Trivy report must be a JSON object")
    results = report.get("Results") or []
    if not isinstance(results, list):
        raise ValueError("Trivy report Results must be an array")
    found: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        for collection_name in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            findings = result.get(collection_name) or []
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                if str(finding.get("Severity", "")).upper() != severity:
                    continue
                identifier = (
                    finding.get("VulnerabilityID")
                    or finding.get("ID")
                    or finding.get("RuleID")
                    or finding.get("Title")
                )
                if identifier:
                    found.add(str(identifier).upper())
    return found


def evaluate(
    reports: list[Path], exceptions_path: Path, summary_path: Path, today: date
) -> dict[str, object]:
    exceptions = load_exceptions(exceptions_path, today)
    critical: set[str] = set()
    high: set[str] = set()
    for path in reports:
        report = json.loads(path.read_text(encoding="utf-8"))
        critical.update(finding_ids(report, "CRITICAL"))
        high.update(finding_ids(report, "HIGH"))
    excepted = critical & exceptions.keys()
    unexcepted = critical - exceptions.keys()
    summary: dict[str, object] = {
        "status": "failed" if unexcepted else "passed",
        "critical": len(critical),
        "high": len(high),
        "excepted_critical": len(excepted),
        "unexcepted_critical_ids": sorted(unexcepted),
        "report_artifact": "image-community-vulnerability-reports",
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "vulnerability summary: "
        f"critical={len(critical)}, high={len(high)}, "
        f"excepted_critical={len(excepted)}, unexcepted_critical={len(unexcepted)}"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", type=Path)
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    parser.add_argument("--validate-exceptions-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.validate_exceptions_only:
            exceptions = load_exceptions(args.exceptions, args.today)
            print(f"vulnerability exception policy passed for {len(exceptions)} entries")
            return
        if not args.report:
            raise ValueError("at least one --report is required")
        summary = evaluate(args.report, args.exceptions, args.summary, args.today)
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        raise SystemExit(f"vulnerability policy validation failed: {exc}") from exc
    if summary["status"] != "passed":
        raise SystemExit("unexcepted critical vulnerability findings are present")


if __name__ == "__main__":
    main()
