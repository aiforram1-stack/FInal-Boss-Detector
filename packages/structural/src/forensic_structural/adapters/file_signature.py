"""Internal byte-signature adapter; no uploaded content is executed."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from forensic_contracts import EvidenceAsset, ForensicTestStatus
from forensic_evidence import detect_media_type

from forensic_structural.adapters.base import AdapterResult


class FileSignatureAdapter:
    def execute(self, evidence_path: Path, evidence: EvidenceAsset) -> AdapterResult:
        with evidence_path.open("rb") as source:
            prefix = source.read(8192)
        signature_mime = detect_media_type(prefix)
        extension_mime = mimetypes.guess_type(evidence.filename, strict=False)[0]
        consistent = extension_mime is None or extension_mime == signature_mime
        warnings = []
        if not consistent:
            warnings.append("Filename extension and byte signature identify different media types.")
        return AdapterResult(
            status=ForensicTestStatus.EXECUTED,
            structured_output={
                "signature_mime_type": signature_mime,
                "database_mime_type": evidence.mime_type,
                "extension_mime_type": extension_mime,
                "extension_signature_consistent": consistent,
            },
            warnings=warnings,
            runtime_ms=0,
            tool_version="internal-signature-v1",
        )
