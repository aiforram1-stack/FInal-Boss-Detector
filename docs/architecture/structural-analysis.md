# Structural analysis architecture

## Boundary and purpose

Phase 3 records deterministic file/container/metadata observations before any
model inference exists. It is CPU-only and local. A structural mismatch is a
review lead with documented limitations, not evidence of authenticity,
authorship, editing intent, or AI generation.

Routes call `StructuralAnalysisService`; they never invoke subprocesses or query
ORM records directly. The service coordinates the read-only integrity verifier,
`StructuralAnalysisEngine`, result storage, repositories, and report renderer.
The engine owns a declarative registry with exactly these tests:

- `structural.file-signature.v1`
- `structural.exiftool-metadata.v1`
- `structural.ffprobe-container.v1`
- `structural.mediainfo.v1`
- `structural.image-summary.v1`
- `structural.audio-summary.v1`
- `structural.video-summary.v1`
- `structural.metadata-consistency.v1`

Every registry entry has a version, description, MIME applicability, required
tool, timeout, output shape, and limitations. Every run stores one status for
every entry; non-applicable and unavailable tests are never dropped.

## Integrity gate

The service resolves only `local-sha256://<expected hash>` through the evidence
backend. It opens the resolved regular file read-only without following a final
symlink, recomputes SHA-256, SHA-512, and size in bounded chunks, and compares all
three to SQLite. Missing, unsafe, size-mismatched, or hash-mismatched objects
produce a persisted `REFUSED` run and HTTP 409. No repair or rewrite path exists.

## Tool isolation

`SafeSubprocessRunner` is the only process boundary. It:

- accepts an argument array and explicitly disables the shell;
- appends the internal evidence path as one argument;
- supplies no stdin and a minimal locale/PATH environment;
- captures stdout/stderr incrementally with per-stream limits;
- terminates and, if required, kills timed-out or over-limit processes;
- records exit code, runtime, and a bounded version string;
- replaces the internal evidence path in errors and parsed output;
- returns structured missing, timeout, output-limit, startup, and exit states.

ExifTool, ffprobe, and MediaInfo are optional. Missing executables map to
`PROVIDER_UNAVAILABLE`; parser errors map to `FAILED`. Neither state prevents
other tests or deterministic reporting. The adapters use local file arguments
only and contain no URL or network client.

The minimum supported capability surface is explicit rather than inferred from
a mutable package tag:

| Tool | Required capability |
| --- | --- |
| ExifTool | `-ver` and JSON metadata via `-json -G1 -n` |
| ffprobe | `-version`, `-show_format`, `-show_streams`, and `-of json` |
| MediaInfo | `--Version` and JSON tracks via `--Output=JSON` |

Each report records the observed version string. A future production image must
pin the package build or container digest; Phase 3 intentionally does not create
or deploy that image.

## Persistence and report artifacts

SQLite records runs, small test envelopes, artifact manifests, and report
manifests. Bounded normalized tool JSON lives beneath ignored
`var/results/<case>/<run>/` with logical `local-result://` URIs and SHA-256.
Files are created with exclusive create semantics, synchronized, made read-only,
and never replaced with different content.

Local source checkouts normally leave `GIT_COMMIT` unset. The report software
identity then records `null`; the legacy Phase 1 manifest field uses forty zeros
as the documented unavailable sentinel. Immutable builds must set `GIT_COMMIT`
to their exact lowercase 40-character source commit.

`StructuralReport` is a shared versioned contract. Canonical serialization uses
sorted keys, compact separators, UTF-8, and a final newline. The SHA-256 is
calculated over those exact stored bytes. HTML is rendered only after reading
and validating stored JSON. Jinja autoescaping is enabled with strict undefined
variables; CSS is self-contained and there is no script or external asset.

The case-level report endpoints return the latest completed structural report.
Concurrent active runs for the same evidence/profile are prevented by a partial
unique SQLite index. The synchronous service boundary is intentionally shaped so
a later authorized phase can place the engine behind a background job without
changing external contracts.

## Limitations

Phase 3 performs no frame extraction, packet-level analysis, signal processing,
provenance verification, OSINT, model inference, calibration, fusion, PDF
generation, or automated reasoning. Metadata may be absent, inaccurate, edited,
copied, rounded, or interpreted differently by tools. Reports therefore expose
tool versions, missing coverage, warnings, sources, and limitations instead of a
forensic verdict.
