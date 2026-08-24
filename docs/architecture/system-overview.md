# System overview

## Scope

This document describes the intended system and the implemented Phase 3 local
slice. Local evidence intake, structural tool isolation, SQLite results, and
deterministic JSON/HTML reports marked “Phase 2/3” exist. Components labeled
“later” are not implemented.

## Architecture

```mermaid
flowchart TB
    User[Forensic operator]

    subgraph Local[Local / API control plane]
        API[Case, evidence and structural API — Phase 2/3]
        Structural[Integrity verifier + structural service — Phase 3]
        Tools[Bounded optional metadata tools — Phase 3]
        Orchestrator[Asynchronous detector orchestrator — later]
        CaseDB[(SQLite metadata and results — Phase 2/3)]
    end

    subgraph Private[Private evidence plane — never Git]
        Originals[(Local content-addressed originals — Phase 2)]
        Derivatives[(Versioned derivatives and detector artifacts)]
        Results[(Create-only result artifacts — Phase 3)]
        Reports[(Canonical JSON and self-contained HTML — Phase 3)]
    end

    subgraph GitHub[Private GitHub control plane]
        Repo[Monorepo: code, schemas, manifests, tests, docs]
        Actions[GitHub Actions]
        GHCR[(GitHub Container Registry)]
    end

    subgraph GPU[Cloud GPU execution — later Phase 5+]
        Queue[Queue-based endpoint]
        Workers[Digest-pinned detector workers]
    end

    subgraph Reporting[Reporting and review]
        Builder[Deterministic report builder — Phase 3]
        Review[Manual analytical review]
    end

    subgraph Learning[Continual-learning plane — later Phase 12]
        Manifests[Permission and lineage manifests]
        Candidate[Candidate training]
        Eval[Evaluation, shadow and canary gates]
        Registry[(Approved model registry)]
    end

    User --> API
    API --> Originals
    API --> CaseDB
    API --> Structural
    Structural --> Originals
    Structural --> Tools
    Tools --> Structural
    Structural --> CaseDB
    Structural --> Results
    CaseDB --> Builder
    Results --> Builder
    Builder --> Reports
    API --> Orchestrator
    Orchestrator --> Queue --> Workers
    Workers --> Derivatives
    Workers --> Orchestrator
    Derivatives --> Builder
    Reports --> Review

    Repo --> Actions --> GHCR
    GHCR --> Workers

    Originals -. explicit training permission only .-> Manifests
    Derivatives -. approved labeled data only .-> Manifests
    Manifests --> Candidate --> Eval --> Registry
    Registry -. immutable approved revision .-> Repo
```

## Trust boundaries

- Uploaded bytes, names, media metadata, URLs, archives, provider responses, and
  detector output are untrusted until bounded and validated.
- Evidence originals live in private versioned object storage. The control plane
  stores immutable hashes and object versions, not bytes in Git.
- A worker receives a short-lived URL and expected SHA-256. It must bound the
  download, reject redirects or destinations that violate network policy, and
  verify the complete input hash before inference.
- Detector results cross from GPU infrastructure back to the control plane and
  must pass contract, identity, case/evidence ID, and input-hash validation.
- Deterministic report fields are generated from stored records. Narrative review
  cannot edit hashes, scores, versions, preprocessing, or timestamps.
- The continual-learning plane has a separate permission boundary. Production
  case data is ineligible unless explicit training permission and governance are
  recorded.

## Implemented Phase 2 request flow

```mermaid
sequenceDiagram
    participant Client
    participant API as FastAPI service
    participant Stage as Unique staging file
    participant Store as Hash-addressed store
    participant DB as SQLite metadata

    Client->>API: POST one multipart file
    API->>Stage: bounded chunks + SHA-256/SHA-512
    API->>API: validate byte signature and allowlist
    API->>Store: atomic hard-link put-if-absent
    API->>DB: insert/reuse blob + case association
    API->>Store: verify object still exists at exact size
    API-->>Client: shared EvidenceAsset + dedup headers
```

The filesystem and SQLite cannot share one transaction. Storage is committed
first so the database never intentionally points to an absent object. A database
failure can leave an unreferenced immutable blob; `make reconcile` reports its
logical URI and never deletes it. If the post-commit storage check fails, the API
compensates by removing the metadata association before returning an error.

Phase 2 “sealed” means every accepted original is immutable and hash-addressed.
It does not close the case to additional evidence; an explicit case-close state
transition belongs to a later authorized phase.

## Implemented Phase 3 analysis flow

```mermaid
sequenceDiagram
    participant Client
    participant API as Structural route
    participant Service as StructuralAnalysisService
    participant Store as Evidence store
    participant Tools as Safe tool runner
    participant Results as Result store
    participant DB as SQLite

    Client->>API: POST structural-analysis
    API->>Service: case ID + evidence ID only
    Service->>DB: create unique RUNNING record
    Service->>Store: resolve logical URI and read-only re-hash
    alt integrity mismatch or missing object
        Service->>DB: persist REFUSED integrity result
        Service-->>Client: 409 structured error
    else integrity verified
        Service->>Tools: argument arrays + internal path + timeout/output cap
        Tools-->>Service: normalized output or explicit coverage status
        Service->>Results: create-only tool JSON and canonical report.json
        Service->>Results: render HTML from stored report.json
        Service->>DB: atomically finalize tests, artifacts, report and run
        Service-->>Client: shared StructuralAnalysisRun
    end
```

Optional executables are never discovered by executing uploaded content and are
never installed by the application. Uploaded filenames are report data only;
subprocesses receive the internally resolved content-addressed object path as a
single argument. The HTML renderer validates stored JSON, uses automatic
escaping, and includes no JavaScript, CDN, fonts, or original media.

## GitHub versus private storage

GitHub holds source, schemas, synthetic fixtures, documentation, manifests,
hashes, workflows, model cards, and digest-addressed container metadata. Private
object storage holds evidence, datasets, checkpoints, extracted media,
derivatives, unredacted reports, and caches. An external object is represented in
Git by a manifest containing immutable location/version, size, hash, license,
source, and lineage—not by the object itself.

## Contract compatibility

Every stored root object has `schema_version`. Phase 1 models accept and preserve
unknown fields so a newer producer does not lose data when an older reader loads
and reserializes a record. Current code must not act on unknown fields. Breaking
semantic changes require a new major schema version and an explicit migration.
