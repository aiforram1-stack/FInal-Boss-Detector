# ADR 0010: Immutable worker-container publication and attestation

- Status: Accepted for Phase 5
- Date: 2026-08-24
- Updated: 2026-08-25
- Scope: Community Forensics image-worker build, publication, and verification

## Context

Phase 4 produced one worker implementation with deterministic mock and gated
real CUDA backends. Phase 5 may package and verify that implementation, but it
may not download the model checkpoint, run CUDA, rent a GPU, deploy to RunPod,
connect the API, or claim that real inference has been verified.

Phase 4 and the Phase 5 pipeline are now merged. Publication remains restricted
to an exact commit on protected `main` or a manual dispatch whose ref is
`main`.

## Documentation reviewed

The following current primary documentation was reviewed on 2026-08-24:

- GitHub: [working with the container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry),
  [package access and visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility),
  [publishing Docker images](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images),
  [artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
  and [secure use of Actions](https://docs.github.com/en/actions/reference/security/secure-use).
- Docker: [SBOM and provenance attestations](https://docs.docker.com/build/ci/github-actions/attestations/)
  and [multi-platform builds](https://docs.docker.com/build/building/multi-platform/).
- RunPod: [worker Dockerfiles](https://docs.runpod.io/serverless/workers/create-dockerfile),
  [private registry credentials](https://docs.runpod.io/runpodctl/reference/runpodctl-registry),
  and [Pod templates](https://docs.runpod.io/pods/templates/manage-templates).

Canonical release tags were resolved to their commits from the action owners'
GitHub repositories rather than remembered. Phase 5 pins:

| Action | Reviewed release | Commit |
| --- | --- | --- |
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python` | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/upload-artifact` | `v6.0.0` | `b7c566a772e6b6bfb58ed0dc250532a479d7789f` |
| `actions/attest` | `v4.0.0` | `c32b4b8b198b65d0bd9d63490e847ff7b53989d4` |
| `astral-sh/setup-uv` | `v9.0.0` | `c771a70e6277c0a99b617c7a806ffedaca235ff9` |
| `docker/setup-buildx-action` | `v4.0.0` | `4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd` |
| `docker/login-action` | `v4.0.0` | `b45d80f862d83dbcd57f89517bcf500b2ab88fb2` |
| `docker/build-push-action` | `v7.0.0` | `d08e5c354a6adb9ed34480a06d141179aa583294` |
| `aquasecurity/setup-trivy` | `v0.3.1` | `81e514348e19b6112ce2a7e3ecbafe19c1e1f567` |

Trivy itself is fixed to `v0.74.0`. Dependabot may propose Action updates, but
updates remain ordinary reviewable pull requests and are never auto-merged.

## Decision

### One implementation, two targets

The Dockerfile exposes `mock-test` and `gpu-runtime` targets. Both install the
same project and call the same worker services. `mock-test` uses a digest-pinned
Python CPU base and only CPU runtime dependencies. `gpu-runtime` retains the
digest-pinned PyTorch/CUDA base and GPU dependency group. Neither target
contains a checkpoint or stored test media; the smoke fixture is generated in
memory by worker code.

The verified bases are both from Docker Hub:

- `python:3.11-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91`;
- `pytorch/pytorch:2.7.1-cuda12.6-cudnn9-runtime@sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3`.

Registry manifest responses were rechecked on the ADR date. The GPU image is
Python 3.11 with PyTorch 2.7.1, CUDA 12.6, cuDNN 9, and its upstream runtime OS.
Both final targets use UID/GID 10001, an explicit entrypoint, no secret build
arguments, and complete OCI source/revision/version/created/license metadata.
The CUDA base's `linux-libc-dev` package is removed after dependency
installation because the runtime compiles no code and does not need kernel
headers. This also removes development-only kernel CVEs from the published
artifact instead of masking them with vulnerability exceptions.

### PR validation and protected publication are separate

The pull-request workflow has only `contents: read`; it never logs in to a
registry, pushes an image, creates an attestation, receives a secret, or uses
`pull_request_target`. It builds native `linux/amd64` targets on a GitHub-hosted
AMD64 runner, runs the mock container with networking disabled, scans source
and images, and inspects image contents. The small mock target uses a PR-only
GitHub Actions cache. After that target is verified, its local image and
container-driver cache are removed from the ephemeral runner. The load-required
CUDA target uses Docker's native builder, which loads directly into the local
image store rather than retaining a second container-driver copy of the large
CUDA layers. Docker documents that the native `docker` driver loads directly
but does not support the GitHub Actions cache backend, so that PR step is
intentionally uncached. None of these PR paths are read by the protected
release build.

The pinned PyTorch/CUDA image is large enough that local loading plus Trivy's
Docker export can exceed the default free space on a standard hosted runner.
Both container workflows therefore delete only an explicit allowlist of
unneeded, preinstalled Android, .NET, GHC, and CodeQL SDK directories after all
Python checks pass. The cleanup is guarded by `GITHUB_ACTIONS=true`, runs only
on GitHub's disposable job machine, prints capacity before and after, and does
not touch the checkout, Docker, Python, Node action runtime, credentials, or
any persistent service. Each hosted runner starts from a fresh image, so no
durable data is deleted.

The publication workflow runs only for relevant pushes to `main` or a manual
dispatch on `main`. It has exactly `contents: read`, `packages: write`,
`id-token: write`, and `attestations: write`. It uses `GITHUB_TOKEN`, derives a
lowercase `ghcr.io/<owner>/forensic-image-community` name, and publishes only
`sha-<full-commit>`. The `org.opencontainers.image.source` label links the
package to its repository before first publication. Package visibility cannot
be safely asserted through a build workflow, so an owner must verify in the
package settings that it is private and repository-linked.

The authoritative reference is always `<repository>@sha256:<digest>`. The
workflow captures the digest from Buildx, scans and pulls by that digest, checks
Linux AMD64 and OCI labels, runs a network-disabled mock smoke test, and emits a
schema-validated `container-release.json` plus its SHA-256 as retained workflow
artifacts. It never commits generated manifests to the repository.

### Supply-chain evidence is generated and verified

The protected build requests BuildKit `mode=max` provenance and an SBOM
attestation. Build arguments contain only public source/OCI metadata; secrets
are not build arguments and model weights are never build inputs. A separate
GitHub artifact attestation uses the fully qualified image name and exact
Buildx digest. The workflow then verifies the OCI subject against this
repository with `gh attestation verify`. Linked-artifact storage records are
disabled explicitly because they require the additional
`artifact-metadata: write` permission; Phase 5 does not need or grant it. The
workflow also extracts and validates the attached SPDX SBOM and SLSA provenance
from the immutable registry digest rather than assuming their presence.

Buildx exposes these inspection records through documented wrapper objects:
`.SBOM` contains an `SPDX` document and `.Provenance` contains a `SLSA`
predicate or in-toto statement. Verification accepts only those documented
direct, wrapper, or exact `linux/amd64` wrapper shapes. It validates the SPDX
document identity/version/license/creator metadata and either legacy BuildKit
or SLSA v1 provenance fields. Unknown recursive matches, missing subjects,
malformed SHA-256 subjects, and non-SLSA statements fail closed.

GitHub currently documents artifact attestations for private repositories as a
GitHub Enterprise Cloud feature. Attestation creation and verification are
therefore captured as explicit outcomes so a plan limitation can still produce
a diagnostic release manifest and summary. The final publication gate fails if
either outcome is not successful. Docker provenance and SBOM remain attached;
the workflow never converts an unavailable GitHub feature into a passing or
fabricated attestation status.

The first protected Phase 6 publication on 2026-08-24 proved that the image can
be built, pushed, pulled by digest, scanned, inspected, and run in CPU mock mode,
but failed the final gate. Buildx's current provenance envelope was not handled
by the original inline parser; GitHub rejected artifact-attestation storage for
this private user-owned repository; and the package API omitted its repository
field. Signed-in package settings independently confirmed that the private
package is source-linked to this repository, grants it Actions Admin access,
and inherits repository access. The pushed digest is retained as diagnostic
evidence and is not approved for deployment. The attestation and package
verifiers are repaired through an ordinary reviewable pull request; the
GitHub feature/visibility decision remains an explicit owner action rather than
a workflow bypass.

The owner subsequently approved making the GitHub repository public while
keeping the source-linked GHCR package private. Repair PR #16 updated the
BuildKit evidence parser and package-link verifier without bypassing a gate.
After merge, protected run
[`32769244299`](https://github.com/aiforram1-stack/FInal-Boss-Detector/actions/runs/32769244299)
accepted source commit `4062b946a29288330242d108dbbed9ded4d9d736` and Linux AMD64
digest
`sha256:190618d75aad8dd38bac264c5a1eb48e9b5ee248262f25c49c67e14ec5a44437`.
SBOM, provenance, GitHub attestation creation and repository-bound verification,
pull-by-digest identity, mock smoke, filesystem inspection, package linkage,
release checksum, vulnerability policy, and the final fail-closed gate all
passed. That digest is the first Phase 5 release approved for the Phase 6
proposal; it does not claim checkpoint or CUDA validation.

Trivy configuration/filesystem scans run on pull requests and an image scan
runs on the published digest. Machine-readable JSON is retained. Unexcepted
critical findings fail the corresponding gate. Any exception must name the
finding, justification, owner, expiry date, and compensating control; expired or
malformed exceptions fail closed. High findings are counted and summarized.
Published images are not automatically deleted after a scan failure, preserving
incident evidence and avoiding destructive package actions.

### RunPod remains documentation-only

RunPod supports saved private-registry credentials and refers to them by a
registry-authentication ID. Phase 6 may create a narrowly scoped GHCR
`read:packages` credential outside this repository, save it in RunPod, and use
the immutable digest in one queue-based Serverless endpoint. Phase 5 only
supplies placeholders and instructions. It creates no token, RunPod key,
credential record, template,
Pod, volume, endpoint, or billable resource.

## Consequences

- The MacBook does not need Docker, CUDA, or an NVIDIA GPU; GitHub-hosted AMD64
  jobs are authoritative for image construction.
- PR validation is intentionally slower because it builds both final bases and
  does not reuse untrusted caches in protected publication.
- A protected publication can push an image and subsequently fail a critical
  scan or unsupported GitHub attestation. Such an image is not approved or
  deployable; the failed workflow and release artifact remain the audit trail.
- Phase 5 proves container construction and supply-chain identity only. It does
  not prove checkpoint availability, CUDA fitness, detector accuracy, or real
  Community Forensics inference.
