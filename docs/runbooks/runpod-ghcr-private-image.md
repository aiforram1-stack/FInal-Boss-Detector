# RunPod preparation for the private GHCR worker image

This is a Phase 6 preparation document. Do not create a registry credential,
template, Pod, volume, endpoint, or GPU while Phase 5 is under review. Do not
paste credentials into this repository, issue, pull request, shell history, or
support channel.

## 1. Find and verify the immutable image

After the protected publication workflow succeeds, download its
`image-community-container-release-<commit>` artifact. Validate
`container-release.sha256`, then read these fields from
`container-release.json`:

- `source.git_commit`;
- `container.tag_reference` for registry browsing only;
- `container.digest_reference` for every pull and future RunPod setting;
- `container.platform`, which must be `linux/amd64`;
- `model.checkpoint_included`, which must be `false`;
- all verification and supply-chain statuses.

The SHA tag is release-controlled but the digest reference is authoritative.
Never substitute a moving convenience tag. The image is only container-build
verified; CUDA fitness and real inference have not run.

From a trusted, authenticated workstation with Docker and GitHub CLI:

```bash
export IMAGE_DIGEST_REFERENCE='ghcr.io/<owner>/forensic-image-community@sha256:<published-digest>'
export GITHUB_REPOSITORY='<owner>/<repository>'
gh attestation verify "oci://${IMAGE_DIGEST_REFERENCE}" --repo "${GITHUB_REPOSITORY}"
scripts/verify_published_image.sh \
  "${IMAGE_DIGEST_REFERENCE}" \
  '<full-source-commit>' \
  'https://github.com/<owner>/<repository>'
```

The verification script rejects tags, checks Linux AMD64 and the OCI
source/revision/version labels, and runs only the generated-fixture mock path
with networking disabled. It does not run CUDA or download the checkpoint.

## 2. Confirm package settings manually

Open the package settings under the GitHub owner and verify all of the
following before giving an external service access:

1. Visibility is **Private**.
2. The package is linked to `<owner>/<repository>`.
3. Repository permission inheritance is enabled or this repository has the
   required package access.
4. No unrelated repository or user has package access.

The `org.opencontainers.image.source` label is set before publication so GitHub
can link the package to the source repository. The publication workflow also
queries package metadata and fails closed if it can observe public or unlinked
state. Package settings remain an owner-controlled manual boundary.

## 3. Prepare a read-only registry credential in Phase 6

GitHub's current GHCR documentation requires a classic GitHub personal access
token for an external private-registry client. In Phase 6, an authorized owner
may create a dedicated, revocable credential with only `read:packages`; do not
grant write/delete package access, and do not reuse a broad personal credential.
Confirm the dedicated account has read access to the private package. Record an
owner and rotation/expiry date outside Git.

RunPod supports saved private-registry authentication containing a registry
username and password/token. Prefer its console/settings flow so the token does
not enter shell history. If the CLI is used later, obtain the syntax from the
current [RunPod registry documentation](https://docs.runpod.io/runpodctl/reference/runpodctl-registry)
and pass the secret through an ephemeral protected prompt or environment—not a
committed command. Save only the returned registry-authentication ID in the
future Pod configuration. Never store the token in `image-reference.example.yaml`.

## 4. Configure the temporary Phase 6 Pod

Only after explicit Phase 6 authorization:

1. Copy `infra/runpod/image-reference.example.yaml` outside the repository and
   replace placeholders from the validated release manifest.
2. Select one temporary NVIDIA GPU Pod with at least 24 GB VRAM and CUDA 12.6
   compatibility.
3. Set the container image to the exact digest reference and select the saved
   private-registry credential ID.
4. Attach external persistent model-cache storage at
   `/models/community-forensics`; the container image itself must remain
   checkpoint-free.
5. Download only the manifest-pinned checkpoint to that external storage using
   the Phase 4 double-opt-in acquisition path.
6. Calculate and record its SHA-256, require an exact match to the model
   manifest, and set the verified container digest in worker configuration.
7. Run CUDA/VRAM/output-shape fitness first, then one controlled generated or
   explicitly authorized Community Forensics inference.
8. Do not create a Serverless endpoint and do not connect the main API yet.
9. Terminate—not merely stop—the temporary Pod immediately after evidence is
   collected. Remove or rotate the temporary registry credential if it is no
   longer needed, and verify that no billable resource remains.

Current RunPod documentation confirms that private images use saved registry
credentials referenced by an authentication ID, Linux AMD64 is the expected
worker platform, and persistent volumes should hold model caches instead of the
container filesystem. Recheck the current GitHub and RunPod instructions at the
start of Phase 6 because authentication and UI mechanics can change.
