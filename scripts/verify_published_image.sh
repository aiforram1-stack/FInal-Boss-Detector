#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: verify_published_image.sh <digest-reference> <full-commit> <source-url>" >&2
  exit 2
fi

image_reference="$1"
source_commit="$2"
source_url="$3"

if [[ ! "$image_reference" =~ ^ghcr\.io/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ ]]; then
  echo "image reference must be a lowercase immutable GHCR digest reference" >&2
  exit 2
fi
if [[ ! "$source_commit" =~ ^[a-f0-9]{40}$ ]]; then
  echo "source commit must be a complete lowercase Git commit" >&2
  exit 2
fi
if [[ ! "$source_url" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "source URL must identify one GitHub repository" >&2
  exit 2
fi

docker pull "$image_reference"

image_os=$(docker image inspect --format '{{.Os}}' "$image_reference")
image_architecture=$(docker image inspect --format '{{.Architecture}}' "$image_reference")
image_revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image_reference")
image_source=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' "$image_reference")
image_version=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$image_reference")
image_title=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.title" }}' "$image_reference")
image_description=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.description" }}' "$image_reference")
image_created=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.created" }}' "$image_reference")
image_licenses=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.licenses" }}' "$image_reference")
image_vendor=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.vendor" }}' "$image_reference")
image_base_digest=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.base.digest" }}' "$image_reference")

test "$image_os" = "linux"
test "$image_architecture" = "amd64"
test "$image_revision" = "$source_commit"
test "$image_source" = "$source_url"
test "$image_version" = "sha-$source_commit"
test -n "$image_title"
test -n "$image_description"
[[ "$image_created" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
test "$image_licenses" = "LicenseRef-Proprietary"
test -n "$image_vendor"
test "$image_base_digest" = "sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3"

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --tmpfs /work/tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --entrypoint python \
  --env IMAGE_COMMUNITY_ENVIRONMENT=test \
  --env IMAGE_COMMUNITY_BACKEND=mock \
  --env IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false \
  --env IMAGE_COMMUNITY_REQUIRE_CUDA=false \
  --env IMAGE_COMMUNITY_TEMP_ROOT=/work/tmp \
  "$image_reference" \
  /app/workers/image-community/scripts/container_smoke.py

echo "published image digest, architecture, labels, and mock smoke passed"
