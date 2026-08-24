# syntax=docker/dockerfile:1.7

# CPU-only target for deterministic mock validation. Registry digest rechecked 2026-08-24.
FROM --platform=linux/amd64 python:3.11-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91 AS mock-test

ARG PROJECT_SOURCE_COMMIT=0000000000000000000000000000000000000000
ARG PROJECT_CREATED_AT=1970-01-01T00:00:00Z
ARG PROJECT_VERSION=sha-0000000000000000000000000000000000000000
ARG PROJECT_SOURCE_URL=https://github.com/unknown/unknown
ARG PROJECT_VENDOR=unknown

LABEL org.opencontainers.image.title="Community Forensics image worker (mock test)" \
      org.opencontainers.image.description="CPU-only deterministic mock target; not a real detector" \
      org.opencontainers.image.source="${PROJECT_SOURCE_URL}" \
      org.opencontainers.image.revision="${PROJECT_SOURCE_COMMIT}" \
      org.opencontainers.image.created="${PROJECT_CREATED_AT}" \
      org.opencontainers.image.version="${PROJECT_VERSION}" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.vendor="${PROJECT_VENDOR}" \
      org.opencontainers.image.base.name="python:3.11-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IMAGE_COMMUNITY_ENVIRONMENT=test \
    IMAGE_COMMUNITY_BACKEND=mock \
    IMAGE_COMMUNITY_MODEL_MANIFEST=/app/workers/image-community/model-manifest.yaml \
    IMAGE_COMMUNITY_MODEL_CACHE=/models/community-forensics \
    IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false \
    IMAGE_COMMUNITY_TEMP_ROOT=/work/tmp \
    IMAGE_COMMUNITY_DEVICE=cuda \
    IMAGE_COMMUNITY_REQUIRE_CUDA=false \
    HF_HOME=/models/huggingface \
    TMPDIR=/work/tmp

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY packages/contracts ./packages/contracts
COPY workers/image-community ./workers/image-community

RUN mkdir -p /work/tmp && \
    python -m pip install --no-cache-dir uv==0.11.2 && \
    uv export --no-cache --frozen --only-group image-community-mock-runtime --no-emit-project --output-file /tmp/requirements.txt && \
    python -m pip install --no-cache-dir --requirement /tmp/requirements.txt && \
    python -m pip install --no-cache-dir --no-deps . && \
    rm -rf /root/.cache/uv /tmp/requirements.txt && \
    groupadd --system --gid 10001 forensic && \
    useradd --system --uid 10001 --gid forensic --home-dir /nonexistent --shell /usr/sbin/nologin forensic && \
    mkdir -p /models/community-forensics /models/huggingface /work/tmp && \
    chown -R forensic:forensic /models /work

USER 10001:10001

ENTRYPOINT ["python", "/app/workers/image-community/scripts/container_smoke.py"]


# Production-shaped CUDA target. The checkpoint remains external and Phase 6 is not authorized.
# Registry digest rechecked 2026-08-24.
FROM --platform=linux/amd64 pytorch/pytorch:2.7.1-cuda12.6-cudnn9-runtime@sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3 AS gpu-runtime

ARG PROJECT_SOURCE_COMMIT=0000000000000000000000000000000000000000
ARG PROJECT_CREATED_AT=1970-01-01T00:00:00Z
ARG PROJECT_VERSION=sha-0000000000000000000000000000000000000000
ARG PROJECT_SOURCE_URL=https://github.com/unknown/unknown
ARG PROJECT_VENDOR=unknown

LABEL org.opencontainers.image.title="Community Forensics image worker" \
      org.opencontainers.image.description="Pinned CUDA worker; GPU inference is not yet verified" \
      org.opencontainers.image.source="${PROJECT_SOURCE_URL}" \
      org.opencontainers.image.revision="${PROJECT_SOURCE_COMMIT}" \
      org.opencontainers.image.created="${PROJECT_CREATED_AT}" \
      org.opencontainers.image.version="${PROJECT_VERSION}" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.vendor="${PROJECT_VENDOR}" \
      org.opencontainers.image.base.name="pytorch/pytorch:2.7.1-cuda12.6-cudnn9-runtime" \
      org.opencontainers.image.base.digest="sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IMAGE_COMMUNITY_ENVIRONMENT=production \
    IMAGE_COMMUNITY_BACKEND=community \
    IMAGE_COMMUNITY_MODEL_MANIFEST=/app/workers/image-community/model-manifest.yaml \
    IMAGE_COMMUNITY_MODEL_CACHE=/models/community-forensics \
    IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false \
    IMAGE_COMMUNITY_TEMP_ROOT=/work/tmp \
    IMAGE_COMMUNITY_DEVICE=cuda \
    IMAGE_COMMUNITY_REQUIRE_CUDA=true \
    HF_HOME=/models/huggingface \
    TMPDIR=/work/tmp

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY packages/contracts ./packages/contracts
COPY workers/image-community ./workers/image-community

RUN mkdir -p /work/tmp && \
    python -m pip install --no-cache-dir uv==0.11.2 && \
    uv export --no-cache --frozen --only-group image-community-runtime --no-emit-project --output-file /tmp/requirements.txt && \
    python -m pip install --no-cache-dir --requirement /tmp/requirements.txt && \
    python -m pip install --no-cache-dir --no-deps . && \
    rm -rf \
      /opt/conda/etc/conda/test-files \
      /opt/conda/pkgs \
      /root/.cache/uv \
      /tmp/requirements.txt && \
    groupadd --system --gid 10001 forensic && \
    useradd --system --uid 10001 --gid forensic --home-dir /nonexistent --shell /usr/sbin/nologin forensic && \
    mkdir -p /models/community-forensics /models/huggingface /work/tmp && \
    chown -R forensic:forensic /models /work

USER 10001:10001

ENTRYPOINT ["python", "/app/workers/image-community/handler.py"]
CMD ["--runpod"]
