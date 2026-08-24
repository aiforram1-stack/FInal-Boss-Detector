# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 pytorch/pytorch:2.7.1-cuda12.6-cudnn9-runtime@sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3 AS runtime

ARG PROJECT_SOURCE_COMMIT
LABEL org.opencontainers.image.source="https://github.com/aiforram1-stack/FInal-Boss-Detector" \
      org.opencontainers.image.revision="${PROJECT_SOURCE_COMMIT}" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.title="Community Forensics image worker"

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
    HF_HOME=/models/huggingface

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY packages/contracts ./packages/contracts
COPY workers/image-community ./workers/image-community

RUN python -m pip install --no-cache-dir uv==0.11.2 && \
    uv export --frozen --only-group image-community-runtime --no-emit-project --output-file /tmp/requirements.txt && \
    python -m pip install --no-cache-dir --requirement /tmp/requirements.txt && \
    python -m pip install --no-cache-dir --no-deps . && \
    rm -f /tmp/requirements.txt && \
    groupadd --system --gid 10001 forensic && \
    useradd --system --uid 10001 --gid forensic --home-dir /nonexistent --shell /usr/sbin/nologin forensic && \
    mkdir -p /models/community-forensics /models/huggingface /work/tmp && \
    chown -R forensic:forensic /models /work

USER 10001:10001

ENTRYPOINT ["python", "/app/workers/image-community/handler.py", "--runpod"]
