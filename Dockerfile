# CodeScan engine image — published to ghcr.io/yourorg/codescan
#
# This image is intentionally platform-agnostic: it only reads source code
# from /workspace and writes SARIF/JSON to an output directory. It knows
# nothing about GitHub, PRs, or Actions — that's the composite action's
# job (see ../action.yml in the codescan-action repo). This separation is
# what lets the exact same image back a future GitLab/Bitbucket adapter
# without any changes here.

FROM python:3.12-slim AS base

# Semgrep needs a small amount of build tooling for some of its own
# dependencies on certain platforms; kept minimal and removed from the
# final layer via slim base + no-cache pip installs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (separate layer from app code so
# `docker build` cache hits on dependency-only changes are fast).
COPY requirements-runtime.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the actual engine package.
COPY scanner/ ./scanner/
COPY aggregator/ ./aggregator/
COPY patcher/ ./patcher/
COPY sarif/ ./sarif/
COPY docker/entrypoint.py ./docker/entrypoint.py

# Run as a non-root user inside the container — defense in depth even
# though this container only ever reads a mounted volume and writes to
# another mounted volume; no reason to run as root for that.
RUN useradd --create-home --shell /bin/bash scanner \
    && chown -R scanner:scanner /app
USER scanner

# Disable semgrep's own telemetry/version-check network calls by default;
# the entrypoint also passes --metrics off explicitly at call sites, this
# is a belt-and-suspenders env default for anything that doesn't.
ENV SEMGREP_SEND_METRICS=off
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "/app/docker/entrypoint.py"]
