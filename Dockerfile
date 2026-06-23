# CodeScan engine image — published to ghcr.io/yourorg/codescan
#
# This image is intentionally platform-agnostic: it only reads source code
# from /workspace and writes SARIF/JSON to an output directory. It knows
# nothing about GitHub, PRs, or Actions — that's the composite action's
# job (see codescan-action/action.yml, a separate repo when published).
# This separation is what lets the exact same image back a future
# GitLab/Bitbucket adapter without any changes here.

FROM python:3.12-slim AS base

# git: some lockfile/manifest parsing paths shell out to it for VCS-pinned
# dependencies. build-essential: semgrep's own transitive deps need a C
# toolchain on some platforms; removed from the final layer via slim base +
# no-cache pip installs, so it doesn't bloat the published image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (separate layer from app code so
# `docker build` cache hits on dependency-only changes are fast).
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the actual engine package and CLI entrypoint.
COPY engine/ ./engine/
COPY main.py ./main.py

# Run as a non-root user inside the container — defense in depth even
# though this container only ever reads a mounted volume and writes to
# another mounted volume; no reason to run as root for that.
RUN useradd --create-home --shell /bin/bash scanner \
    && chown -R scanner:scanner /app
USER scanner

# Disable semgrep's own telemetry/version-check network calls by default;
# this is a belt-and-suspenders env default in case any call site forgets
# to pass --metrics off explicitly.
ENV SEMGREP_SEND_METRICS=off
ENV PYTHONUNBUFFERED=1

# Force a UTF-8 default encoding inside the container. python:3.12-slim is
# Debian-based and does NOT generate/set a locale by default — it boots
# into the POSIX/C locale, whose preferred encoding is ASCII, not UTF-8.
# Without this, anything inside the container that relies on the platform
# default encoding (e.g. a subprocess.run(text=True) call without an
# explicit encoding=) would be exposed to the same class of decode crash
# that surfaces on Windows hosts with a non-UTF-8 code page — just
# triggered by the container's own locale instead of the host's. PYTHONUTF8
# additionally forces Python's own text-mode I/O (open(), print(), etc.)
# into UTF-8 mode regardless of what LANG resolves to, so this holds even
# if the base image's locale story changes in a future update.
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PYTHONUTF8=1

# main.py's container-mode contract (--repo / --out / --repo-uri) is what
# the codescan-action composite action's `docker run` invocation relies on
# — see action.yml. The container always exits 0 in this mode; the actual
# pass/fail gate decision is made downstream by evaluate_gate.py.
ENTRYPOINT ["python3", "/app/main.py"]
