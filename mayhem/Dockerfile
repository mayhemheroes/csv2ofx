# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — PYTHON target (atheris / libFuzzer). Builds ON TOP of the org
# C/C++ base (ghcr.io/mayhemheroes/base) — the base ships CPython + pip + clang (clang links the
# compiled ELF launcher that drives the Atheris harness). This adds an in-image Python wheelhouse +
# site dir under /opt/toolchains/python (so the air-gapped PATCH re-run resolves atheris/pytest/
# meza offline) and runs the per-repo mayhem/build.sh.
#
# WHY a fixed /opt/toolchains/python prefix (SPEC §6.2 items 8/9, §6.5): pip's default cache/user-
# site live under $HOME; the commit build and the PATCH re-run use DIFFERENT $HOMEs, so we pin the
# wheelhouse + site dir at fixed, $HOME-independent paths.
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] -t mytag .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never an ENV (an empty value breaks clang).
ARG SOURCE_DATE_EPOCH
# Sanitizer override (the launcher is a thin exec wrapper; Atheris instruments the Python at import).
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# ── Python toolchain caches at a FIXED, lockable, $HOME-independent prefix ─────
ENV PY_PREFIX=/opt/toolchains/python \
    PYTHONPATH=/mayhem:/opt/toolchains/python/site \
    PATH=/opt/toolchains/python/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1
USER root
RUN install -d -o 2000 -g 2000 /opt/toolchains/python
USER mayhem

WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Populates the wheelhouse (online, this first build), installs deps offline into the site dir, and
# compiles the ELF launcher + standalone reproducer + the pytest-runner wrapper.
RUN bash mayhem/build.sh

# Run the project's functional tests at build time (a failing suite fails the image build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
