# syntax=docker/dockerfile:1
#
# One image serves every role in the demonstration — the secure API, each static origin,
# and the verification runner. That is deliberate: it guarantees all origins share the
# single demo CA generated in this build, so there is exactly one trust root and no way
# for two services to disagree about it.

ARG PYTHON_IMAGE=python:3.13-slim-bookworm

# --- Throwaway demonstration CA and per-origin server certificates -------------------
FROM ${PYTHON_IMAGE} AS certs
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY docker/demo-origins.txt /tmp/demo-origins.txt
COPY docker/generate-demo-ca.sh /tmp/generate-demo-ca.sh
RUN bash /tmp/generate-demo-ca.sh /certs /tmp/demo-origins.txt

# --- Runtime -------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    MYPY_CACHE_DIR=/tmp/mypy \
    RUFF_CACHE_DIR=/tmp/ruff \
    PYTEST_ADDOPTS="-p no:cacheprovider"

WORKDIR /app

RUN pip install --no-cache-dir "uv==0.5.14"

COPY pyproject.toml README.md ./
COPY src ./src
RUN uv pip install --system --no-cache ".[dev]"

COPY tests ./tests
COPY web ./web
COPY scripts ./scripts
COPY --from=certs /certs /certs

# Non-root, and the server keys are readable only by that account's group.
RUN groupadd --gid 10001 originjack \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin originjack \
 && chown -R root:10001 /certs \
 && find /certs -type d -exec chmod 0750 {} + \
 && find /certs -type f -exec chmod 0640 {} +

USER 10001:10001

CMD ["python", "-c", "print('originjack: specify a service command')"]

# --- Browser harness -----------------------------------------------------------------
# Built FROM the runtime stage, so it carries the *same* /certs layer — and therefore the
# same demo CA — as every other service. Only this image pays for Chromium.
FROM runtime AS browser

USER root

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    HOME=/home/originjack \
    ORIGINJACK_ARTIFACTS=/artifacts

# certutil (libnss3-tools) is how the demo CA is genuinely added to Chromium's own trust
# store at run time. The alternative — launching with certificate errors ignored — would
# make a demonstration about trust decisions work by switching trust off.
RUN playwright install --with-deps chromium \
 && apt-get update \
 && apt-get install -y --no-install-recommends libnss3-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /artifacts /home/originjack \
 && chown 10001:10001 /artifacts /home/originjack

USER 10001:10001

CMD ["bash", "scripts/verify-browser.sh"]
