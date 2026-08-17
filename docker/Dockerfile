# syntax=docker/dockerfile:1
#
# Two images from one file: the service image, and the browser image built on the same
# dependency layers. That is deliberate — both inherit the single demo CA generated in
# this build, so there is exactly one trust root and no way for two services to disagree
# about it.
#
# The stage order matters for build times: dependencies and Chromium are installed before
# any source is copied, so editing a Python file rebuilds a 100ms layer rather than
# re-downloading a browser.

ARG PYTHON_IMAGE=python:3.13-slim-bookworm

# --- Throwaway demonstration CA and per-origin server certificates -------------------
FROM ${PYTHON_IMAGE} AS certs
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY docker/demo-origins.txt /tmp/demo-origins.txt
COPY docker/generate-demo-ca.sh /tmp/generate-demo-ca.sh
RUN bash /tmp/generate-demo-ca.sh /certs /tmp/demo-origins.txt

# --- Dependencies, installed from pyproject.toml alone -------------------------------
FROM ${PYTHON_IMAGE} AS deps

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

# A placeholder package, so the project installs from pyproject.toml alone and this layer
# does not depend on any source file. The install is editable, so the real sources copied
# over it later are the ones that run — and Chromium, which sits on top of this layer,
# survives every source edit.
RUN mkdir -p src/originjack \
 && touch src/originjack/__init__.py src/originjack/py.typed \
 && uv pip install --system --no-cache -e ".[dev]"

# --- Chromium, on top of dependencies and below any source ---------------------------
FROM deps AS chromium
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
# certutil (libnss3-tools) is how the demo CA is genuinely added to Chromium's own trust
# store at run time. The alternative — launching with certificate errors ignored — would
# make a demonstration about trust decisions work by switching trust off.
RUN playwright install --with-deps chromium \
 && apt-get update \
 && apt-get install -y --no-install-recommends libnss3-tools \
 && rm -rf /var/lib/apt/lists/*

# --- The service image ---------------------------------------------------------------
FROM deps AS runtime

COPY src ./src
COPY tests ./tests
COPY web ./web
COPY scripts ./scripts
COPY docs ./docs
COPY --from=certs /certs /certs

# Non-root, and the server keys are readable only by that account's group.
RUN groupadd --gid 10001 originjack \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin originjack \
 && chown -R root:10001 /certs \
 && find /certs -type d -exec chmod 0750 {} + \
 && find /certs -type f -exec chmod 0640 {} +

USER 10001:10001

CMD ["python", "-c", "print('originjack: specify a service command')"]

# --- The browser harness image -------------------------------------------------------
FROM chromium AS browser

ENV HOME=/home/originjack \
    ORIGINJACK_ARTIFACTS=/artifacts

COPY src ./src
COPY tests ./tests
COPY web ./web
COPY scripts ./scripts
COPY docs ./docs
COPY --from=certs /certs /certs

RUN groupadd --gid 10001 originjack \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin originjack \
 && chown -R root:10001 /certs \
 && find /certs -type d -exec chmod 0750 {} + \
 && find /certs -type f -exec chmod 0640 {} + \
 && mkdir -p /artifacts /home/originjack \
 && chown 10001:10001 /artifacts /home/originjack

USER 10001:10001

CMD ["bash", "scripts/verify-browser.sh"]
