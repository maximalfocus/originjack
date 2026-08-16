#!/usr/bin/env bash
# The verification gate, run inside the container by `docker compose run --rm verify`.
# Local verification and GitHub Actions both reach this file through that one command,
# so there is only ever one gate to keep green.
set -euo pipefail

cd /app

echo "==> ruff (lint)"
ruff check .

echo "==> ruff (format)"
ruff format --check .

echo "==> mypy"
mypy

echo "==> pytest"
pytest

echo "==> verification gate passed"
