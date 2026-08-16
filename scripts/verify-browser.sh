#!/usr/bin/env bash
# The browser stage of the verification gate, run inside the browser container by
# `docker compose run --no-deps browser`.
#
# Lint and type checking already ran over this code in the main stage; this stage exists
# to drive a real Chromium against the running origins and to leave a transcript and
# screenshots behind.
set -euo pipefail

cd /app

echo "==> browser harness"
pytest tests/browser

transcript="${ORIGINJACK_ARTIFACTS:-/artifacts}/transcript.txt"
if [ -f "$transcript" ]; then
  echo
  cat "$transcript"
fi

echo "==> browser gate passed"
