#!/usr/bin/env bash
# The one supported command.
#
#   ./scripts/demo.sh
#
# Builds the image (which generates the throwaway demo CA and every origin's
# certificate), brings up the secure API and the first-party application on the hermetic
# no-egress network, seeds fresh deterministic fixtures by starting them, runs the full
# verification gate from inside that network, reports the result, and tears everything
# down again.
#
# The host needs Docker and nothing else: no Python, no browser, no hosts-file entry, no
# trusted certificate, no published port.
set -euo pipefail

cd "$(dirname "$0")/.."

compose() { docker compose "$@"; }

cleanup() {
  echo
  echo "==> tearing down"
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building the demo image (throwaway CA + per-origin certificates)"
compose build

echo "==> starting the secure API and the first-party application"
compose up --detach --wait api app

echo "==> running the verification gate inside the hermetic network"
compose run --rm --no-deps verify

echo
echo "==> originjack: secure baseline verified"
