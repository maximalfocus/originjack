#!/usr/bin/env bash
# The one supported command.
#
#   ./scripts/demo.sh
#
# Builds the images (which generate the throwaway demo CA and every origin's
# certificate), brings the origins up on the hermetic no-egress network, seeds fresh
# deterministic fixtures by starting them, runs the verification gate and then the real
# headless browser from inside that network, copies the run artifacts to ./artifacts,
# reports the result, and tears everything down again.
#
# The host needs Docker and nothing else: no Python, no browser, no hosts-file entry, no
# trusted certificate, no published port.
set -euo pipefail

cd "$(dirname "$0")/.."

BROWSER_CONTAINER=originjack-browser-run
ARTIFACTS_DIR=artifacts

compose() { docker compose "$@"; }

cleanup() {
  echo
  echo "==> tearing down"
  docker rm -f "$BROWSER_CONTAINER" >/dev/null 2>&1 || true
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building the demo images (throwaway CA + per-origin certificates)"
# Both build targets are named explicitly: `browser` sits behind a Compose profile, so a
# bare `compose build` would silently skip it.
compose build api browser

echo "==> starting the API and the two static origins"
compose up --detach --wait api app partner

echo "==> running the verification gate inside the hermetic network"
compose run --rm --no-deps verify

echo "==> driving the demonstration through a real headless browser"
docker rm -f "$BROWSER_CONTAINER" >/dev/null 2>&1 || true
set +e
compose run --no-deps --name "$BROWSER_CONTAINER" browser
browser_rc=$?
set -e

# Copy the transcript and screenshots out before anything is removed — they are most
# useful precisely when the run failed. `docker cp` writes as the host user, so the
# artifacts land readable without loosening permissions anywhere.
mkdir -p "$ARTIFACTS_DIR"
if docker container inspect "$BROWSER_CONTAINER" >/dev/null 2>&1; then
  docker cp "$BROWSER_CONTAINER:/artifacts/." "$ARTIFACTS_DIR/" >/dev/null 2>&1 \
    && echo "==> run artifacts copied to ./$ARTIFACTS_DIR"
  docker rm -f "$BROWSER_CONTAINER" >/dev/null 2>&1 || true
fi

if [ "$browser_rc" -ne 0 ]; then
  echo "==> browser harness failed (exit $browser_rc); see ./$ARTIFACTS_DIR" >&2
  exit "$browser_rc"
fi

echo
echo "==> originjack: secure baseline verified through a real browser"
