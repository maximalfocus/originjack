#!/usr/bin/env bash
# The one supported command.
#
#   ./scripts/demo.sh                    secure baseline only (the default)
#   ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh --with-vulnerable
#
# The default builds the images (generating the throwaway demo CA and every origin's
# certificate), brings the secure origins up on the hermetic no-egress network, seeds
# fresh deterministic fixtures by starting them, runs the verification gate and then a
# real headless browser from inside that network, copies the run artifacts to
# ./artifacts, and tears everything down.
#
# `--with-vulnerable` additionally starts the intentionally vulnerable API and the
# attacker's page. That takes two deliberate actions — this flag, which selects the opt-in
# Compose profile, and ALLOW_VULNERABLE_DEMO=true, which the vulnerable application checks
# for itself. Either one alone does nothing.
#
# The host needs Docker and nothing else: no Python, no browser, no hosts-file entry, no
# trusted certificate, no published port.
set -euo pipefail

cd "$(dirname "$0")/.."

BROWSER_CONTAINER=originjack-browser-run
ARTIFACTS_DIR=artifacts
WITH_VULNERABLE=false

case "${1:-}" in
  "") ;;
  --with-vulnerable) WITH_VULNERABLE=true ;;
  *)
    echo "usage: $0 [--with-vulnerable]" >&2
    exit 64
    ;;
esac

if [ "$WITH_VULNERABLE" = true ] && [ "${ALLOW_VULNERABLE_DEMO:-}" != "true" ]; then
  cat >&2 <<'MSG'
Refusing to start the intentionally vulnerable demonstration.

--with-vulnerable selects the opt-in Compose profile. The second acknowledgement is
still missing:

    ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh --with-vulnerable

That service deliberately exposes a logged-in user's data to any origin that asks. It is
local educational material and must never be deployed.
MSG
  exit 64
fi

compose() {
  if [ "$WITH_VULNERABLE" = true ]; then
    docker compose --profile vulnerable "$@"
  else
    docker compose "$@"
  fi
}

cleanup() {
  echo
  echo "==> tearing down"
  docker rm -f "$BROWSER_CONTAINER" >/dev/null 2>&1 || true
  docker compose --profile vulnerable --profile browser --profile verify \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building the demo images (throwaway CA + per-origin certificates)"
# Both build targets are named explicitly: `browser` sits behind a Compose profile, so a
# bare `compose build` would silently skip it.
compose build api browser

# The gate that keeps the deliberately insecure service off by accident. Checked on every
# run, in both modes, because a containment control nobody exercises is a containment
# control nobody knows is broken.
echo "==> checking the vulnerable opt-in gate"
set +e
gate_output="$(docker compose --profile vulnerable run --rm --no-deps \
  -e ALLOW_VULNERABLE_DEMO= legacy-api 2>&1)"
gate_rc=$?
set -e
if [ "$gate_rc" -eq 0 ]; then
  echo "FAIL: the vulnerable API started without its acknowledgement" >&2
  exit 1
fi
if ! printf '%s' "$gate_output" | grep -q "ALLOW_VULNERABLE_DEMO"; then
  echo "FAIL: the vulnerable API failed for some other reason than the missing gate" >&2
  printf '%s\n' "$gate_output" >&2
  exit 1
fi
echo "    refused without ALLOW_VULNERABLE_DEMO=true, as it must"

if [ "$WITH_VULNERABLE" = true ]; then
  echo "==> starting the secure origins AND the opt-in vulnerable services"
  compose up --detach --wait api app partner legacy-api attacker
else
  echo "==> starting the API and the two static origins"
  compose up --detach --wait api app partner
  running_optin="$(docker compose ps --services --status running 2>/dev/null \
    | grep -E '^(legacy-api|attacker)$' || true)"
  if [ -n "$running_optin" ]; then
    echo "FAIL: the default path started an opt-in service: $running_optin" >&2
    exit 1
  fi
  echo "    no vulnerable or attacker service is running, as it must not be"
fi

echo "==> running the verification gate inside the hermetic network"
if [ "$WITH_VULNERABLE" = true ]; then
  compose run --rm --no-deps -e ORIGINJACK_INCLUDE_VULNERABLE=1 verify
else
  compose run --rm --no-deps verify
fi

echo "==> driving the demonstration through a real headless browser"
docker rm -f "$BROWSER_CONTAINER" >/dev/null 2>&1 || true
set +e
if [ "$WITH_VULNERABLE" = true ]; then
  compose run --no-deps --name "$BROWSER_CONTAINER" \
    -e ORIGINJACK_INCLUDE_VULNERABLE=1 browser
else
  compose run --no-deps --name "$BROWSER_CONTAINER" browser
fi
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
if [ "$WITH_VULNERABLE" = true ]; then
  echo "==> originjack: the vulnerable/secure contrast verified through a real browser"
else
  echo "==> originjack: secure baseline verified through a real browser"
fi
