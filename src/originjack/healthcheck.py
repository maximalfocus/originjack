"""Container healthcheck: fetch one URL over HTTPS and exit non-zero unless it is 200.

Run inside the container by Compose, so the host needs no HTTP client, no certificate
trust, and no published port.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

import httpx

from originjack.demo_ca import ssl_context

TIMEOUT_SECONDS = 5.0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m originjack.healthcheck URL", file=sys.stderr)
        return 64

    try:
        response = httpx.get(args[0], verify=ssl_context(), timeout=TIMEOUT_SECONDS)
    except (httpx.HTTPError, OSError) as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1

    return 0 if response.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
