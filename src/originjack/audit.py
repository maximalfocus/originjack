"""Structured, secret-free audit logging.

Two properties are enforced here rather than left to reviewer discipline:

* every record is a single line of deterministic JSON on standard output, so it can be
  correlated and counted by an operator or a test; and
* credential-bearing field names are rejected at the call site, so a cookie, session
  token, API token, or authorization header cannot reach the log by accident (FR-002,
  FR-014, NFR-003).
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import Any, Final, TextIO

#: Field names that must never be logged. Checked case-insensitively against every
#: keyword passed to :func:`emit`.
FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "api_token",
        "authorization",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "csrf",
        "csrf_token",
        "password",
        "secret",
        "session",
        "session_cookie",
        "session_token",
        "set-cookie",
        "set_cookie",
        "token",
    }
)

#: Emitted once per cross-origin request the secure API declines to grant (FR-014).
ORIGIN_REFUSED_EVENT: Final = "cors.origin_refused"

#: Emitted once per completed request, carrying no header or credential material.
REQUEST_COMPLETED_EVENT: Final = "http.request_completed"


class ForbiddenAuditFieldError(ValueError):
    """Raised when a caller tries to log a credential-bearing field."""


def _timestamp() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def emit(event: str, /, *, stream: TextIO | None = None, **fields: Any) -> dict[str, Any]:
    """Write one structured JSON audit record and return it.

    Raises:
        ForbiddenAuditFieldError: if any field name is credential-bearing.
    """
    offending = sorted(name for name in fields if name.lower() in FORBIDDEN_FIELDS)
    if offending:
        raise ForbiddenAuditFieldError(
            f"refusing to log credential-bearing field(s): {', '.join(offending)}"
        )

    record: dict[str, Any] = {"ts": _timestamp(), "event": event, **fields}
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    print(line, file=stream if stream is not None else sys.stdout, flush=True)
    return record


def emit_origin_refused(
    *,
    request_id: str,
    method: str,
    path: str,
    origin: str,
    preflight: bool,
    stream: TextIO | None = None,
) -> dict[str, Any]:
    """Record that a cross-origin response was withheld from a non-allowlisted origin.

    The record names the *refused* origin and nothing else about the policy: it never
    reveals the allowlist, never names an accepted origin, and never carries session
    material. Client-visible behaviour is unchanged by it, so it is not an oracle.
    """
    return emit(
        ORIGIN_REFUSED_EVENT,
        stream=stream,
        request_id=request_id,
        method=method,
        path=path,
        refused_origin=origin,
        preflight=preflight,
        outcome="cross_origin_response_withheld",
        reason="origin_not_allowlisted",
    )


def emit_request_completed(
    *,
    request_id: str,
    method: str,
    path: str,
    status_code: int,
    cross_origin: bool,
    stream: TextIO | None = None,
) -> dict[str, Any]:
    """Record a completed request without any header, cookie, or body material."""
    return emit(
        REQUEST_COMPLETED_EVENT,
        stream=stream,
        request_id=request_id,
        method=method,
        path=path,
        status_code=status_code,
        cross_origin=cross_origin,
    )
