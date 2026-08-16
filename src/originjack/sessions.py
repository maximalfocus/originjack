"""Demo-only session credentials.

A session is a signed, self-describing token rather than a server-side handle. That is a
deliberate demonstration choice: the reader can mint an expired or tampered credential
with the published demo key and watch the API answer all four failure shapes — missing,
malformed, expired, unknown — with one indistinguishable ``401`` (FR-002).

This is not production session management, and the module says so out loud. Real
services should not publish their signing key in their own source tree.
"""

from __future__ import annotations

import base64
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Final

TOKEN_VERSION: Final = "v1"
_SEPARATOR: Final = "."


class SessionError(Exception):
    """Base class for every credential rejection. All map to the same generic 401."""


class MalformedSessionError(SessionError):
    """Structure, encoding, or signature is wrong."""


class ExpiredSessionError(SessionError):
    """Signature is valid but the credential has passed its expiry."""


@dataclass(frozen=True, slots=True)
class Session:
    """A decoded demo session."""

    session_id: str
    employee_id: str
    expires_at: int
    csrf_token: str


def now_epoch() -> int:
    return int(datetime.now(tz=UTC).timestamp())


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(payload: str, *, key: str) -> str:
    digest = hmac.new(key.encode("utf-8"), payload.encode("ascii"), sha256).digest()
    return _b64url_encode(digest)


def issue(
    employee_id: str,
    *,
    ttl_seconds: int,
    now: int | None = None,
) -> Session:
    """Mint a fresh session for ``employee_id``.

    The session identifier and CSRF token are random per login — they are credentials,
    not fixtures — while everything the demonstration renders stays deterministic.
    """
    issued_at = now_epoch() if now is None else now
    return Session(
        session_id=secrets.token_urlsafe(12),
        employee_id=employee_id,
        expires_at=issued_at + ttl_seconds,
        csrf_token=secrets.token_urlsafe(24),
    )


def encode(session: Session, *, key: str) -> str:
    """Serialize a session into its cookie value."""
    body: dict[str, Any] = {
        "sid": session.session_id,
        "emp": session.employee_id,
        "exp": session.expires_at,
        "csrf": session.csrf_token,
    }
    payload = _b64url_encode(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return _SEPARATOR.join((TOKEN_VERSION, payload, _sign(payload, key=key)))


def decode(token: str, *, key: str, now: int | None = None) -> Session:
    """Parse and validate a cookie value.

    Raises:
        MalformedSessionError: structure, encoding, or signature failure.
        ExpiredSessionError: valid signature, expiry in the past.
    """
    parts = token.split(_SEPARATOR)
    if len(parts) != 3:
        raise MalformedSessionError("expected three token segments")

    version, payload, signature = parts
    if version != TOKEN_VERSION:
        raise MalformedSessionError(f"unsupported token version {version!r}")

    if not hmac.compare_digest(signature, _sign(payload, key=key)):
        raise MalformedSessionError("signature mismatch")

    try:
        body = json.loads(_b64url_decode(payload))
    except (ValueError, json.JSONDecodeError) as exc:
        raise MalformedSessionError("undecodable payload") from exc

    if not isinstance(body, dict):
        raise MalformedSessionError("payload is not an object")

    try:
        session = Session(
            session_id=str(body["sid"]),
            employee_id=str(body["emp"]),
            expires_at=int(body["exp"]),
            csrf_token=str(body["csrf"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MalformedSessionError("payload is missing required claims") from exc

    if session.expires_at <= (now_epoch() if now is None else now):
        raise ExpiredSessionError("session has expired")

    return session


def csrf_token_matches(session: Session, presented: str | None) -> bool:
    """Constant-time comparison of the presented CSRF token against the session's."""
    if not presented:
        return False
    return hmac.compare_digest(session.csrf_token, presented)
