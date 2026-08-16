"""Demo session credentials: one indistinguishable rejection for every failure shape."""

from __future__ import annotations

import base64
import json

import pytest

from originjack import sessions
from originjack.config import DEMO_SESSION_SIGNING_KEY
from originjack.sessions import (
    ExpiredSessionError,
    MalformedSessionError,
    Session,
    csrf_token_matches,
    decode,
    encode,
    issue,
)

KEY = DEMO_SESSION_SIGNING_KEY


def test_issue_and_roundtrip() -> None:
    session = issue("EMP-4417", ttl_seconds=3600, now=1_000_000)

    assert session.employee_id == "EMP-4417"
    assert session.expires_at == 1_003_600

    decoded = decode(encode(session, key=KEY), key=KEY, now=1_000_001)
    assert decoded == session


def test_session_identifiers_are_not_fixtures() -> None:
    """Credentials are random per login; only the *rendered* payloads are deterministic."""
    first = issue("EMP-4417", ttl_seconds=60)
    second = issue("EMP-4417", ttl_seconds=60)

    assert first.session_id != second.session_id
    assert first.csrf_token != second.csrf_token


def test_expired_session_is_rejected() -> None:
    session = issue("EMP-4417", ttl_seconds=60, now=1_000_000)
    token = encode(session, key=KEY)

    with pytest.raises(ExpiredSessionError):
        decode(token, key=KEY, now=1_000_061)


def test_expiry_boundary_is_exclusive() -> None:
    session = issue("EMP-4417", ttl_seconds=60, now=1_000_000)
    token = encode(session, key=KEY)

    with pytest.raises(ExpiredSessionError):
        decode(token, key=KEY, now=session.expires_at)

    assert decode(token, key=KEY, now=session.expires_at - 1) == session


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-token",
        "v1.only-two",
        "v1.a.b.c",
        "v2.payload.signature",
        "v1.!!!not-base64!!!.signature",
    ],
    ids=[
        "empty",
        "unstructured",
        "too-few-segments",
        "too-many-segments",
        "unsupported-version",
        "bad-signature",
    ],
)
def test_malformed_tokens_are_rejected(token: str) -> None:
    with pytest.raises(MalformedSessionError):
        decode(token, key=KEY)


def test_signature_is_key_bound() -> None:
    token = encode(issue("EMP-4417", ttl_seconds=60), key=KEY)

    with pytest.raises(MalformedSessionError):
        decode(token, key="a-different-demo-key")


def test_tampered_payload_is_rejected() -> None:
    session = issue("EMP-4417", ttl_seconds=60)
    version, payload, signature = encode(session, key=KEY).split(".")

    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["emp"] = "EMP-2093"
    forged = (
        base64.urlsafe_b64encode(json.dumps(body, sort_keys=True).encode()).decode().rstrip("=")
    )

    with pytest.raises(MalformedSessionError):
        decode(".".join((version, forged, signature)), key=KEY)


def test_payload_without_claims_is_rejected() -> None:
    payload = base64.urlsafe_b64encode(b'{"sid":"x"}').decode().rstrip("=")
    token = ".".join(("v1", payload, sessions._sign(payload, key=KEY)))

    with pytest.raises(MalformedSessionError):
        decode(token, key=KEY)


def test_non_object_payload_is_rejected() -> None:
    payload = base64.urlsafe_b64encode(b"[1, 2, 3]").decode().rstrip("=")
    token = ".".join(("v1", payload, sessions._sign(payload, key=KEY)))

    with pytest.raises(MalformedSessionError):
        decode(token, key=KEY)


@pytest.mark.parametrize("presented", [None, "", "wrong", "  "])
def test_csrf_mismatch(presented: str | None) -> None:
    session = Session(
        session_id="s", employee_id="EMP-4417", expires_at=1, csrf_token="the-real-token"
    )
    assert not csrf_token_matches(session, presented)


def test_csrf_match() -> None:
    session = Session(
        session_id="s", employee_id="EMP-4417", expires_at=1, csrf_token="the-real-token"
    )
    assert csrf_token_matches(session, "the-real-token")
