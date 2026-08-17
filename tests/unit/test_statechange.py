"""What each deployment demands before it will change anything.

CORS decides whether a page may *read* a response. It has never decided whether a request
is *processed*, which is why this is a separate policy object and why the two deployments
differ in it.
"""

from __future__ import annotations

from typing import TypedDict

import pytest

from originjack.sessions import Session
from originjack.statechange import (
    CsrfProtectedWrites,
    Refusal,
    SessionOnlyWrites,
    StateChangePolicy,
)

SESSION = Session(
    session_id="s", employee_id="EMP-4417", expires_at=9_999_999_999, csrf_token="the-token"
)


class Attempt(TypedDict):
    media_type: str
    presented_csrf: str | None


#: The shape a cross-site request can take without triggering a preflight: a
#: CORS-safelisted content type and no custom header.
SIMPLE_REQUEST: Attempt = {"media_type": "text/plain", "presented_csrf": None}

#: What the secure route actually demands.
NON_SIMPLE_REQUEST: Attempt = {"media_type": "application/json", "presented_csrf": "the-token"}


def test_the_secure_policy_refuses_a_simple_request() -> None:
    refusal = CsrfProtectedWrites().refuse(session=SESSION, **SIMPLE_REQUEST)

    assert refusal == Refusal(415, "unsupported_media_type")


@pytest.mark.parametrize(
    "media_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""]
)
def test_the_secure_policy_refuses_every_safelisted_content_type(media_type: str) -> None:
    """Requiring a non-simple content type is what forces a preflight to exist at all."""
    refusal = CsrfProtectedWrites().refuse(
        media_type=media_type, presented_csrf="the-token", session=SESSION
    )

    assert refusal is not None
    assert refusal.status_code == 415


@pytest.mark.parametrize("presented", [None, "", "wrong"])
def test_the_secure_policy_refuses_a_missing_or_wrong_csrf_token(presented: str | None) -> None:
    refusal = CsrfProtectedWrites().refuse(
        media_type="application/json", presented_csrf=presented, session=SESSION
    )

    assert refusal == Refusal(403, "forbidden")


def test_the_secure_policy_admits_a_non_simple_request_with_a_matching_token() -> None:
    assert (
        CsrfProtectedWrites().refuse(
            media_type="application/json", presented_csrf="the-token", session=SESSION
        )
        is None
    )


def test_the_legacy_policy_admits_the_simple_request() -> None:
    """The whole point of the control: nothing here asks where the request came from."""
    assert SessionOnlyWrites().refuse(session=SESSION, **SIMPLE_REQUEST) is None


def test_the_two_policies_disagree_only_about_the_request_shape() -> None:
    assert CsrfProtectedWrites().refuse(session=SESSION, **NON_SIMPLE_REQUEST) is None
    assert SessionOnlyWrites().refuse(session=SESSION, **NON_SIMPLE_REQUEST) is None

    assert CsrfProtectedWrites().refuse(session=SESSION, **SIMPLE_REQUEST) is not None
    assert SessionOnlyWrites().refuse(session=SESSION, **SIMPLE_REQUEST) is None


@pytest.mark.parametrize("policy", [CsrfProtectedWrites(), SessionOnlyWrites()])
def test_both_satisfy_the_policy_protocol(policy: StateChangePolicy) -> None:
    assert isinstance(policy, StateChangePolicy)
    assert policy.name
