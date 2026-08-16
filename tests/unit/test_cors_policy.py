"""The exact-match allowlist, tested as the security boundary it is."""

from __future__ import annotations

import inspect

import pytest

from originjack import cors
from originjack.config import FIRST_PARTY_ORIGIN, Settings
from originjack.cors import CorsDecision, ExactMatchAllowlistPolicy, response_headers
from tests.conftest import REFUSED_ORIGINS


@pytest.fixture
def policy() -> ExactMatchAllowlistPolicy:
    return ExactMatchAllowlistPolicy.from_settings(Settings(allowed_origins=(FIRST_PARTY_ORIGIN,)))


def test_allowlisted_origin_is_granted(policy: ExactMatchAllowlistPolicy) -> None:
    decision = policy.decide(FIRST_PARTY_ORIGIN)

    assert decision.granted
    assert decision.allow_origin == FIRST_PARTY_ORIGIN
    assert decision.allow_credentials


def test_grant_returns_the_allowlisted_value_not_the_requested_one(
    policy: ExactMatchAllowlistPolicy,
) -> None:
    """The response header must be built from the server's set, never from the request.

    The two strings are equal, so equality cannot tell them apart — identity can. This
    is what stops the policy from ever degenerating into origin reflection.
    """
    requested = "".join(["https://app.", "meridianpay.", "example"])
    assert requested == FIRST_PARTY_ORIGIN
    assert requested is not policy.allowed_origins[0]

    decision = policy.decide(requested)

    assert decision.allow_origin is policy.allowed_origins[0]
    assert decision.allow_origin is not requested


@pytest.mark.parametrize("origin", REFUSED_ORIGINS)
def test_non_allowlisted_origins_get_nothing(
    policy: ExactMatchAllowlistPolicy, origin: str
) -> None:
    decision = policy.decide(origin)

    assert not decision.granted
    assert decision.allow_origin is None
    assert not decision.allow_credentials
    assert response_headers(decision, preflight=False) == {}
    assert response_headers(decision, preflight=True) == {}


def test_absent_origin_is_not_a_grant(policy: ExactMatchAllowlistPolicy) -> None:
    """No ``Origin`` header is not a cross-origin request, so there is nothing to grant."""
    decision = policy.decide(None)

    assert not decision.granted
    assert decision.allow_origin is None


def test_grant_headers_are_narrow(policy: ExactMatchAllowlistPolicy) -> None:
    headers = response_headers(policy.decide(FIRST_PARTY_ORIGIN), preflight=True)

    assert headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN
    assert headers["access-control-allow-credentials"] == "true"
    assert headers["access-control-allow-methods"] == "GET, POST"
    assert headers["access-control-allow-headers"] == "content-type, x-meridian-csrf"
    assert headers["access-control-max-age"] == "60"


def test_non_preflight_grant_omits_preflight_headers(policy: ExactMatchAllowlistPolicy) -> None:
    headers = response_headers(policy.decide(FIRST_PARTY_ORIGIN), preflight=False)

    assert set(headers) == {"access-control-allow-origin", "access-control-allow-credentials"}


def test_a_refused_decision_cannot_carry_a_grant() -> None:
    with pytest.raises(ValueError, match="must carry no grant"):
        CorsDecision(granted=False, allow_origin="https://promo.attacker.example")

    with pytest.raises(ValueError, match="must carry no grant"):
        CorsDecision(granted=False, allow_credentials=True)


def test_the_decision_path_contains_no_pattern_matching() -> None:
    """The acceptance boundary forbids substring, prefix, suffix, and regex matching.

    Asserted against the source of the decision itself, because "we only compare whole
    strings" is exactly the property that erodes silently during a later change.
    """
    source = inspect.getsource(ExactMatchAllowlistPolicy)
    forbidden = (
        "startswith",
        "endswith",
        "fnmatch",
        "re.match",
        "re.search",
        "re.compile",
        "re.fullmatch",
        "regex",
        ".find(",
        ".index(",
        ".replace(",
        ".strip(",
        ".lower(",
        ".removeprefix(",
        ".removesuffix(",
    )
    for token in forbidden:
        assert token not in source, f"{token!r} has no place in the origin decision"

    module_source = inspect.getsource(cors)
    assert "import re" not in module_source
    assert "import fnmatch" not in module_source
