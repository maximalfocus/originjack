"""The reflection shape, tested as the exact inverse of the secure policy.

The secure policy's defining property is that its answer comes from the server's own set.
This one's defining property is that its answer comes from the request. Both are asserted
by identity, because the two strings are equal and equality cannot tell them apart.
"""

from __future__ import annotations

import pytest

from originjack.config import FIRST_PARTY_ORIGIN, ConfigurationError, Settings
from originjack.cors import ExactMatchAllowlistPolicy, response_headers
from originjack.vulnerable_cors import ReflectedOriginPolicy, policy_for_shape
from tests.conftest import ATTACKER_ORIGINS


@pytest.fixture
def settings() -> Settings:
    return Settings(allowed_origins=(FIRST_PARTY_ORIGIN,))


@pytest.fixture
def policy(settings: Settings) -> ReflectedOriginPolicy:
    return ReflectedOriginPolicy.from_settings(settings)


@pytest.mark.parametrize("origin", ATTACKER_ORIGINS)
def test_every_origin_is_granted_with_credentials(
    policy: ReflectedOriginPolicy, origin: str
) -> None:
    decision = policy.decide(origin)

    assert decision.granted
    assert decision.allow_origin == origin
    assert decision.allow_credentials

    headers = response_headers(decision, preflight=False)
    assert headers["access-control-allow-origin"] == origin
    assert headers["access-control-allow-credentials"] == "true"


def test_the_grant_is_literally_the_request_value(policy: ReflectedOriginPolicy) -> None:
    """The exact inverse of the secure policy's guarantee.

    The secure policy returns the object held in its allowlist. This one returns the
    object the request supplied — which is the entire vulnerability, expressed as an
    identity check.
    """
    requested = "".join(["https://promo.", "attacker.", "example"])

    assert policy.decide(requested).allow_origin is requested


def test_the_secure_policy_refuses_what_this_one_grants(settings: Settings) -> None:
    """The two policies disagree about every attacker origin, and agree about the app."""
    secure = ExactMatchAllowlistPolicy.from_settings(settings)
    vulnerable = ReflectedOriginPolicy.from_settings(settings)

    for origin in ATTACKER_ORIGINS:
        assert not secure.decide(origin).granted
        assert vulnerable.decide(origin).granted

    assert secure.decide(FIRST_PARTY_ORIGIN).granted
    assert vulnerable.decide(FIRST_PARTY_ORIGIN).granted


def test_an_absent_origin_is_still_not_a_grant(policy: ReflectedOriginPolicy) -> None:
    """Even reflection has nothing to reflect when there is no Origin header."""
    decision = policy.decide(None)

    assert not decision.granted
    assert decision.allow_origin is None


def test_the_shapes_are_named_and_unknown_ones_are_refused(settings: Settings) -> None:
    assert policy_for_shape("reflect", settings).name == "vulnerable-reflected-origin"

    with pytest.raises(ConfigurationError, match="unknown vulnerable shape"):
        policy_for_shape("definitely-not-a-shape", settings)
