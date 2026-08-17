"""The reflection shape, tested as the exact inverse of the secure policy.

The secure policy's defining property is that its answer comes from the server's own set.
This one's defining property is that its answer comes from the request. Both are asserted
by identity, because the two strings are equal and equality cannot tell them apart.
"""

from __future__ import annotations

import pytest

from originjack.config import FIRST_PARTY_ORIGIN, ConfigurationError, Settings
from originjack.cors import ExactMatchAllowlistPolicy, response_headers
from originjack.vulnerable_cors import (
    NullOriginPolicy,
    ReflectedOriginPolicy,
    SloppyMatchPolicy,
    policy_for_shape,
)
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


# --- shape 2: the sloppy allowlist match ----------------------------------------------

PLAIN_ATTACKER = "https://promo.attacker.example"
PREFIX_LOOKALIKE = "https://app.meridianpay.example.attacker.example"
SUFFIX_LOOKALIKE = "https://notmeridianpay.example"


@pytest.fixture
def sloppy(settings: Settings) -> SloppyMatchPolicy:
    return SloppyMatchPolicy.from_settings(settings)


def test_the_sloppy_shape_blocks_the_obvious_attack(sloppy: SloppyMatchPolicy) -> None:
    """Which is the entire problem: it produces evidence of having been fixed."""
    assert not sloppy.decide(PLAIN_ATTACKER).granted


@pytest.mark.parametrize("origin", [PREFIX_LOOKALIKE, SUFFIX_LOOKALIKE])
def test_the_sloppy_shape_admits_lookalikes(sloppy: SloppyMatchPolicy, origin: str) -> None:
    decision = sloppy.decide(origin)

    assert decision.granted
    assert decision.allow_origin == origin
    assert decision.allow_credentials


def test_the_sloppy_shape_keeps_the_real_app_working(sloppy: SloppyMatchPolicy) -> None:
    """Nobody notices, because the thing everybody tests still works."""
    assert sloppy.decide(FIRST_PARTY_ORIGIN).granted


def test_the_sloppy_shape_blocks_and_grants_at_once(sloppy: SloppyMatchPolicy) -> None:
    """Both facts in one configuration, which is what shape 1 cannot do."""
    assert not sloppy.decide(PLAIN_ATTACKER).granted
    assert sloppy.decide(PREFIX_LOOKALIKE).granted
    assert sloppy.decide(SUFFIX_LOOKALIKE).granted


def test_the_sloppy_shape_refuses_null_and_absent_origins(sloppy: SloppyMatchPolicy) -> None:
    assert not sloppy.decide("null").granted
    assert not sloppy.decide(None).granted


# --- shape 3: the allowlisted null origin ---------------------------------------------


@pytest.fixture
def null_shape(settings: Settings) -> NullOriginPolicy:
    return NullOriginPolicy.from_settings(settings)


def test_the_null_shape_grants_the_literal_null_origin(null_shape: NullOriginPolicy) -> None:
    decision = null_shape.decide("null")

    assert decision.granted
    assert decision.allow_origin == "null"
    assert decision.allow_credentials


def test_the_null_shape_is_otherwise_an_exact_match_allowlist(
    null_shape: NullOriginPolicy, settings: Settings
) -> None:
    """It differs from the secure policy by exactly one entry, and no other behaviour."""
    secure = ExactMatchAllowlistPolicy.from_settings(settings)

    for origin in (*ATTACKER_ORIGINS, PREFIX_LOOKALIKE, SUFFIX_LOOKALIKE, "*", ""):
        assert null_shape.decide(origin).granted == secure.decide(origin).granted

    assert null_shape.decide(FIRST_PARTY_ORIGIN).granted
    assert secure.decide(FIRST_PARTY_ORIGIN).granted

    # The one difference.
    assert null_shape.decide("null").granted
    assert not secure.decide("null").granted


def test_the_null_shape_returns_the_allowlisted_value(null_shape: NullOriginPolicy) -> None:
    """Still no reflection — it just has one entry that everybody can match."""
    requested = "".join(["nu", "ll"])

    assert null_shape.decide(requested).allow_origin is not requested
    assert null_shape.decide(requested).allow_origin == "null"


def test_every_shape_is_reachable_by_name(settings: Settings) -> None:
    assert policy_for_shape("sloppy", settings).name == "vulnerable-sloppy-match"
    assert policy_for_shape("null", settings).name == "vulnerable-null-origin"
