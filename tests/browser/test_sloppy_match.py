"""Shape 2 — the fix that isn't.

The assertion that matters here is not that a lookalike origin gets through. It is that
the *plain* attacker origin is blocked at the same time, because that is what makes this
shape more dangerous than plain reflection: it produces evidence of having been fixed.
"""

from __future__ import annotations

import pytest

from originjack.harness import HarnessRun

pytestmark = [pytest.mark.browser, pytest.mark.vulnerable, pytest.mark.demo_pass("sloppy")]

PLAIN = "sloppy match — plain attacker origin"
PREFIX = "sloppy match — prefix lookalike"
SUFFIX = "sloppy match — suffix lookalike"
PREFIX_SECURE = "sloppy match — prefix lookalike vs secure API"
SUFFIX_SECURE = "sloppy match — suffix lookalike vs secure API"


def test_the_plain_attacker_origin_is_now_blocked(harness: HarnessRun) -> None:
    """The reassuring result. Nothing has been repaired."""
    plain = harness.by_name(PLAIN)

    assert not plain.browser_released
    assert not plain.victim_data_rendered
    assert plain.observation is not None
    assert plain.observation.allow_origin is None


def test_the_prefix_lookalike_walks_straight_through(harness: HarnessRun) -> None:
    """`app.meridianpay.example.attacker.example` belongs entirely to the attacker."""
    exposed = harness.by_name(PREFIX)

    assert exposed.calling_origin == "https://app.meridianpay.example.attacker.example"
    assert exposed.browser_released
    assert exposed.victim_data_rendered
    assert exposed.verdict == "vulnerable"
    assert exposed.observation is not None
    assert exposed.observation.allow_origin == exposed.calling_origin
    assert exposed.observation.allow_credentials == "true"


def test_the_suffix_lookalike_walks_straight_through(harness: HarnessRun) -> None:
    """`notmeridianpay.example` is a different domain that ends the same way."""
    exposed = harness.by_name(SUFFIX)

    assert exposed.calling_origin == "https://notmeridianpay.example"
    assert exposed.browser_released
    assert exposed.victim_data_rendered
    assert exposed.verdict == "vulnerable"
    assert exposed.observation is not None
    assert exposed.observation.allow_origin == exposed.calling_origin


def test_the_shape_blocks_and_grants_in_the_same_run(harness: HarnessRun) -> None:
    """Both facts have to be true at once, or the demonstration proves nothing.

    A shape that grants everything is shape 1. This one has to refuse the obvious attack
    *and* admit the lookalikes, in the same configuration, for the lesson to land.
    """
    plain = harness.by_name(PLAIN)
    prefix = harness.by_name(PREFIX)
    suffix = harness.by_name(SUFFIX)

    assert not plain.browser_released
    assert prefix.browser_released
    assert suffix.browser_released
    assert plain.shape == prefix.shape == suffix.shape


@pytest.mark.parametrize("name", [PREFIX_SECURE, SUFFIX_SECURE])
def test_the_secure_api_refuses_both_lookalikes(harness: HarnessRun, name: str) -> None:
    blocked = harness.by_name(name)

    assert not blocked.browser_released
    assert not blocked.victim_data_rendered
    assert blocked.decided_by == "browser"
    assert blocked.verdict == "secure"
    assert blocked.observation is not None
    assert blocked.observation.allow_origin is None


def test_the_transcript_names_the_shape(harness: HarnessRun) -> None:
    assert "shape 2 — sloppy allowlist match" in harness.transcript
    # The earlier pass's scenarios are still there: one transcript, not fragments.
    assert "attacker read (vulnerable API)" in harness.transcript
