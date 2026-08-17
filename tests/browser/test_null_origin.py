"""Shape 3 — an exact-match allowlist with one entry too many.

This shape does everything right except the one thing. It compares whole strings against
a fixed server-side set. `null` is simply in that set — and `null` is not an origin, it
is what the browser sends when a document has none, which any page can arrange in a
single HTML attribute.
"""

from __future__ import annotations

import pytest

from originjack.harness import HarnessRun

pytestmark = [pytest.mark.browser, pytest.mark.vulnerable, pytest.mark.demo_pass("null")]

FRAME_VULNERABLE = "null origin — sandboxed frame"
FRAME_SECURE = "null origin — sandboxed frame vs secure API"
PLAIN = "null origin — plain attacker origin"


def test_the_sandboxed_frame_obtains_the_payslip(harness: HarnessRun) -> None:
    exposed = harness.by_name(FRAME_VULNERABLE)

    assert exposed.browser_released
    assert exposed.victim_data_rendered
    assert exposed.verdict == "vulnerable"
    assert exposed.decided_by == "server"


def test_the_response_granted_the_null_origin(harness: HarnessRun) -> None:
    exposed = harness.by_name(FRAME_VULNERABLE)

    assert exposed.observation is not None
    assert exposed.observation.status == 200
    assert exposed.observation.allow_origin == "null"
    assert exposed.observation.allow_credentials == "true"


def test_the_browser_reported_the_frames_origin_as_null(harness: HarnessRun) -> None:
    """Observed, not inferred from the `sandbox` attribute.

    The frame posts its result to its parent, and the browser stamps that message with
    the frame's origin. For an opaque origin, that stamp is the string `null` — the same
    value that went out in the request header.
    """
    exposed = harness.by_name(FRAME_VULNERABLE)
    notes = " ".join(exposed.notes)

    assert "reported that frame's origin to its parent as: null" in notes


def test_the_transcript_does_not_claim_this_shape_echoed_anything(
    harness: HarnessRun,
) -> None:
    """This shape does not reflect. Saying it did would describe shape 1 instead.

    It compares whole strings against a fixed set, exactly as a correct policy does. The
    fault is one entry in that set, and the wording has to say so or the reader learns
    the wrong lesson about a policy that looks right.
    """
    exposed = harness.by_name(FRAME_VULNERABLE)

    assert exposed.decider_detail is not None
    assert "in its accepted set" in exposed.decider_detail
    assert "echoed" not in exposed.decider_detail


def test_the_secure_api_refuses_the_null_origin(harness: HarnessRun) -> None:
    blocked = harness.by_name(FRAME_SECURE)

    assert not blocked.browser_released
    assert not blocked.victim_data_rendered
    assert blocked.decided_by == "browser"
    assert blocked.verdict == "secure"
    assert blocked.observation is not None
    assert blocked.observation.allow_origin is None


def test_the_shape_still_refuses_a_named_attacker_origin(harness: HarnessRun) -> None:
    """Which is exactly why one extra entry is so easy to wave through in review."""
    blocked = harness.by_name(PLAIN)

    assert not blocked.browser_released
    assert not blocked.victim_data_rendered
    assert blocked.observation is not None
    assert blocked.observation.allow_origin is None


def test_the_transcript_covers_all_three_shapes_in_one_document(
    harness: HarnessRun,
) -> None:
    """The final pass renders every scenario the run produced, in order."""
    for shape in (
        "shape 1 — origin reflection with credentials",
        "shape 2 — sloppy allowlist match",
        "shape 3 — allowlisted `null` origin",
    ):
        assert shape in harness.transcript

    for name in ("first-party read", "third-party read", FRAME_VULNERABLE):
        assert name in harness.transcript
