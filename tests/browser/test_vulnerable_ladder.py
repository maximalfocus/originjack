"""The exposure, observed in a real browser.

These only run when the operator opted in twice. What they assert is not that a header is
wrong — the unit tests cover that — but that a page on an unrelated origin ends up with
the victim's pay, bank account tail, and session token rendered in it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from originjack.harness import HarnessRun
from originjack.harness.scenarios import VICTIM_MARKERS

pytestmark = [pytest.mark.browser, pytest.mark.vulnerable, pytest.mark.demo_pass("reflect")]

ATTACKER_ORIGIN = "https://promo.attacker.example"
VULNERABLE_READ = "attacker read (vulnerable API)"
SECURE_READ = "attacker read (secure API)"


def test_the_reflection_shape_hands_the_payslip_to_the_attacker(
    harness: HarnessRun,
) -> None:
    exposed = harness.by_name(VULNERABLE_READ)

    assert exposed.calling_origin == ATTACKER_ORIGIN
    assert exposed.browser_released
    assert exposed.victim_data_rendered
    assert exposed.verdict == "vulnerable"


def test_the_server_is_what_granted_it(harness: HarnessRun) -> None:
    """The mirror image of the secure case.

    There, the server answered and the browser withheld it. Here, the server told the
    browser to hand the response to the attacker's own origin, and the browser — doing
    exactly as instructed — did.
    """
    exposed = harness.by_name(VULNERABLE_READ)

    assert exposed.decided_by == "server"
    assert exposed.observation is not None
    assert exposed.observation.status == 200
    assert exposed.observation.allow_origin == ATTACKER_ORIGIN
    assert exposed.observation.allow_credentials == "true"


def test_the_attacker_page_renders_the_victims_data(harness: HarnessRun) -> None:
    """Rendered on the page, not merely present in a response body.

    The screenshot is the artifact a reader believes; the marker check is what fails the
    build if it ever stops being true.
    """
    exposed = harness.by_name(VULNERABLE_READ)

    assert exposed.victim_data_rendered
    assert exposed.screenshot is not None
    shot = Path(harness.transcript_path).parent / exposed.screenshot
    assert shot.is_file()
    assert shot.stat().st_size > 0


def test_the_identical_page_gets_nothing_from_the_secure_api(harness: HarnessRun) -> None:
    blocked = harness.by_name(SECURE_READ)

    assert blocked.calling_origin == ATTACKER_ORIGIN
    assert not blocked.browser_released
    assert not blocked.victim_data_rendered
    assert blocked.decided_by == "browser"
    assert blocked.verdict == "secure"


def test_the_secure_api_answered_but_granted_nothing(harness: HarnessRun) -> None:
    blocked = harness.by_name(SECURE_READ)

    assert blocked.observation is not None
    assert blocked.observation.status == 200
    assert blocked.observation.allow_origin is None
    assert blocked.observation.allow_credentials is None
    assert blocked.observation.failure is not None


def test_the_two_runs_differ_only_in_which_api_answered(harness: HarnessRun) -> None:
    """Same page, same path, same credentials, same victim. One object apart."""
    exposed = harness.by_name(VULNERABLE_READ)
    blocked = harness.by_name(SECURE_READ)

    assert exposed.calling_origin == blocked.calling_origin
    assert exposed.credential_mode == blocked.credential_mode
    assert exposed.preflight == blocked.preflight
    assert exposed.observation is not None
    assert blocked.observation is not None
    assert exposed.observation.url.endswith("/me/payslip")
    assert blocked.observation.url.endswith("/me/payslip")
    assert exposed.observation.status == blocked.observation.status == 200


def test_the_transcript_names_the_exposure(harness: HarnessRun) -> None:
    assert "VERDICT: VULNERABLE" in harness.transcript
    assert VULNERABLE_READ in harness.transcript
    assert SECURE_READ in harness.transcript
    assert "opt-in" in harness.transcript


def test_no_victim_datum_appears_in_the_blocked_scenarios_record(
    harness: HarnessRun,
) -> None:
    blocked = harness.by_name(SECURE_READ)
    joined = " ".join((*blocked.notes, blocked.summary))

    for marker in VICTIM_MARKERS:
        assert marker not in joined


def test_the_legitimate_scenarios_still_pass_alongside(harness: HarnessRun) -> None:
    """The vulnerable services being up must not change the secure path's behaviour."""
    assert harness.by_name("first-party read").verdict == "secure"
    assert harness.by_name("first-party write").state_changed
    assert harness.by_name("third-party read").decided_by == "browser"
