"""What a real browser does with the secure API's answers.

Runs inside the browser container, on the hermetic network, with the demo CA imported
into Chromium's own trust store. The whole harness runs once for the session; each test
then interrogates one recorded outcome.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from originjack.config import FIRST_PARTY_ORIGIN
from originjack.harness import HarnessRun
from originjack.harness.scenarios import CHANGED_ACCOUNT_TAIL, VICTIM_MARKERS
from originjack.harness.transcript import ENGINE_NOTES

pytestmark = pytest.mark.browser


# --- the lab itself -------------------------------------------------------------------


def test_the_run_used_a_real_pinned_chromium(harness: HarnessRun) -> None:
    assert harness.engine.startswith("chromium ")
    assert harness.engine.split()[1][0].isdigit()


def test_pages_loaded_over_https_with_the_demo_ca_actually_trusted(
    harness: HarnessRun,
) -> None:
    """Certificate errors are not ignored, so a page loading at all proves the trust.

    If the throwaway CA had not been imported into Chromium's NSS store, every
    navigation in this run would have failed at the TLS handshake instead.
    """
    read = harness.by_name("first-party read")
    assert read.calling_origin.startswith("https://")
    assert read.observation is not None
    assert read.observation.url.startswith("https://")


# --- the allowlisted origin -----------------------------------------------------------


def test_the_allowlisted_origin_completes_the_credentialed_read(harness: HarnessRun) -> None:
    read = harness.by_name("first-party read")

    assert read.browser_released
    assert read.victim_data_rendered
    assert read.observation is not None
    assert read.observation.status == 200
    assert read.observation.allow_origin == FIRST_PARTY_ORIGIN
    assert read.observation.allow_credentials == "true"
    assert read.verdict == "secure"


def test_the_allowlisted_origin_completes_the_csrf_protected_write(
    harness: HarnessRun,
) -> None:
    write = harness.by_name("first-party write")

    assert write.browser_released
    assert write.state_changed
    assert write.observation is not None
    assert write.observation.status == 200
    assert write.verdict == "secure"


def test_the_write_was_preceded_by_a_real_preflight(harness: HarnessRun) -> None:
    """Observed, not assumed: a non-simple request cannot reach the route without one."""
    assert harness.by_name("first-party write").preflight is True


def test_the_simple_read_needed_no_preflight(harness: HarnessRun) -> None:
    assert harness.by_name("first-party read").preflight is False


# --- the origin the allowlist does not name -------------------------------------------


def test_the_third_party_read_is_blocked_by_the_browser(harness: HarnessRun) -> None:
    blocked = harness.by_name("third-party read")

    assert not blocked.browser_released
    assert not blocked.victim_data_rendered
    assert blocked.decided_by == "browser"
    assert blocked.verdict == "secure"


def test_the_server_answered_and_the_browser_withheld_it(harness: HarnessRun) -> None:
    """The distinction the whole project exists to make legible.

    The request was sent and the server responded. What stopped the page reading that
    response was the absence of ``Access-Control-Allow-Origin`` — enforced by the
    browser, in the browser, after the bytes had already arrived.
    """
    blocked = harness.by_name("third-party read")
    assert blocked.observation is not None

    # The server answered in full...
    assert blocked.observation.server_answered
    assert blocked.observation.status == 200
    # ...with no grant of any kind...
    assert blocked.observation.allow_origin is None
    assert blocked.observation.allow_credentials is None
    # ...and all the page was ever told is that its request failed.
    assert blocked.observation.failure is not None


def test_the_session_cookie_was_carried_on_the_cross_site_request(
    harness: HarnessRun,
) -> None:
    """The credential reached the API, so nothing but the header stood in the way.

    Worth pinning: had the browser withheld the cookie under a third-party cookie
    policy, the server would have answered 401 and this run would be demonstrating a
    different protection than the one it claims to.
    """
    blocked = harness.by_name("third-party read")
    assert blocked.observation is not None
    assert blocked.observation.status == 200, (
        "the cross-site request was unauthenticated; the origin policy is not what this "
        "run observed being enforced"
    )


def test_no_victim_datum_reached_the_third_party_page(harness: HarnessRun) -> None:
    blocked = harness.by_name("third-party read")
    joined = " ".join((*blocked.notes, blocked.summary))

    assert not blocked.victim_data_rendered
    for marker in VICTIM_MARKERS:
        assert marker not in joined


# --- run artifacts --------------------------------------------------------------------


def test_the_transcript_is_written_and_readable(harness: HarnessRun) -> None:
    path = Path(harness.transcript_path)

    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert text == harness.transcript
    assert harness.engine in text
    for result in harness.results:
        assert result.name in text


def test_the_transcript_records_the_engine_and_its_known_differences(
    harness: HarnessRun,
) -> None:
    for note in ENGINE_NOTES:
        assert note in harness.transcript


def test_every_scenario_produced_a_screenshot(harness: HarnessRun) -> None:
    root = Path(harness.transcript_path).parent

    for result in harness.results:
        assert result.screenshot is not None
        shot = root / result.screenshot
        assert shot.is_file(), result.name
        assert shot.stat().st_size > 0, result.name


def test_the_run_left_the_fixture_where_it_found_it(harness: HarnessRun) -> None:
    """The write scenario restores the original tail, so runs are repeatable."""
    write = harness.by_name("first-party write")

    assert CHANGED_ACCOUNT_TAIL in " ".join(write.notes) or write.state_changed
    assert any("restored" in note for note in write.notes)
    assert not any("RESTORE FAILED" in note for note in write.notes)
