"""The two negative controls and the `SameSite` contrast, in a real browser.

Each of these corrects a belief people hold confidently, so each has to be shown rather
than stated — and shown in a way that makes the *reason* legible, not just the outcome.
"""

from __future__ import annotations

import pytest

from originjack.harness import HarnessRun

WILDCARD = "wildcard with credentials"
SIMPLE_POST_VULNERABLE = "simple cross-origin POST — vulnerable API"
SIMPLE_POST_SECURE = "simple cross-origin POST — secure API"
SAMESITE = "SameSite=Lax contrast"


# --- FR-011: the wildcard is refused by the browser, not by the server ----------------


@pytest.mark.browser
@pytest.mark.vulnerable
@pytest.mark.demo_pass("wildcard")
class TestWildcardWithCredentials:
    def test_the_read_fails_in_the_browser(self, harness: HarnessRun) -> None:
        control = harness.by_name(WILDCARD)

        assert not control.browser_released
        assert not control.victim_data_rendered
        assert control.decided_by == "browser"

    def test_the_server_granted_every_origin_and_asked_for_credentials(
        self, harness: HarnessRun
    ) -> None:
        """The distinction that makes this a control rather than another exposure.

        The secure API refuses by sending *no* grant. This server sent the widest grant
        there is — and the browser still refused, because the specification forbids the
        combination. Nothing was refused server-side at all.
        """
        control = harness.by_name(WILDCARD)

        assert control.observation is not None
        assert control.observation.status == 200
        assert control.observation.allow_origin == "*"
        assert control.observation.allow_credentials == "true"
        assert control.observation.failure is not None

    def test_the_record_says_the_wildcard_is_not_the_dangerous_shape(
        self, harness: HarnessRun
    ) -> None:
        notes = " ".join(harness.by_name(WILDCARD).notes)

        assert "not the dangerous shape" in notes
        assert "not evidence of a correct policy" in notes

    def test_the_record_does_not_claim_the_server_withheld_the_header(
        self, harness: HarnessRun
    ) -> None:
        """It sent the widest header there is. Saying otherwise describes a different bug."""
        notes = " ".join(harness.by_name(WILDCARD).notes)

        assert "with no Access-Control-Allow-Origin" not in notes
        assert "It granted everyone; the browser refused the combination." in notes

    def test_it_breaks_the_legitimate_application_too(self, harness: HarnessRun) -> None:
        """Observed, not asserted: the refusal is indiscriminate.

        A wildcard with credentials is not a lax policy that happens to be safe — it is a
        policy under which nothing credentialed works at all.
        """
        notes = " ".join(harness.by_name(WILDCARD).notes)

        assert "The refusal is indiscriminate" in notes
        assert "blocked:" in notes
        assert "it is a broken one" in notes


# --- FR-012: a simple request lands, with no preflight --------------------------------


@pytest.mark.browser
@pytest.mark.vulnerable
@pytest.mark.demo_pass("simple-post")
class TestSimpleRequestControl:
    def test_no_preflight_was_sent(self, harness: HarnessRun) -> None:
        """Observed on the wire. A simple request has nothing to ask permission for."""
        assert harness.by_name(SIMPLE_POST_VULNERABLE).preflight is False
        assert harness.by_name(SIMPLE_POST_SECURE).preflight is False

    def test_the_attacker_could_not_read_the_response(self, harness: HarnessRun) -> None:
        """Which is exactly the reassurance this control exists to remove."""
        landed = harness.by_name(SIMPLE_POST_VULNERABLE)

        assert not landed.browser_released
        assert not landed.victim_data_rendered

    def test_it_changed_the_victims_payout_account_anyway(self, harness: HarnessRun) -> None:
        landed = harness.by_name(SIMPLE_POST_VULNERABLE)
        notes = " ".join(landed.notes)

        assert landed.state_changed
        assert landed.verdict == "vulnerable"
        assert "payout account tail went from" in notes
        assert "changed the victim's bank details anyway" in notes

    def test_the_secure_api_refused_it_and_state_is_unchanged(self, harness: HarnessRun) -> None:
        refused = harness.by_name(SIMPLE_POST_SECURE)

        assert not refused.state_changed
        assert refused.verdict == "secure"
        assert refused.observation is not None
        assert refused.observation.status == 415
        assert "Canonical state is unchanged" in " ".join(refused.notes)

    def test_the_record_never_says_the_secure_api_granted_anything(
        self, harness: HarnessRun
    ) -> None:
        """It refused the write and granted no origin. Both halves must read that way."""
        refused = harness.by_name(SIMPLE_POST_SECURE)

        assert refused.decider_detail is not None
        assert "refused the write" in refused.decider_detail
        assert "granted" not in refused.decider_detail
        assert refused.observation is not None
        assert refused.observation.allow_origin is None

    def test_the_vulnerable_record_says_it_asked_nothing_about_the_caller(
        self, harness: HarnessRun
    ) -> None:
        landed = harness.by_name(SIMPLE_POST_VULNERABLE)

        assert landed.decider_detail is not None
        assert "asking nothing about where the request came from" in landed.decider_detail


# --- FR-013: SameSite withholds the credential, not the read --------------------------


@pytest.mark.browser
@pytest.mark.vulnerable
@pytest.mark.demo_pass("samesite-lax")
class TestSameSiteContrast:
    def test_the_cross_origin_read_still_succeeded(self, harness: HarnessRun) -> None:
        """The misconfiguration is untouched, and the browser still handed the page a
        response. That is the half everybody forgets."""
        contrast = harness.by_name(SAMESITE)

        assert contrast.browser_released
        assert contrast.observation is not None
        assert contrast.observation.allow_origin == "https://promo.attacker.example"
        assert contrast.observation.allow_credentials == "true"

    def test_but_it_carried_no_victim_data(self, harness: HarnessRun) -> None:
        contrast = harness.by_name(SAMESITE)

        assert not contrast.victim_data_rendered
        assert contrast.observation is not None
        assert contrast.observation.status == 401
        assert contrast.verdict == "secure"

    def test_the_record_says_which_protection_actually_acted(self, harness: HarnessRun) -> None:
        notes = " ".join(harness.by_name(SAMESITE).notes)

        assert "withholds the credential" in notes
        assert "does not repair the origin policy" in notes
        assert "SameSite=None; Secure" in notes

    def test_the_decider_line_reflects_the_shape_not_an_allowlist(
        self, harness: HarnessRun
    ) -> None:
        contrast = harness.by_name(SAMESITE)

        assert contrast.decider_detail is not None
        assert "echoed the caller's own origin" in contrast.decider_detail
        assert "allowlist" not in contrast.decider_detail
