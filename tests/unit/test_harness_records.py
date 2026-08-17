"""The harness's records and transcript, without needing a browser.

These run in the ordinary verification container so the invariants stay cheap to check.
"""

from __future__ import annotations

import pytest

from originjack.harness.models import NetworkObservation, ScenarioResult
from originjack.harness.transcript import ENGINE_NOTES, render


def _result(**overrides: object) -> ScenarioResult:
    base: dict[str, object] = {
        "name": "third-party read",
        "summary": "An unrelated origin attempts the identical credentialed read.",
        "calling_origin": "https://partner.othercorp.example",
        "credential_mode": "include",
        "preflight": False,
        "browser_released": False,
        "victim_data_rendered": False,
        "state_changed": False,
        "decided_by": "browser",
        "verdict": "secure",
    }
    base.update(overrides)
    return ScenarioResult(**base)  # type: ignore[arg-type]


def test_victim_data_cannot_be_rendered_from_a_withheld_response() -> None:
    """The record refuses to describe an impossible outcome.

    A page cannot render what the browser never handed it, so a result claiming both is
    a bug in the harness rather than a finding about the server.
    """
    with pytest.raises(ValueError, match="withheld"):
        _result(browser_released=False, victim_data_rendered=True)


def test_a_released_response_may_render_victim_data() -> None:
    assert _result(browser_released=True, victim_data_rendered=True).victim_data_rendered


def test_an_observation_knows_whether_the_server_answered() -> None:
    answered = NetworkObservation(url="https://api.meridianpay.example/me/payslip", status=200)
    never = NetworkObservation(
        url="https://api.meridianpay.example/me/payslip", failure="net::ERR_FAILED"
    )

    assert answered.server_answered
    assert not never.server_answered


def test_an_observation_describes_absent_cors_headers_explicitly() -> None:
    described = NetworkObservation(
        url="https://api.meridianpay.example/me/payslip",
        status=200,
        failure="net::ERR_FAILED",
    ).describe()

    assert "status=200" in described
    assert "ACAO=(absent)" in described
    assert "ACAC=(absent)" in described
    assert "net::ERR_FAILED" in described


def test_the_transcript_names_the_engine_the_decider_and_the_verdict() -> None:
    text = render(
        [
            _result(
                observation=NetworkObservation(
                    url="https://api.meridianpay.example/me/payslip", status=200
                ),
                screenshot="screenshots/03-third-party-read-blocked.png",
                notes=("Only the Origin differs.",),
            )
        ],
        engine="chromium 131.0.0.0",
        generated_at="2026-08-17T00:00:00+00:00",
        subject="the secure API only",
    )

    assert "chromium 131.0.0.0" in text
    assert "VERDICT: SECURE" in text
    assert "THE BROWSER" in text
    assert "screenshots/03-third-party-read-blocked.png" in text
    assert "Only the Origin differs." in text
    assert "1 scenarios — 1 secure, 0 vulnerable" in text
    for note in ENGINE_NOTES:
        assert note in text


def test_the_transcript_never_credits_an_allowlist_the_server_does_not_have() -> None:
    """The reflection shape grants without comparing anything, and the wording must say so.

    Describing it as "the allowlist granted it" would quietly teach the opposite of the
    lesson — that the vulnerable server made a decision, when its whole problem is that
    it made none.
    """
    reflected = render(
        [
            _result(
                calling_origin="https://promo.attacker.example",
                browser_released=True,
                victim_data_rendered=True,
                decided_by="server",
                verdict="vulnerable",
                decider_detail="it echoed the caller's own origin back as an allowed one",
                observation=NetworkObservation(
                    url="https://legacy-api.meridianpay.example/me/payslip",
                    status=200,
                    allow_origin="https://promo.attacker.example",
                    allow_credentials="true",
                ),
            )
        ],
        engine="chromium 131.0.0.0",
        generated_at="2026-08-17T00:00:00+00:00",
        subject="x",
    )

    assert "VERDICT: VULNERABLE" in reflected
    assert "THE SERVER" in reflected
    assert "echoed the caller's own origin" in reflected
    assert "allowlist" not in reflected


def test_the_transcript_distinguishes_an_observed_preflight_from_none() -> None:
    sent = render(
        [_result(preflight=True)],
        engine="chromium 131.0.0.0",
        generated_at="2026-08-17T00:00:00+00:00",
        subject="x",
    )
    not_sent = render(
        [_result(preflight=False)],
        engine="chromium 131.0.0.0",
        generated_at="2026-08-17T00:00:00+00:00",
        subject="x",
    )

    assert "yes (observed)" in sent
    assert "no (none sent)" in not_sent
