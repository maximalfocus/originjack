"""The browser-driven scenarios.

Every outcome recorded here is produced by Chromium executing the pages' own JavaScript
against the real network. Nothing in this module asserts a response header and calls it a
result: the header is captured as *supporting* evidence beside what the page could
actually render.

This slice runs the secure API only. The vulnerable ladder and its negative controls are
added beside these scenarios in a later slice.
"""

from __future__ import annotations

from typing import Final

from playwright.sync_api import Page

from originjack.domain import FIXTURE_EMPLOYEES, VICTIM_EMPLOYEE_ID
from originjack.harness.lab import BrowserLab, NetworkLog
from originjack.harness.models import ScenarioResult

_VICTIM: Final = next(e for e in FIXTURE_EMPLOYEES if e.employee_id == VICTIM_EMPLOYEE_ID)

#: Strings that exist only in the victim's payslip. If any appears in a page's rendered
#: text, that page obtained victim data. Sourced from the fixtures so they cannot drift.
VICTIM_MARKERS: Final[tuple[str, ...]] = (
    _VICTIM.api_token,
    _VICTIM.payslip.tax_reference,
)

PAYSLIP_PATH: Final = "/me/payslip"
PAYOUT_PATH: Final = "/me/payout-account"

ORIGINAL_ACCOUNT_TAIL: Final = "8842"
CHANGED_ACCOUNT_TAIL: Final = "7311"

_SETTLED = 'body:not([data-outcome="pending"])'
_PAYOUT_SETTLED = 'body[data-payout="updated"], body[data-payout="refused"]'


def _rendered_victim_data(page: Page) -> bool:
    text = page.inner_text("body")
    return any(marker in text for marker in VICTIM_MARKERS)


def first_party_read(lab: BrowserLab) -> tuple[ScenarioResult, Page, NetworkLog]:
    """The allowlisted origin performs the credentialed cross-origin payslip read."""
    page, log = lab.open(f"{lab.settings.app_origin}/")
    page.wait_for_selector(_SETTLED)

    outcome = page.get_attribute("body", "data-outcome")
    released = outcome == "released"
    rendered = _rendered_victim_data(page)
    observation = log.observation_for(PAYSLIP_PATH)
    screenshot = lab.capture(page, "01-first-party-read")

    result = ScenarioResult(
        name="first-party read",
        summary=(
            "The allowlisted first-party application reads the victim's payslip "
            "cross-origin, with credentials."
        ),
        calling_origin=lab.settings.app_origin,
        credential_mode="include",
        preflight=log.saw_preflight(PAYSLIP_PATH),
        browser_released=released,
        victim_data_rendered=rendered and released,
        state_changed=False,
        decided_by="server",
        verdict="secure",
        observation=observation,
        screenshot=screenshot,
        notes=(
            "The allowlist names this origin verbatim, so the response carries "
            "Access-Control-Allow-Origin and the browser releases it.",
            "This is the behaviour the fix must preserve, not an exposure.",
        ),
    )
    return result, page, log


def first_party_write(lab: BrowserLab, page: Page, log: NetworkLog) -> ScenarioResult:
    """The same page performs the CSRF-protected payout-account change.

    The harness restores the original fixture value afterwards, so a run is repeatable
    and leaves the demonstration's canonical state where it found it.
    """
    page.fill("#account-tail", CHANGED_ACCOUNT_TAIL)
    page.click("#payout-form button[type=submit]")
    page.wait_for_selector(_PAYOUT_SETTLED)

    payout_outcome = page.get_attribute("body", "data-payout")
    payout_text = page.inner_text("#payout")
    changed = payout_outcome == "updated" and CHANGED_ACCOUNT_TAIL in payout_text
    observation = log.observation_for(PAYOUT_PATH)
    preflight = log.saw_preflight(PAYOUT_PATH)
    screenshot = lab.capture(page, "02-first-party-write")

    restored = _restore_account_tail(page)

    return ScenarioResult(
        name="first-party write",
        summary=(
            "The allowlisted first-party application changes the payout account through "
            "the CSRF-protected route."
        ),
        calling_origin=lab.settings.app_origin,
        credential_mode="include",
        preflight=preflight,
        browser_released=payout_outcome == "updated",
        victim_data_rendered=False,
        state_changed=changed,
        decided_by="server",
        verdict="secure",
        observation=observation,
        screenshot=screenshot,
        notes=(
            "A JSON content type and the X-Meridian-CSRF header make this a non-simple "
            "request, so the browser sent a preflight first.",
            f"The fixture was restored to ••••{ORIGINAL_ACCOUNT_TAIL} after the change "
            f"({'restored' if restored else 'RESTORE FAILED'}), so the run is repeatable.",
        ),
    )


def _restore_account_tail(page: Page) -> bool:
    page.fill("#account-tail", ORIGINAL_ACCOUNT_TAIL)
    page.click("#payout-form button[type=submit]")
    page.wait_for_selector(_PAYOUT_SETTLED)
    return page.get_attribute(
        "body", "data-payout"
    ) == "updated" and ORIGINAL_ACCOUNT_TAIL in page.inner_text("#payout")


def third_party_read(lab: BrowserLab) -> ScenarioResult:
    """An origin the allowlist does not name makes the identical credentialed read."""
    page, log = lab.open(f"{lab.settings.partner_origin}/")
    page.wait_for_selector(_SETTLED)

    outcome = page.get_attribute("body", "data-outcome")
    released = outcome == "released"
    rendered = _rendered_victim_data(page)
    observation = log.observation_for(PAYSLIP_PATH)
    screenshot = lab.capture(page, "03-third-party-read-blocked")
    page.close()

    server_answered = observation is not None and observation.server_answered
    notes = [
        "Same URL, same method, same credentials, same session. Only the Origin differs.",
    ]
    if server_answered and observation is not None:
        notes.append(
            f"The server answered this request with HTTP {observation.status} and no "
            "Access-Control-Allow-Origin. The response reached the browser; the browser "
            "is what refused to hand it to the page."
        )
    if observation is not None and observation.failure:
        notes.append(f"The browser reported the request to the page as: {observation.failure}.")
    if observation is not None and observation.status == 200:
        notes.append(
            "The session cookie was carried on this cross-site request, so the server "
            "produced the victim's full payslip. Nothing but the missing header stood "
            "between this page and that data."
        )
    elif observation is not None and observation.status == 401:
        notes.append(
            "The browser did not carry the session cookie on this cross-site request, so "
            "the server answered 401. That is the browser's cookie policy, which is a "
            "separate protection from the origin policy — the read was refused here "
            "either way."
        )

    return ScenarioResult(
        name="third-party read",
        summary=(
            "An unrelated origin the allowlist does not name attempts the identical "
            "credentialed cross-origin payslip read."
        ),
        calling_origin=lab.settings.partner_origin,
        credential_mode="include",
        preflight=log.saw_preflight(PAYSLIP_PATH),
        browser_released=released,
        victim_data_rendered=rendered and released,
        state_changed=False,
        decided_by="browser",
        verdict="secure",
        observation=observation,
        screenshot=screenshot,
        notes=tuple(notes),
    )


def run_secure_baseline(lab: BrowserLab) -> list[ScenarioResult]:
    """Run every scenario this slice covers, in one browser context, in order."""
    read_result, page, log = first_party_read(lab)
    write_result = first_party_write(lab, page, log)
    page.close()
    blocked_result = third_party_read(lab)
    return [read_result, write_result, blocked_result]
