"""The browser-driven scenarios.

Every outcome recorded here is produced by Chromium executing the pages' own JavaScript
against the real network. Nothing in this module asserts a response header and calls it a
result: the header is captured as *supporting* evidence beside what the page could
actually render.

The secure-path scenarios always run. The vulnerable ladder runs only when the operator
opted in twice, and then once per misconfiguration shape, because the shapes are mutually
exclusive.
"""

from __future__ import annotations

from collections.abc import Callable
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

DEMO_PASSWORD: Final = _VICTIM.demo_password

PAYSLIP_PATH: Final = "/me/payslip"
PAYOUT_PATH: Final = "/me/payout-account"

ORIGINAL_ACCOUNT_TAIL: Final = "8842"
CHANGED_ACCOUNT_TAIL: Final = "7311"

_SETTLED = 'body:not([data-outcome="pending"])'
_PAYOUT_SETTLED = 'body[data-payout="updated"], body[data-payout="refused"]'


def _rendered_victim_data(page: Page) -> bool:
    text = page.inner_text("body")
    return any(marker in text for marker in VICTIM_MARKERS)


def first_party_read(lab: BrowserLab, *, index: int) -> tuple[ScenarioResult, Page, NetworkLog]:
    """The allowlisted origin performs the credentialed cross-origin payslip read."""
    page, log = lab.open(f"{lab.settings.app_origin}/")
    page.wait_for_selector(_SETTLED)

    outcome = page.get_attribute("body", "data-outcome")
    released = outcome == "released"
    rendered = _rendered_victim_data(page)
    observation = log.observation_for(PAYSLIP_PATH)
    screenshot = lab.capture(page, f"{index:02d}-first-party-read")

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


def first_party_write(
    lab: BrowserLab, page: Page, log: NetworkLog, *, index: int
) -> ScenarioResult:
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
    screenshot = lab.capture(page, f"{index:02d}-first-party-write")

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


def third_party_read(lab: BrowserLab, *, index: int) -> ScenarioResult:
    """An origin the allowlist does not name makes the identical credentialed read."""
    page, log = lab.open(f"{lab.settings.partner_origin}/")
    page.wait_for_selector(_SETTLED)

    outcome = page.get_attribute("body", "data-outcome")
    released = outcome == "released"
    rendered = _rendered_victim_data(page)
    observation = log.observation_for(PAYSLIP_PATH)
    screenshot = lab.capture(page, f"{index:02d}-third-party-read-blocked")
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


def run_secure_baseline(lab: BrowserLab, *, start: int = 1) -> list[ScenarioResult]:
    """Run every secure-path scenario, in one browser context, in order."""
    read_result, page, log = first_party_read(lab, index=start)
    write_result = first_party_write(lab, page, log, index=start + 1)
    page.close()
    blocked_result = third_party_read(lab, index=start + 2)
    return [read_result, write_result, blocked_result]


# --- the vulnerable ladder ------------------------------------------------------------
#
# Only reachable when the operator opted in twice. The three shapes are mutually
# exclusive — shape 2's whole lesson is that the plain attacker origin is *blocked* under
# it — so the vulnerable API is recreated between them and the harness runs once per
# shape, accumulating into one transcript.

SHAPE_LABELS: Final[dict[str, str]] = {
    "reflect": "shape 1 — origin reflection with credentials",
    "sloppy": "shape 2 — sloppy allowlist match",
    "null": "shape 3 — allowlisted `null` origin",
}

#: How each shape actually granted, in its own terms. The three fail differently, and one
#: phrasing for all of them would misdescribe two.
GRANT_BASIS: Final[dict[str, str]] = {
    "reflect": "it echoed the caller's own origin back as an allowed one",
    "sloppy": (
        "the caller's hostname contained the corporate domain, which is all its "
        "unanchored match asked for"
    ),
    "null": "`null` was in its accepted set, and any page can arrange to send it",
}


def _api_origin(lab: BrowserLab, target: str) -> str:
    return lab.settings.vulnerable_api_origin if target == "vulnerable" else lab.settings.api_origin


def attacker_read(
    lab: BrowserLab,
    *,
    name: str,
    attacker_origin: str,
    target: str,
    index: int,
    shape: str,
    mode: str = "direct",
    extra_notes: tuple[str, ...] = (),
) -> ScenarioResult:
    """The attacker's page performs the credentialed cross-origin read.

    One page, two query parameters, and everything that follows is decided by the
    response headers the API chose to send.
    """
    api_origin = _api_origin(lab, target)
    slug = attacker_origin.removeprefix("https://").replace(".", "-")
    page, log = lab.open(f"{attacker_origin}/?api={target}&mode={mode}")

    page.wait_for_selector(_SETTLED)

    released = page.get_attribute("body", "data-outcome") == "released"
    rendered = _rendered_victim_data(page)
    frame_origin = page.get_attribute("body", "data-frame-origin") or None
    observation = log.observation_for(PAYSLIP_PATH)
    screenshot = lab.capture(page, f"{index:02d}-{shape}-{slug}-{target}")
    page.close()

    notes = list(extra_notes)
    if mode == "iframe":
        notes.append(
            'The read was made from a frame created with sandbox="allow-scripts" and no '
            "allow-same-origin, so the browser has no origin to report for it."
        )
        if frame_origin:
            notes.append(
                f"The browser reported that frame's origin to its parent as: {frame_origin}."
            )
    if released and observation is not None:
        notes.append(
            f"{api_origin} answered {observation.status} with Access-Control-Allow-Origin: "
            f"{observation.allow_origin} and Access-Control-Allow-Credentials: "
            f"{observation.allow_credentials}, so the browser released the response."
        )
        notes.append(
            "The victim's net pay, payout-account tail, and session API token are now "
            "rendered on a page the payroll provider has never heard of."
        )
    elif observation is not None:
        notes.append(
            f"{api_origin} answered {observation.status} with no "
            "Access-Control-Allow-Origin, so the browser withheld the response and the "
            "page obtained nothing."
        )
    if observation is not None and observation.failure:
        notes.append(f"The page was told only: {observation.failure}.")

    return ScenarioResult(
        name=name,
        summary=(
            f"{attacker_origin} attempts the victim's payslip from {api_origin} "
            f"(the {target} deployment), with the victim's own session cookie."
        ),
        calling_origin=attacker_origin if mode == "direct" else f"{attacker_origin} (sandboxed)",
        credential_mode="include",
        preflight=log.saw_preflight(PAYSLIP_PATH),
        browser_released=released,
        victim_data_rendered=rendered and released,
        state_changed=False,
        # When the data is released, the *server* decided that. When it is withheld, the
        # browser did.
        decided_by="server" if released else "browser",
        verdict="vulnerable" if (released and rendered) else "secure",
        observation=observation,
        screenshot=screenshot,
        shape=SHAPE_LABELS.get(shape, shape),
        decider_detail=GRANT_BASIS.get(shape) if released else None,
        notes=tuple(notes),
    )


def _sign_in_everywhere(lab: BrowserLab) -> None:
    for origin in (lab.settings.vulnerable_api_origin, lab.settings.api_origin):
        lab.sign_in(origin, employee_id=VICTIM_EMPLOYEE_ID, demo_password=DEMO_PASSWORD)


def run_reflect_shape(lab: BrowserLab, *, start: int) -> list[ScenarioResult]:
    """Shape 1: the exposure, then the identical attempt against the API that gets it right."""
    _sign_in_everywhere(lab)
    return [
        attacker_read(
            lab,
            name="attacker read (vulnerable API)",
            attacker_origin=lab.settings.attacker_origin,
            target="vulnerable",
            index=start,
            shape="reflect",
        ),
        attacker_read(
            lab,
            name="attacker read (secure API)",
            attacker_origin=lab.settings.attacker_origin,
            target="secure",
            index=start + 1,
            shape="reflect",
        ),
    ]


def run_sloppy_shape(lab: BrowserLab, *, start: int) -> list[ScenarioResult]:
    """Shape 2: the plain attacker origin is blocked, and two lookalikes are not."""
    _sign_in_everywhere(lab)
    return [
        attacker_read(
            lab,
            name="sloppy match — plain attacker origin",
            attacker_origin=lab.settings.attacker_origin,
            target="vulnerable",
            index=start,
            shape="sloppy",
            extra_notes=(
                "This is the reassuring result, and it is the trap. The obvious attack "
                "stopped working, so the configuration looks repaired. Nothing has been "
                "repaired.",
            ),
        ),
        attacker_read(
            lab,
            name="sloppy match — prefix lookalike",
            attacker_origin=lab.settings.attacker_prefix_origin,
            target="vulnerable",
            index=start + 1,
            shape="sloppy",
            extra_notes=(
                "The corporate domain appears in the middle of a hostname the attacker "
                "owns outright, which is all an unanchored match asks for.",
            ),
        ),
        attacker_read(
            lab,
            name="sloppy match — suffix lookalike",
            attacker_origin=lab.settings.attacker_suffix_origin,
            target="vulnerable",
            index=start + 2,
            shape="sloppy",
            extra_notes=(
                "And here it appears at the end of one. A check that forgot the leading "
                "dot cannot tell these two domains apart.",
            ),
        ),
        attacker_read(
            lab,
            name="sloppy match — prefix lookalike vs secure API",
            attacker_origin=lab.settings.attacker_prefix_origin,
            target="secure",
            index=start + 3,
            shape="sloppy",
        ),
        attacker_read(
            lab,
            name="sloppy match — suffix lookalike vs secure API",
            attacker_origin=lab.settings.attacker_suffix_origin,
            target="secure",
            index=start + 4,
            shape="sloppy",
        ),
    ]


def run_null_shape(lab: BrowserLab, *, start: int) -> list[ScenarioResult]:
    """Shape 3: an exact-match allowlist with one entry too many."""
    _sign_in_everywhere(lab)
    return [
        attacker_read(
            lab,
            name="null origin — sandboxed frame",
            attacker_origin=lab.settings.attacker_origin,
            target="vulnerable",
            index=start,
            shape="null",
            mode="iframe",
            extra_notes=(
                "This shape compares whole strings against a fixed server-side set, "
                "exactly as it should. Someone added one entry to that set.",
            ),
        ),
        attacker_read(
            lab,
            name="null origin — sandboxed frame vs secure API",
            attacker_origin=lab.settings.attacker_origin,
            target="secure",
            index=start + 1,
            shape="null",
            mode="iframe",
        ),
        attacker_read(
            lab,
            name="null origin — plain attacker origin",
            attacker_origin=lab.settings.attacker_origin,
            target="vulnerable",
            index=start + 2,
            shape="null",
            extra_notes=(
                "Blocked, because this shape really does compare whole origins. That is "
                "what makes the one extra entry so easy to wave through in review.",
            ),
        ),
    ]


SHAPE_RUNNERS: Final[dict[str, Callable[..., list[ScenarioResult]]]] = {
    "reflect": run_reflect_shape,
    "sloppy": run_sloppy_shape,
    "null": run_null_shape,
}
