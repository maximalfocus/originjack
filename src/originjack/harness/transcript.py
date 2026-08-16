"""Rendering a run as something a person can read.

The transcript is a run artifact, not a log. It should let someone who was not watching
tell, for each scenario, what the server sent, what the browser did, what the page could
show, and which component decided.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from originjack.harness.models import ScenarioResult

WIDTH: Final = 88
LABEL: Final = 22

#: One engine is pinned, so anything known to differ elsewhere is stated rather than
#: silently generalized.
ENGINE_NOTES: Final[tuple[str, ...]] = (
    "This harness pins Chromium and claims nothing about any other engine.",
    "Third-party cookie policy is the behaviour most likely to differ. WebKit's "
    "Intelligent Tracking Prevention and Firefox's Total Cookie Protection withhold or "
    "partition cookies on cross-site requests by default, and Chromium has its own "
    "phase-out. Where the cookie is withheld, a cross-site read returns an "
    "unauthenticated response: the origin policy is unchanged and still decides whether "
    "the page may read it — only the credential is missing.",
    "The text a blocked fetch reports to page script is engine-specific (Chromium says "
    "'Failed to fetch'); the refusal itself is not.",
)


def _decided_by(result: ScenarioResult) -> str:
    """Describe the decider using only what this run actually observed.

    The interesting claim — that the server answered and the browser withheld the answer
    — is only made when the response was seen on the wire.
    """
    if result.decided_by == "server":
        return "the server's allowlist granted it, and the browser honoured the grant"

    observation = result.observation
    if observation is not None and observation.server_answered:
        return (
            f"THE BROWSER — the server answered {observation.status}; "
            "the browser withheld that answer from the page"
        )
    return "THE BROWSER — the page was refused the response"


def _field(label: str, value: str) -> str:
    return f"    {label.ljust(LABEL)}{value}"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _preflight(value: bool | None) -> str:
    if value is None:
        return "—"
    return "yes (observed)" if value else "no (none sent)"


def render(
    results: Sequence[ScenarioResult],
    *,
    engine: str,
    generated_at: str,
    subject: str,
) -> str:
    lines: list[str] = [
        "originjack — browser verification harness",
        "=" * WIDTH,
        "",
        _field("engine", f"{engine}  (pinned)").strip(),
        _field("generated", generated_at).strip(),
        _field("subject", subject).strip(),
        "",
        "Every outcome below was produced by that browser executing the pages' own script",
        "against the real network. Response headers are shown as supporting evidence only.",
        "",
    ]

    for index, result in enumerate(results, start=1):
        heading = f"[{index}] {result.name}".ljust(WIDTH - 18)
        lines.append("-" * WIDTH)
        lines.append(f"{heading}VERDICT: {result.verdict.upper()}")
        lines.append(f"    {result.summary}")
        lines.append("")
        lines.append(_field("calling origin", result.calling_origin))
        lines.append(_field("credential mode", result.credential_mode))
        lines.append(_field("preflight", _preflight(result.preflight)))
        lines.append(
            _field(
                "server response",
                result.observation.describe() if result.observation else "(not observed)",
            )
        )
        lines.append(_field("browser released", _yes_no(result.browser_released)))
        lines.append(_field("victim data rendered", _yes_no(result.victim_data_rendered)))
        lines.append(_field("state changed", _yes_no(result.state_changed)))
        lines.append(_field("decided by", _decided_by(result)))
        if result.screenshot:
            lines.append(_field("screenshot", result.screenshot))
        if result.notes:
            lines.append("")
            lines.extend(f"    · {note}" for note in result.notes)
        lines.append("")

    secure = sum(1 for r in results if r.verdict == "secure")
    vulnerable = len(results) - secure
    lines.append("=" * WIDTH)
    lines.append(f"{len(results)} scenarios — {secure} secure, {vulnerable} vulnerable")
    lines.append("")
    lines.append("Engine notes")
    lines.extend(f"  · {note}" for note in ENGINE_NOTES)
    lines.append("")

    return "\n".join(lines)
