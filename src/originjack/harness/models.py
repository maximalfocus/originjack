"""What the harness records about a single browser-driven scenario.

These records are the demonstration's evidence. Each one answers, for one page on one
origin: what the server sent, what the browser did with it, what the page could actually
show, and — the question the whole project exists to make legible — *which component*
decided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Decider = Literal["browser", "server"]
Verdict = Literal["secure", "vulnerable"]


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    """What the browser saw on the wire, as distinct from what it gave the page."""

    url: str
    status: int | None = None
    allow_origin: str | None = None
    allow_credentials: str | None = None
    failure: str | None = None
    request_origin: str | None = None

    @property
    def server_answered(self) -> bool:
        """The server produced a response, whatever the browser then did with it."""
        return self.status is not None

    def describe(self) -> str:
        parts = [f"status={self.status if self.status is not None else '—'}"]
        if self.request_origin is not None:
            parts.append(f"sent-Origin={self.request_origin}")
        parts.append(f"ACAO={self.allow_origin or '(absent)'}")
        parts.append(f"ACAC={self.allow_credentials or '(absent)'}")
        if self.failure:
            parts.append(f"browser-failure={self.failure}")
        return "  ".join(parts)


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """One scenario, as observed through a real browser."""

    name: str
    summary: str
    calling_origin: str
    credential_mode: str
    preflight: bool | None
    browser_released: bool
    victim_data_rendered: bool
    state_changed: bool
    decided_by: Decider
    verdict: Verdict
    observation: NetworkObservation | None = None
    screenshot: str | None = None
    #: Which misconfiguration shape the vulnerable API was serving at the time, when one
    #: was involved. The shapes are mutually exclusive, so every scenario belongs to at
    #: most one of them.
    shape: str | None = None
    #: Why the decider decided as it did, in the scenario's own words. The shapes fail
    #: differently — one reflects, one matches sloppily, one has an extra entry — and a
    #: single generic phrasing would misdescribe two of the three.
    decider_detail: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.victim_data_rendered and not self.browser_released:
            raise ValueError("victim data cannot be rendered from a response the browser withheld")
