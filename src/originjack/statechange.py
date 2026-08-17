"""What the state-changing route demands before it will act.

The two deployments differ here as well as in their CORS policy, and they have to: no
CORS policy can decide whether a request is *processed*. CORS governs whether a page may
**read** a response; it has never governed whether a request may be **sent**. That is the
whole point of the simple-request control, and demonstrating it requires a deployment
where the write actually lands.

Modelled as a policy object for the same reason the CORS decision is: the difference
between the two deployments should read as a diff, not as a special case buried in a
route.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from originjack.sessions import Session, csrf_token_matches

JSON_MEDIA_TYPE = "application/json"


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why a state change was declined, as an HTTP answer."""

    status_code: int
    error: str


@runtime_checkable
class StateChangePolicy(Protocol):
    """Decides whether a state-changing request may proceed."""

    @property
    def name(self) -> str: ...

    def refuse(
        self, *, media_type: str, presented_csrf: str | None, session: Session
    ) -> Refusal | None:
        """Return a refusal, or ``None`` to let the change proceed."""


@dataclass(frozen=True, slots=True)
class CsrfProtectedWrites:
    """The secure deployment: a non-simple request, and a matching CSRF token.

    Requiring ``application/json`` is not decoration. A cross-site *simple* request may
    only carry a CORS-safelisted content type, so demanding a non-simple one means the
    browser must preflight — and a preflight this policy will not grant is a preflight
    that never becomes a request.
    """

    _name: str = field(default="csrf-protected-writes", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    def refuse(
        self, *, media_type: str, presented_csrf: str | None, session: Session
    ) -> Refusal | None:
        if media_type != JSON_MEDIA_TYPE:
            return Refusal(415, "unsupported_media_type")
        if not csrf_token_matches(session, presented_csrf):
            return Refusal(403, "forbidden")
        return None


@dataclass(frozen=True, slots=True)
class SessionOnlyWrites:
    """The legacy deployment: a valid session and nothing more.

    **Educational material.** This is what a state-changing route looks like before
    anybody added CSRF protection to it, which is to say: like most of them, for years.
    A cross-site form or a `text/plain` fetch reaches it with the victim's cookie
    attached, no preflight is sent, and the write happens — whether or not the caller is
    ever allowed to read the answer.
    """

    _name: str = field(default="legacy-session-only-writes", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    def refuse(
        self, *, media_type: str, presented_csrf: str | None, session: Session
    ) -> Refusal | None:
        return None
