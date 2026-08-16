"""The cross-origin decision, written as explicit application code.

This module is the whole security boundary of the demonstration, so it is deliberately
small enough to read in one sitting and deliberately *not* delegated to a framework CORS
middleware: a later slice adds the misconfigured shapes beside it, and the contrast has
to be legible as a diff rather than as a configuration flag.

The rule the secure API applies:

    The request's ``Origin`` is compared as a **whole string** against a fixed,
    server-side set. On a match the response carries ``Access-Control-Allow-Origin`` set
    to *the value held in that set* — never the value the request supplied — plus
    ``Access-Control-Allow-Credentials: true`` and a narrow, enumerated set of methods
    and request headers. Anything else receives no ``Access-Control-Allow-Origin`` and no
    credential grant.

There is no substring test, no ``startswith``, no ``endswith``, and no regular
expression anywhere in the decision path, and that absence is what the regression tests
protect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from originjack.config import Settings


@dataclass(frozen=True, slots=True)
class CorsDecision:
    """What the server decided to tell the browser about this origin."""

    granted: bool
    allow_origin: str | None = None
    allow_credentials: bool = False
    allow_methods: tuple[str, ...] = ()
    allow_headers: tuple[str, ...] = ()
    max_age: int | None = None

    def __post_init__(self) -> None:
        if not self.granted and (self.allow_origin is not None or self.allow_credentials):
            raise ValueError("a refused decision must carry no grant")


#: The single refused decision. Shared so that every refusal is byte-identical and no
#: caller can accidentally leak a partial grant.
REFUSED = CorsDecision(granted=False)


@runtime_checkable
class CorsPolicy(Protocol):
    """A policy maps an incoming ``Origin`` header to a :class:`CorsDecision`."""

    @property
    def name(self) -> str:
        """Short identifier used in demo output."""

    def decide(self, origin: str | None) -> CorsDecision:
        """Decide what to grant to ``origin`` (``None`` when the header is absent)."""


@dataclass(frozen=True, slots=True)
class ExactMatchAllowlistPolicy:
    """The secure policy: exact, whole-string membership of a fixed server-side set."""

    allowed_origins: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_headers: tuple[str, ...]
    max_age: int
    _name: str = field(default="secure-exact-match-allowlist", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_settings(cls, settings: Settings) -> ExactMatchAllowlistPolicy:
        return cls(
            allowed_origins=settings.allowed_origins,
            allowed_methods=settings.allowed_methods,
            allowed_headers=settings.allowed_headers,
            max_age=settings.preflight_max_age,
        )

    def decide(self, origin: str | None) -> CorsDecision:
        if origin is None:
            # Not a cross-origin browser request at all: there is nothing to grant and
            # nothing to refuse, so this is not an audited refusal either.
            return REFUSED

        for allowlisted in self.allowed_origins:
            if origin == allowlisted:
                return CorsDecision(
                    granted=True,
                    # The allowlisted constant, not the request's value. Equal here by
                    # construction; distinct as a matter of policy, and the reason this
                    # service can never be talked into reflecting an attacker's origin.
                    allow_origin=allowlisted,
                    allow_credentials=True,
                    allow_methods=self.allowed_methods,
                    allow_headers=self.allowed_headers,
                    max_age=self.max_age,
                )

        return REFUSED


def response_headers(decision: CorsDecision, *, preflight: bool) -> dict[str, str]:
    """Render a decision as response headers.

    A refusal renders to *nothing*: the absence of ``Access-Control-Allow-Origin`` is
    what makes the browser withhold the response from the calling page.
    """
    if not decision.granted or decision.allow_origin is None:
        return {}

    headers = {"access-control-allow-origin": decision.allow_origin}
    if decision.allow_credentials:
        headers["access-control-allow-credentials"] = "true"

    if preflight:
        headers["access-control-allow-methods"] = ", ".join(decision.allow_methods)
        headers["access-control-allow-headers"] = ", ".join(decision.allow_headers)
        if decision.max_age is not None:
            headers["access-control-max-age"] = str(decision.max_age)

    return headers
