"""The misconfigured cross-origin policies. **Educational material — never deploy.**

Read this beside :mod:`originjack.cors`. Same interface, same routes, same payloads; the
difference between the two files is the whole vulnerability, and it is a few lines long.

The secure policy compares the request's ``Origin`` against a fixed server-side set and
answers with *the value it holds*. The policy below never compares anything: it answers
with *the value the request supplied*. That is the entire bug — an API that says yes to
whoever asks, and grants credentials while doing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal, get_args

from originjack.config import ConfigurationError, Settings
from originjack.cors import REFUSED, CorsDecision, CorsPolicy

#: The misconfiguration shapes this demonstration ships. Each is a different amount of
#: effort spent arriving at the same mistake.
VulnerableShape = Literal["reflect"]

DEFAULT_SHAPE: Final[VulnerableShape] = "reflect"


@dataclass(frozen=True, slots=True)
class ReflectedOriginPolicy:
    """Shape 1 — echo the request's ``Origin`` back and grant credentials.

    Usually arrived at honestly: someone needed several front-ends to work, a wildcard
    was refused by the browser because credentials were involved, and reflecting the
    request's own origin made the error go away. It does make the error go away. It also
    means every origin on the internet is now an allowed origin.
    """

    allowed_methods: tuple[str, ...]
    allowed_headers: tuple[str, ...]
    max_age: int
    _name: str = field(default="vulnerable-reflected-origin", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_settings(cls, settings: Settings) -> ReflectedOriginPolicy:
        return cls(
            allowed_methods=settings.allowed_methods,
            allowed_headers=settings.allowed_headers,
            max_age=settings.preflight_max_age,
        )

    def decide(self, origin: str | None) -> CorsDecision:
        if origin is None:
            return REFUSED

        # No comparison. No set. No check of any kind. Whatever asked, gets.
        return CorsDecision(
            granted=True,
            allow_origin=origin,
            allow_credentials=True,
            allow_methods=self.allowed_methods,
            allow_headers=self.allowed_headers,
            max_age=self.max_age,
        )


def policy_for_shape(shape: str, settings: Settings) -> CorsPolicy:
    """Select a misconfiguration shape by name."""
    if shape not in get_args(VulnerableShape):
        raise ConfigurationError(
            f"unknown vulnerable shape {shape!r}; expected one of {get_args(VulnerableShape)}"
        )
    return ReflectedOriginPolicy.from_settings(settings)
