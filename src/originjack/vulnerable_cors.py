"""The misconfigured cross-origin policies. **Educational material — never deploy.**

Read this beside :mod:`originjack.cors`. Same interface, same routes, same payloads; the
difference between the two files is the whole vulnerability, and it is a few lines long.

The secure policy compares the request's ``Origin`` against a fixed server-side set and
answers with *the value it holds*. The policy below never compares anything: it answers
with *the value the request supplied*. That is the entire bug — an API that says yes to
whoever asks, and grants credentials while doing it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Literal, get_args

from originjack.config import CORPORATE_DOMAIN, ConfigurationError, Settings
from originjack.cors import REFUSED, CorsDecision, CorsPolicy

#: The misconfiguration shapes this demonstration ships. Each is a different amount of
#: effort spent arriving at the same mistake — and the later two are more dangerous than
#: the first, because they arrive with the reassurance of looking deliberate.
VulnerableShape = Literal["reflect", "sloppy", "null", "wildcard"]

DEFAULT_SHAPE: Final[VulnerableShape] = "reflect"

#: The literal origin a browser sends from an opaque origin — a sandboxed iframe, a
#: `file://` page, some redirect chains. It is a string, not a domain, and it belongs to
#: nobody, which is why no allowlist may contain it.
NULL_ORIGIN: Final = "null"


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


@dataclass(frozen=True, slots=True)
class SloppyMatchPolicy:
    """Shape 2 — an allowlist that is not one.

    This is what "only allow our own domain" turns into when it is implemented against
    the origin *string* instead of against a set of origins. The pattern is unanchored,
    so it matches anywhere in the value:

    * ``https://promo.attacker.example`` no longer matches, so the obvious attack stops
      working and the configuration looks repaired;
    * ``https://app.meridianpay.example.attacker.example`` matches, because the corporate
      domain appears in the middle of a domain the attacker owns; and
    * ``https://notmeridianpay.example`` matches, because it appears at the end of one.

    A plain ``corporate_domain in origin``, an ``endswith`` that forgets the leading dot,
    or a regular expression missing its anchors all have this same hole. The bug is not
    the technique; it is comparing anything other than whole origins.
    """

    corporate_domain: str
    allowed_methods: tuple[str, ...]
    allowed_headers: tuple[str, ...]
    max_age: int
    _name: str = field(default="vulnerable-sloppy-match", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_settings(cls, settings: Settings) -> SloppyMatchPolicy:
        return cls(
            corporate_domain=CORPORATE_DOMAIN,
            allowed_methods=settings.allowed_methods,
            allowed_headers=settings.allowed_headers,
            max_age=settings.preflight_max_age,
        )

    def decide(self, origin: str | None) -> CorsDecision:
        if origin is None:
            return REFUSED

        # Unanchored. Matches the corporate domain anywhere in the origin, including in
        # the middle of somebody else's.
        if re.search(re.escape(self.corporate_domain), origin) is None:
            return REFUSED

        return CorsDecision(
            granted=True,
            allow_origin=origin,
            allow_credentials=True,
            allow_methods=self.allowed_methods,
            allow_headers=self.allowed_headers,
            max_age=self.max_age,
        )


@dataclass(frozen=True, slots=True)
class NullOriginPolicy:
    """Shape 3 — the secure policy, with one extra entry in the set.

    This shape is the most instructive of the three precisely because it is *so nearly
    right*. It compares whole strings against a fixed server-side set, exactly as it
    should. Someone simply added ``null`` to that set, because a sandboxed iframe or a
    redirect chain needed it and the request looked harmless.

    ``null`` is not an origin. It is what the browser sends *instead of* one, and anybody
    can arrange to send it — from a sandboxed iframe, in one attribute.
    """

    allowed_origins: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_headers: tuple[str, ...]
    max_age: int
    _name: str = field(default="vulnerable-null-origin", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_settings(cls, settings: Settings) -> NullOriginPolicy:
        return cls(
            # The one-entry difference from the secure policy.
            allowed_origins=(*settings.allowed_origins, NULL_ORIGIN),
            allowed_methods=settings.allowed_methods,
            allowed_headers=settings.allowed_headers,
            max_age=settings.preflight_max_age,
        )

    def decide(self, origin: str | None) -> CorsDecision:
        if origin is None:
            return REFUSED

        for allowlisted in self.allowed_origins:
            if origin == allowlisted:
                return CorsDecision(
                    granted=True,
                    allow_origin=allowlisted,
                    allow_credentials=True,
                    allow_methods=self.allowed_methods,
                    allow_headers=self.allowed_headers,
                    max_age=self.max_age,
                )

        return REFUSED


@dataclass(frozen=True, slots=True)
class WildcardCredentialsPolicy:
    """The **negative control** — the shape everyone worries about, which does not work.

    Returns ``Access-Control-Allow-Origin: *`` together with
    ``Access-Control-Allow-Credentials: true``. The specification forbids that
    combination and the **browser** refuses it, so a credentialed read fails even though
    the server granted every origin on earth.

    Two things follow, and both are worth saying out loud:

    * the wildcard is *not* the dangerous shape — it fails safe under credentials; and
    * "we never use ``*``" is therefore not evidence of a correct policy. Reflection,
      which looks more careful, is the one that hands the data over.
    """

    allowed_methods: tuple[str, ...]
    allowed_headers: tuple[str, ...]
    max_age: int
    _name: str = field(default="vulnerable-wildcard-credentials", init=False, repr=False)

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def from_settings(cls, settings: Settings) -> WildcardCredentialsPolicy:
        return cls(
            allowed_methods=settings.allowed_methods,
            allowed_headers=settings.allowed_headers,
            max_age=settings.preflight_max_age,
        )

    def decide(self, origin: str | None) -> CorsDecision:
        if origin is None:
            return REFUSED

        return CorsDecision(
            granted=True,
            allow_origin="*",
            allow_credentials=True,
            allow_methods=self.allowed_methods,
            allow_headers=self.allowed_headers,
            max_age=self.max_age,
        )


_SHAPES: Final[
    dict[
        str,
        type[
            ReflectedOriginPolicy | SloppyMatchPolicy | NullOriginPolicy | WildcardCredentialsPolicy
        ],
    ]
] = {
    "reflect": ReflectedOriginPolicy,
    "sloppy": SloppyMatchPolicy,
    "null": NullOriginPolicy,
    "wildcard": WildcardCredentialsPolicy,
}


def policy_for_shape(shape: str, settings: Settings) -> CorsPolicy:
    """Select a misconfiguration shape by name."""
    if shape not in get_args(VulnerableShape):
        raise ConfigurationError(
            f"unknown vulnerable shape {shape!r}; expected one of {get_args(VulnerableShape)}"
        )
    return _SHAPES[shape].from_settings(settings)
