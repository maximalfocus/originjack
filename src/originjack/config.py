"""Runtime configuration for the demo services.

Everything here is demonstration configuration. The signing key below is a published
constant, not a secret: the whole point of the demo is that the reader can mint and
inspect the fictional session credentials themselves.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, get_args

SameSite = Literal["none", "lax"]

#: The one legitimate first-party origin. Kept as a module constant so the allowlist is
#: visibly a fixed, server-side set rather than anything derived from a request.
FIRST_PARTY_ORIGIN: Final = "https://app.meridianpay.example"

#: Conspicuously fake. Published on purpose — see the module docstring.
DEMO_SESSION_SIGNING_KEY: Final = "originjack-demo-signing-key-not-a-secret"

DEFAULT_ALLOWED_METHODS: Final[tuple[str, ...]] = ("GET", "POST")
DEFAULT_ALLOWED_HEADERS: Final[tuple[str, ...]] = ("content-type", "x-meridian-csrf")
DEFAULT_PREFLIGHT_MAX_AGE: Final = 60
DEFAULT_SESSION_TTL_SECONDS: Final = 3600

SESSION_COOKIE_NAME: Final = "mp_session"
CSRF_HEADER_NAME: Final = "x-meridian-csrf"


class ConfigurationError(ValueError):
    """Raised when the environment describes a configuration the demo will not serve."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable service settings, resolved once at import time by an entry point."""

    allowed_origins: tuple[str, ...]
    allowed_methods: tuple[str, ...] = DEFAULT_ALLOWED_METHODS
    allowed_headers: tuple[str, ...] = DEFAULT_ALLOWED_HEADERS
    preflight_max_age: int = DEFAULT_PREFLIGHT_MAX_AGE
    session_samesite: SameSite = "none"
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS
    session_signing_key: str = DEMO_SESSION_SIGNING_KEY

    def __post_init__(self) -> None:
        if not self.allowed_origins:
            raise ConfigurationError("at least one allowlisted origin is required")
        for origin in self.allowed_origins:
            if not origin.startswith("https://") or origin.endswith("/"):
                raise ConfigurationError(
                    f"allowlisted origins must be bare https origins, got {origin!r}"
                )

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        raw_origins = source.get("ORIGINJACK_ALLOWED_ORIGINS", FIRST_PARTY_ORIGIN)
        origins = tuple(part.strip() for part in raw_origins.split(",") if part.strip())

        samesite = source.get("ORIGINJACK_SESSION_SAMESITE", "none").strip().lower()
        if samesite not in get_args(SameSite):
            raise ConfigurationError(
                f"ORIGINJACK_SESSION_SAMESITE must be one of {get_args(SameSite)}, got {samesite!r}"
            )

        return cls(
            allowed_origins=origins,
            session_samesite=samesite,  # type: ignore[arg-type]
            session_ttl_seconds=int(
                source.get("ORIGINJACK_SESSION_TTL_SECONDS", str(DEFAULT_SESSION_TTL_SECONDS))
            ),
            session_signing_key=source.get(
                "ORIGINJACK_SESSION_SIGNING_KEY", DEMO_SESSION_SIGNING_KEY
            ),
        )


def static_root_from_env(env: dict[str, str] | None = None) -> Path:
    """Resolve the directory a static origin serves."""
    source = os.environ if env is None else env
    root = Path(source.get("ORIGINJACK_STATIC_ROOT", "/app/web/app"))
    if not root.is_dir():
        raise ConfigurationError(f"static root does not exist: {root}")
    return root
