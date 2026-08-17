"""Entry point for the **deliberately vulnerable** Meridian Payroll API.

**This service is educational material. It must never be deployed anywhere.**

It is a separate entry point from :mod:`originjack.secure` on purpose. The secure
application has no switch that can widen its policy, and cannot be configured into this
behaviour — the misconfiguration lives here, in its own module, behind its own gate.

Starting it takes two deliberate actions, and this file enforces the second one. The
first is an opt-in Compose profile; the second is the acknowledgement below. A gate that
lived only in Compose configuration would be one `docker run` away from being bypassed,
so the refusal is in the application itself.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from fastapi import FastAPI

from originjack.api import create_app
from originjack.config import Settings
from originjack.statechange import SessionOnlyWrites
from originjack.vulnerable_cors import DEFAULT_SHAPE, policy_for_shape

ACKNOWLEDGEMENT_ENV = "ALLOW_VULNERABLE_DEMO"
REQUIRED_ACKNOWLEDGEMENT = "true"
SHAPE_ENV = "ORIGINJACK_VULNERABLE_SHAPE"


class VulnerableDemoNotAcknowledgedError(RuntimeError):
    """Raised when the vulnerable service is started without the explicit opt-in."""


def require_acknowledgement(env: Mapping[str, str] | None = None) -> None:
    """Refuse to start unless the operator has said so in as many words."""
    source = os.environ if env is None else env
    if source.get(ACKNOWLEDGEMENT_ENV) != REQUIRED_ACKNOWLEDGEMENT:
        raise VulnerableDemoNotAcknowledgedError(
            "refusing to start the intentionally vulnerable demonstration API: set "
            f"{ACKNOWLEDGEMENT_ENV}={REQUIRED_ACKNOWLEDGEMENT} to acknowledge that this "
            "service exposes a logged-in user's data to any origin that asks, and is for "
            "local educational use only"
        )


def build(env: dict[str, str] | None = None) -> FastAPI:
    """Build the vulnerable application, refusing unless the opt-in is present.

    Exposed as a **factory** rather than a module-level ``app``, and served with
    ``uvicorn originjack.vulnerable:build --factory``. The gate then fires when the
    service starts rather than when the module is imported, which keeps the refusal
    exactly as strict while leaving the module importable — by its own tests, among
    other things. A gate that cannot be tested is a gate nobody should trust.
    """
    source = os.environ if env is None else env
    require_acknowledgement(source)
    settings = Settings.from_env(env)
    shape = source.get(SHAPE_ENV, DEFAULT_SHAPE)
    return create_app(
        settings=settings,
        policy=policy_for_shape(shape, settings),
        # The legacy deployment also predates CSRF protection on its write route. That is
        # a second, independent fault — and the only way to show that CORS was never
        # standing between a cross-site request and a state change.
        writes=SessionOnlyWrites(),
    )
