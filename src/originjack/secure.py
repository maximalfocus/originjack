"""Entry point for the **secure** Meridian Payroll API.

This is the default service. It applies the strict, exact-match origin allowlist *and*
requires a non-simple request with a matching CSRF token before it will change anything —
two separate protections, because they answer two separate questions. It is the reference
every contrast is measured against, and contains no misconfiguration shape, no switch
that can widen its policy at runtime, and no attacker-facing surface.
"""

from __future__ import annotations

from fastapi import FastAPI

from originjack.api import create_app
from originjack.config import Settings
from originjack.cors import ExactMatchAllowlistPolicy
from originjack.statechange import CsrfProtectedWrites


def build() -> FastAPI:
    settings = Settings.from_env()
    return create_app(
        settings=settings,
        policy=ExactMatchAllowlistPolicy.from_settings(settings),
        writes=CsrfProtectedWrites(),
    )


app = build()
