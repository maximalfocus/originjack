"""Entry point for the **secure** Meridian Payroll API.

This is the default service. It applies the strict, exact-match origin allowlist and is
the reference every later contrast is measured against. It contains no misconfiguration
shape, no switch that can widen its policy at runtime, and no attacker-facing surface.
"""

from __future__ import annotations

from fastapi import FastAPI

from originjack.api import create_app
from originjack.config import Settings
from originjack.cors import ExactMatchAllowlistPolicy


def build() -> FastAPI:
    settings = Settings.from_env()
    return create_app(settings=settings, policy=ExactMatchAllowlistPolicy.from_settings(settings))


app = build()
