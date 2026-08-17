"""Shared fixtures and the origins the regression matrix keeps refusing."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Final

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from originjack.api import create_app
from originjack.config import FIRST_PARTY_ORIGIN, Settings
from originjack.cors import ExactMatchAllowlistPolicy

#: Origins that must never be granted a cross-origin response by the secure API.
#:
#: The first three are the ladder a later slice exploits against the *vulnerable* API:
#: an unrelated attacker site, a name that walks through a prefix or unanchored-regex
#: check, and a name that walks through a suffix check. The rest are the near-misses an
#: exact-string comparison has to keep refusing — scheme, port, case, trailing slash —
#: plus the two values a policy must never accept as a matter of course.
REFUSED_ORIGINS: Final[tuple[str, ...]] = (
    "https://promo.attacker.example",
    "https://app.meridianpay.example.attacker.example",
    "https://notmeridianpay.example",
    "https://meridianpay.example",
    "https://app.meridianpay.example.evil.example",
    "https://evil.example/?x=https://app.meridianpay.example",
    "http://app.meridianpay.example",
    "https://app.meridianpay.example:8443",
    "https://APP.meridianpay.example",
    "https://app.meridianpay.example/",
    "https://app.meridianpay.example.",
    " https://app.meridianpay.example",
    "null",
    "*",
    "",
)

#: The origins the demonstration frames as adversaries. Each is refused by the secure
#: policy and granted by the reflection shape, which is the contrast the demo is built on.
ATTACKER_ORIGINS: Final[tuple[str, ...]] = (
    "https://promo.attacker.example",
    "https://app.meridianpay.example.attacker.example",
    "https://notmeridianpay.example",
)

#: Values a policy must refuse but that no real client can put on the wire — a header
#: value cannot begin with whitespace. They stay in the policy-level matrix and are
#: excluded from the suites that make real HTTP requests.
UNSENDABLE_ORIGINS: Final[tuple[str, ...]] = (" https://app.meridianpay.example",)

#: The refusal matrix restricted to values that can actually be sent over HTTP.
WIRE_REFUSED_ORIGINS: Final[tuple[str, ...]] = tuple(
    origin for origin in REFUSED_ORIGINS if origin not in UNSENDABLE_ORIGINS
)


@pytest.fixture
def settings() -> Settings:
    return Settings(allowed_origins=(FIRST_PARTY_ORIGIN,))


@pytest.fixture
def secure_app(settings: Settings) -> FastAPI:
    return create_app(
        settings=settings,
        policy=ExactMatchAllowlistPolicy.from_settings(settings),
    )


@pytest.fixture
def client(secure_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(secure_app, base_url="https://api.meridianpay.example") as test_client:
        yield test_client


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip suites whose environment is absent, rather than failing them.

    The HTTPS boundary suite needs the containers up; the browser suite additionally
    needs the browser image, which is the only one carrying Chromium.
    """
    skip_boundary = pytest.mark.skip(
        reason="ORIGINJACK_API_BASE is unset; run the boundary suite via ./scripts/demo.sh"
    )
    skip_browser = pytest.mark.skip(
        reason="ORIGINJACK_ARTIFACTS is unset; the browser suite runs in the browser image"
    )
    skip_vulnerable = pytest.mark.skip(
        reason="the opt-in vulnerable services are not running; "
        "run ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh --with-vulnerable"
    )
    has_services = bool(os.environ.get("ORIGINJACK_API_BASE"))
    has_browser = bool(os.environ.get("ORIGINJACK_ARTIFACTS"))
    has_vulnerable = os.environ.get("ORIGINJACK_INCLUDE_VULNERABLE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    # The three misconfiguration shapes are mutually exclusive, so only one is live per
    # pass. A test written for another shape is skipped rather than run against the wrong
    # configuration.
    live_shape = os.environ.get("ORIGINJACK_VULNERABLE_SHAPE", "reflect").strip() or "reflect"

    for item in items:
        if "boundary" in item.keywords and not has_services:
            item.add_marker(skip_boundary)
        if "browser" in item.keywords and not has_browser:
            item.add_marker(skip_browser)
        if "vulnerable" in item.keywords and not has_vulnerable:
            item.add_marker(skip_vulnerable)

        shape_marker = item.get_closest_marker("shape")
        if shape_marker and shape_marker.args and shape_marker.args[0] != live_shape:
            item.add_marker(
                pytest.mark.skip(
                    reason=f"shape {shape_marker.args[0]!r} is not the live shape ({live_shape!r})"
                )
            )
