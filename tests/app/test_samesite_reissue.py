"""Reissuing the session cookie as ``SameSite=Lax`` changes the cookie and nothing else.

A later slice uses this switch to make a point that is easy to get backwards: ``Lax``
withholds the *credential*, it does not repair the *origin policy*. Here we only
establish the precondition — that flipping it is a one-attribute change, so the contrast
later cannot be confounded by some other difference.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from originjack.api import create_app
from originjack.config import FIRST_PARTY_ORIGIN, SESSION_COOKIE_NAME, SameSite, Settings
from originjack.cors import ExactMatchAllowlistPolicy
from originjack.domain import VICTIM_EMPLOYEE_ID

DEMO_PASSWORD = "demo-only-password"


def _app(samesite: SameSite) -> FastAPI:
    settings = Settings(allowed_origins=(FIRST_PARTY_ORIGIN,), session_samesite=samesite)
    return create_app(settings=settings, policy=ExactMatchAllowlistPolicy.from_settings(settings))


@pytest.fixture
def lax_client() -> Iterator[TestClient]:
    with TestClient(_app("lax"), base_url="https://api.meridianpay.example") as client:
        yield client


def _set_cookie(client: TestClient) -> str:
    response = client.post(
        "/session",
        json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    return response.headers["set-cookie"]


def test_lax_reissue_keeps_every_other_cookie_attribute(
    client: TestClient, lax_client: TestClient
) -> None:
    default_attrs = _set_cookie(client).split("; ")
    lax_attrs = _set_cookie(lax_client).split("; ")

    assert "SameSite=None" in default_attrs
    assert "SameSite=Lax" in lax_attrs

    def without_samesite_or_value(attrs: list[str]) -> list[str]:
        return [a for a in attrs if not a.startswith(("SameSite=", f"{SESSION_COOKIE_NAME}="))]

    assert without_samesite_or_value(default_attrs) == without_samesite_or_value(lax_attrs)
    assert "HttpOnly" in lax_attrs
    assert "Secure" in lax_attrs


def test_lax_reissue_does_not_change_the_cross_origin_decision(lax_client: TestClient) -> None:
    granted = lax_client.get("/healthz", headers={"origin": FIRST_PARTY_ORIGIN})
    refused = lax_client.get("/healthz", headers={"origin": "https://promo.attacker.example"})

    assert granted.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN
    assert granted.headers["access-control-allow-credentials"] == "true"
    assert "access-control-allow-origin" not in refused.headers


def test_lax_reissue_does_not_change_the_payslip_payload(
    client: TestClient, lax_client: TestClient
) -> None:
    _set_cookie(client)
    _set_cookie(lax_client)

    default_payload = client.get("/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN}).json()
    lax_payload = lax_client.get("/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN}).json()

    assert default_payload == lax_payload


def test_lax_reissue_does_not_change_the_rejection_shape(lax_client: TestClient) -> None:
    response = lax_client.get("/me/payslip", headers={"cookie": f"{SESSION_COOKIE_NAME}=junk"})

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
