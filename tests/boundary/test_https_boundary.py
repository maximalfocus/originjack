"""The same claims, made against the real containers over real HTTPS.

These run inside the hermetic network via ``./scripts/demo.sh``. They prove the wiring
the in-process tests cannot: real TLS from the build-time demo CA, real DNS from the
container runtime's embedded resolver, real cross-origin headers on the wire, and a
network with no way out.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest

from originjack.config import (
    DEMO_SESSION_SIGNING_KEY,
    FIRST_PARTY_ORIGIN,
    SESSION_COOKIE_NAME,
)
from originjack.demo_ca import ssl_context
from originjack.domain import VICTIM_EMPLOYEE_ID
from originjack.sessions import encode, issue
from tests.conftest import WIRE_REFUSED_ORIGINS

pytestmark = pytest.mark.boundary

API_BASE = os.environ.get("ORIGINJACK_API_BASE", "https://api.meridianpay.example")
APP_BASE = os.environ.get("ORIGINJACK_APP_BASE", "https://app.meridianpay.example")
SIGNING_KEY = os.environ.get("ORIGINJACK_SESSION_SIGNING_KEY", DEMO_SESSION_SIGNING_KEY)
DEMO_PASSWORD = "demo-only-password"
SECOND_EMPLOYEE_ID = "EMP-2093"

#: RFC 5737 TEST-NET-3. Reserved for documentation, never routed, and deliberately not a
#: real host: reaching *anything* from this network is the failure we are testing for.
UNROUTABLE_ADDRESS = "https://203.0.113.1/"


@pytest.fixture
def api() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=API_BASE, verify=ssl_context(), timeout=10.0) as client:
        yield client


def _login(client: httpx.Client, employee_id: str = VICTIM_EMPLOYEE_ID) -> tuple[str, str]:
    response = client.post(
        "/session", json={"employee_id": employee_id, "demo_password": DEMO_PASSWORD}
    )
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    return cookie, response.json()["csrf_token"]


def _cookie(value: str) -> dict[str, str]:
    return {"cookie": f"{SESSION_COOKIE_NAME}={value}"}


# --- transport ------------------------------------------------------------------------


def test_origins_serve_https_from_the_build_time_demo_ca() -> None:
    with httpx.Client(verify=ssl_context(), timeout=10.0) as trusting:
        assert trusting.get(f"{API_BASE}/healthz").status_code == 200
        assert trusting.get(f"{APP_BASE}/healthz").status_code == 200

    # And only from it: the demo CA is not, and must never be, publicly trusted.
    with httpx.Client(timeout=10.0) as untrusting, pytest.raises(httpx.HTTPError):
        untrusting.get(f"{API_BASE}/healthz")


def test_the_network_has_no_egress() -> None:
    """Nothing on this network can reach anything but the demo's own services."""
    with httpx.Client(timeout=5.0) as client, pytest.raises(httpx.HTTPError):
        client.get(UNROUTABLE_ADDRESS)


def test_the_first_party_application_is_served_on_its_own_origin() -> None:
    with httpx.Client(verify=ssl_context(), timeout=10.0) as client:
        response = client.get(f"{APP_BASE}/")

    assert response.status_code == 200
    assert "Meridian Payroll" in response.text
    assert "api.meridianpay.example" in response.text


# --- session --------------------------------------------------------------------------


def test_login_issues_the_cross_site_session_cookie(api: httpx.Client) -> None:
    response = api.post(
        "/session",
        json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": DEMO_PASSWORD},
    )

    assert response.status_code == 200
    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=None" in set_cookie


def test_every_bad_session_gets_the_same_generic_401(api: httpx.Client) -> None:
    expired = encode(issue(VICTIM_EMPLOYEE_ID, ttl_seconds=-60), key=SIGNING_KEY)
    unknown = encode(issue("EMP-0000", ttl_seconds=3600), key=SIGNING_KEY)

    responses = [
        api.get("/me/payslip"),
        api.get("/me/payslip", headers=_cookie("not-a-real-token")),
        api.get("/me/payslip", headers=_cookie(expired)),
        api.get("/me/payslip", headers=_cookie(unknown)),
    ]

    assert [r.status_code for r in responses] == [401, 401, 401, 401]
    assert len({r.text for r in responses}) == 1


# --- the cross-origin decision on the wire --------------------------------------------


def test_the_allowlisted_origin_completes_a_credentialed_read(api: httpx.Client) -> None:
    cookie, _ = _login(api)

    response = api.get("/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_cookie(cookie)})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "origin" in response.headers["vary"].lower()

    payload = response.json()
    assert payload["payslip"]["net_pay_minor"] == 371_845
    assert payload["payout_account"]["account_tail"] == "8842"
    assert payload["api_token"] == "mp_demo_tok_4417_NOT_A_REAL_TOKEN"


@pytest.mark.parametrize("origin", WIRE_REFUSED_ORIGINS)
def test_no_other_origin_is_granted_anything(api: httpx.Client, origin: str) -> None:
    cookie, _ = _login(api)

    response = api.get("/me/payslip", headers={"origin": origin, **_cookie(cookie)})

    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers
    assert "origin" in response.headers["vary"].lower()


def test_preflight_is_granted_narrowly_and_only_to_the_allowlisted_origin(
    api: httpx.Client,
) -> None:
    granted = api.request(
        "OPTIONS",
        "/me/payout-account",
        headers={
            "origin": FIRST_PARTY_ORIGIN,
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-meridian-csrf",
        },
    )
    refused = api.request(
        "OPTIONS",
        "/me/payout-account",
        headers={
            "origin": "https://promo.attacker.example",
            "access-control-request-method": "POST",
        },
    )

    assert granted.status_code == refused.status_code == 204
    assert granted.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN
    assert granted.headers["access-control-allow-methods"] == "GET, POST"
    assert granted.headers["access-control-allow-headers"] == "content-type, x-meridian-csrf"
    assert "access-control-allow-origin" not in refused.headers


# --- the state-changing route ---------------------------------------------------------


def test_the_first_party_can_change_a_payout_account(api: httpx.Client) -> None:
    """Uses the second fictional employee so the walkthrough's victim stays pristine."""
    cookie, csrf = _login(api, SECOND_EMPLOYEE_ID)
    headers = {
        "origin": FIRST_PARTY_ORIGIN,
        "content-type": "application/json",
        "x-meridian-csrf": csrf,
        **_cookie(cookie),
    }

    try:
        response = api.post(
            "/me/payout-account",
            headers=headers,
            json={"bank_name": "Ledgerbrook Mutual (fictional)", "account_tail": "7311"},
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN

        confirmed = api.get("/me/payslip", headers={**_cookie(cookie)}).json()
        assert confirmed["payout_account"]["account_tail"] == "7311"
    finally:
        api.post(
            "/me/payout-account",
            headers=headers,
            json={"bank_name": "Ledgerbrook Mutual (fictional)", "account_tail": "1160"},
        )


def test_a_simple_cross_site_post_is_refused_and_changes_nothing(api: httpx.Client) -> None:
    cookie, _ = _login(api)
    before = api.get("/me/payslip", headers=_cookie(cookie)).json()

    response = api.post(
        "/me/payout-account",
        headers={
            "origin": "https://promo.attacker.example",
            "content-type": "text/plain;charset=UTF-8",
            **_cookie(cookie),
        },
        content='{"bank_name": "Redirected Holdings (fictional)", "account_tail": "0001"}',
    )

    assert response.status_code == 415
    assert "access-control-allow-origin" not in response.headers
    assert api.get("/me/payslip", headers=_cookie(cookie)).json() == before
