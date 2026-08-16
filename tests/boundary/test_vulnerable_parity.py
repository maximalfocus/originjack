"""Both API deployments answer the first party identically, over real HTTPS.

This is a claim about two server responses being equal, not about anything a browser
enforces, so it is verified at the HTTP boundary rather than through the browser — which
is where a claim of this shape actually belongs.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest

from originjack.config import FIRST_PARTY_ORIGIN, SESSION_COOKIE_NAME
from originjack.demo_ca import ssl_context
from originjack.domain import VICTIM_EMPLOYEE_ID
from tests.conftest import ATTACKER_ORIGINS

pytestmark = [pytest.mark.boundary, pytest.mark.vulnerable]

API_BASE = os.environ.get("ORIGINJACK_API_BASE", "https://api.meridianpay.example")
VULNERABLE_BASE = os.environ.get(
    "ORIGINJACK_VULNERABLE_API_BASE", "https://legacy-api.meridianpay.example"
)
DEMO_PASSWORD = "demo-only-password"


@pytest.fixture
def clients() -> Iterator[tuple[httpx.Client, httpx.Client]]:
    context = ssl_context()
    with (
        httpx.Client(base_url=API_BASE, verify=context, timeout=10.0) as secure,
        httpx.Client(base_url=VULNERABLE_BASE, verify=context, timeout=10.0) as vulnerable,
    ):
        yield secure, vulnerable


def _login(client: httpx.Client) -> dict[str, str]:
    response = client.post(
        "/session",
        json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    value = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    return {"cookie": f"{SESSION_COOKIE_NAME}={value}"}


def test_both_deployments_answer_the_first_party_identically(
    clients: tuple[httpx.Client, httpx.Client],
) -> None:
    secure, vulnerable = clients

    secure_payslip = secure.get(
        "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_login(secure)}
    )
    vulnerable_payslip = vulnerable.get(
        "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_login(vulnerable)}
    )

    assert secure_payslip.status_code == vulnerable_payslip.status_code == 200
    assert secure_payslip.json() == vulnerable_payslip.json()
    assert (
        secure_payslip.headers["access-control-allow-origin"]
        == vulnerable_payslip.headers["access-control-allow-origin"]
        == FIRST_PARTY_ORIGIN
    )


@pytest.mark.parametrize("origin", ATTACKER_ORIGINS)
def test_the_two_deployments_disagree_about_every_attacker_origin(
    clients: tuple[httpx.Client, httpx.Client], origin: str
) -> None:
    secure, vulnerable = clients

    refused = secure.get("/me/payslip", headers={"origin": origin, **_login(secure)})
    granted = vulnerable.get("/me/payslip", headers={"origin": origin, **_login(vulnerable)})

    assert "access-control-allow-origin" not in refused.headers
    assert granted.headers["access-control-allow-origin"] == origin
    assert granted.headers["access-control-allow-credentials"] == "true"

    # Both answered the request in full. Only one of them told the browser to share it.
    assert refused.status_code == granted.status_code == 200
    assert refused.json() == granted.json()


def test_the_vulnerable_deployment_is_still_unreachable_from_outside_the_network() -> None:
    """It is opt-in, hardened, and on a network with no egress — not merely unadvertised."""
    with httpx.Client(timeout=5.0) as client, pytest.raises(httpx.HTTPError):
        client.get("https://203.0.113.1/")
