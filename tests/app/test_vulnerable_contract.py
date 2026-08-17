"""The vulnerable API's HTTP contract, and where it does and does not differ.

Two properties matter here and pull in opposite directions: the vulnerable API must hand
its response to anyone (that is the bug), and it must be otherwise indistinguishable from
the secure one (that is what makes the bug a fair demonstration rather than a strawman).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from originjack.api import create_app
from originjack.audit import ORIGIN_REFUSED_EVENT
from originjack.config import FIRST_PARTY_ORIGIN, SESSION_COOKIE_NAME, Settings
from originjack.cors import ExactMatchAllowlistPolicy
from originjack.domain import VICTIM_EMPLOYEE_ID
from originjack.statechange import SessionOnlyWrites
from originjack.vulnerable_cors import ReflectedOriginPolicy
from tests.conftest import ATTACKER_ORIGINS

DEMO_PASSWORD = "demo-only-password"


@pytest.fixture
def vulnerable_app(settings: Settings) -> FastAPI:
    return create_app(
        settings=settings,
        policy=ReflectedOriginPolicy.from_settings(settings),
        writes=SessionOnlyWrites(),
    )


@pytest.fixture
def vulnerable_client(vulnerable_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(vulnerable_app, base_url="https://legacy-api.meridianpay.example") as client:
        yield client


def _login(client: TestClient) -> str:
    response = client.post(
        "/session",
        json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    return response.headers["set-cookie"].split(";")[0].split("=", 1)[1]


def _cookie(value: str) -> dict[str, str]:
    return {"cookie": f"{SESSION_COOKIE_NAME}={value}"}


@pytest.mark.parametrize("origin", ATTACKER_ORIGINS)
def test_the_vulnerable_api_grants_every_attacker_origin(
    vulnerable_client: TestClient, origin: str
) -> None:
    cookie = _login(vulnerable_client)

    response = vulnerable_client.get("/me/payslip", headers={"origin": origin, **_cookie(cookie)})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.json()["api_token"] == "mp_demo_tok_4417_NOT_A_REAL_TOKEN"


def test_the_vulnerable_api_still_sets_vary_origin(vulnerable_client: TestClient) -> None:
    """Its answer depends on the origin more than any correct API's does."""
    response = vulnerable_client.get("/me/payslip", headers={"origin": ATTACKER_ORIGINS[0]})

    assert "origin" in response.headers["vary"].lower()


def test_the_vulnerable_api_audits_nothing_because_it_refuses_nothing(
    vulnerable_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    """A telling silence: there is no refusal to log, so the logs look perfectly clean."""
    capsys.readouterr()
    vulnerable_client.get("/me/payslip", headers={"origin": ATTACKER_ORIGINS[0]})

    assert ORIGIN_REFUSED_EVENT not in capsys.readouterr().out


def test_both_apis_return_identical_payslips_to_the_first_party(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    """The fix must change only the security-relevant behaviour, and this proves it."""
    secure_cookie = _login(client)
    vulnerable_cookie = _login(vulnerable_client)

    secure = client.get(
        "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_cookie(secure_cookie)}
    )
    vulnerable = vulnerable_client.get(
        "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_cookie(vulnerable_cookie)}
    )

    assert secure.status_code == vulnerable.status_code == 200
    assert secure.json() == vulnerable.json()
    assert (
        secure.headers["access-control-allow-origin"]
        == vulnerable.headers["access-control-allow-origin"]
        == FIRST_PARTY_ORIGIN
    )


def test_the_secure_policy_cannot_be_configured_into_the_vulnerable_one(
    settings: Settings,
) -> None:
    """There is no runtime switch from one to the other; they are different objects."""
    secure = ExactMatchAllowlistPolicy.from_settings(settings)

    for origin in ATTACKER_ORIGINS:
        assert not secure.decide(origin).granted

    assert not hasattr(secure, "reflect")
    assert not hasattr(secure, "shape")


def test_the_vulnerable_api_keeps_the_same_authentication_contract(
    vulnerable_client: TestClient,
) -> None:
    """Only the CORS policy differs. Sessions are exactly as strict as the secure API's."""
    responses = [
        vulnerable_client.get("/me/payslip"),
        vulnerable_client.get("/me/payslip", headers=_cookie("not-a-real-token")),
    ]

    for response in responses:
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}


# --- FR-012: the legacy deployment also has no CSRF protection ------------------------
#
# A second, independent fault, and the only way to show that CORS was never standing
# between a cross-site request and a state change. See the PR for the PRD reading taken.

SIMPLE_REQUEST_HEADERS = {"content-type": "text/plain;charset=UTF-8"}
REDIRECTED = '{"bank_name": "Redirected Holdings (fictional)", "account_tail": "0001"}'


def test_the_legacy_deployment_accepts_a_simple_cross_site_post(
    vulnerable_client: TestClient, vulnerable_app: FastAPI
) -> None:
    cookie = _login(vulnerable_client)
    before = vulnerable_app.state.directory.canonical_state()

    response = vulnerable_client.post(
        "/me/payout-account",
        headers={
            "origin": ATTACKER_ORIGINS[0],
            **SIMPLE_REQUEST_HEADERS,
            **_cookie(cookie),
        },
        content=REDIRECTED,
    )

    assert response.status_code == 200
    assert response.json()["account_tail"] == "0001"
    assert vulnerable_app.state.directory.canonical_state() != before


def test_the_secure_deployment_refuses_the_identical_request(
    client: TestClient, secure_app: FastAPI
) -> None:
    cookie = _login(client)
    before = secure_app.state.directory.canonical_state()

    response = client.post(
        "/me/payout-account",
        headers={
            "origin": ATTACKER_ORIGINS[0],
            **SIMPLE_REQUEST_HEADERS,
            **_cookie(cookie),
        },
        content=REDIRECTED,
    )

    assert response.status_code == 415
    assert secure_app.state.directory.canonical_state() == before


def test_the_legacy_deployment_still_requires_a_session(
    vulnerable_client: TestClient, vulnerable_app: FastAPI
) -> None:
    """It is missing CSRF protection, not authentication."""
    before = vulnerable_app.state.directory.canonical_state()

    response = vulnerable_client.post(
        "/me/payout-account", headers=SIMPLE_REQUEST_HEADERS, content=REDIRECTED
    )

    assert response.status_code == 401
    assert vulnerable_app.state.directory.canonical_state() == before


def test_a_fresh_directory_discards_the_attackers_change() -> None:
    """`NFR-001`: the one mutable thing is a disposable fixture, rebuilt every run."""
    from originjack.domain import PayrollDirectory

    pristine = PayrollDirectory.from_fixtures().canonical_state()
    mutated = PayrollDirectory.from_fixtures()
    mutated.set_payout_account(
        VICTIM_EMPLOYEE_ID, bank_name="Redirected Holdings (fictional)", account_tail="0001"
    )

    assert mutated.canonical_state() != pristine
    assert PayrollDirectory.from_fixtures().canonical_state() == pristine


def test_the_two_deployments_report_their_write_policies(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    assert client.get("/healthz").json()["writes"] == "csrf-protected-writes"
    assert vulnerable_client.get("/healthz").json()["writes"] == "legacy-session-only-writes"
