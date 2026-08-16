"""The secure API's observable HTTP contract.

SLICE-001 is verified through the HTTP boundary: these tests assert what the server
sends. A later slice puts a real browser in front of the same services and asserts what
the browser then *does* with it, which is the only way to show impact.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from originjack.audit import ORIGIN_REFUSED_EVENT
from originjack.config import FIRST_PARTY_ORIGIN, SESSION_COOKIE_NAME
from originjack.domain import VICTIM_EMPLOYEE_ID, PayrollDirectory
from originjack.sessions import encode, issue
from tests.conftest import REFUSED_ORIGINS

ATTACKER_ORIGIN = "https://promo.attacker.example"
DEMO_PASSWORD = "demo-only-password"


def _login(client: TestClient) -> tuple[str, str]:
    """Return the raw session cookie value and the session's CSRF token."""
    response = client.post(
        "/session",
        json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    cookie_value = response.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    return cookie_value, response.json()["csrf_token"]


def _cookie_header(value: str) -> dict[str, str]:
    return {"cookie": f"{SESSION_COOKIE_NAME}={value}"}


def _refusal_events(captured: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw in captured.splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("event") == ORIGIN_REFUSED_EVENT:
            events.append(record)
    return events


def _directory(app: FastAPI) -> PayrollDirectory:
    return cast(PayrollDirectory, app.state.directory)


# --- health and session ---------------------------------------------------------------


def test_healthz_reports_the_installed_policy(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "policy": "secure-exact-match-allowlist"}


def test_login_issues_a_cross_site_session_cookie(client: TestClient) -> None:
    response = client.post(
        "/session",
        json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": DEMO_PASSWORD},
    )

    assert response.status_code == 200
    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith(f"{SESSION_COOKIE_NAME}=")
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=None" in set_cookie
    assert "Path=/" in set_cookie


def test_login_rejects_wrong_demo_credentials(client: TestClient) -> None:
    response = client.post(
        "/session", json={"employee_id": VICTIM_EMPLOYEE_ID, "demo_password": "wrong"}
    )

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert "set-cookie" not in response.headers


# --- the four rejection shapes --------------------------------------------------------


def test_all_bad_sessions_get_one_indistinguishable_401(
    client: TestClient, secure_app: FastAPI
) -> None:
    key = secure_app.state.settings.session_signing_key

    expired = encode(issue(VICTIM_EMPLOYEE_ID, ttl_seconds=-60), key=key)
    unknown = encode(issue("EMP-0000", ttl_seconds=3600), key=key)

    responses = {
        "missing": client.get("/me/payslip"),
        "malformed": client.get("/me/payslip", headers=_cookie_header("not-a-real-token")),
        "expired": client.get("/me/payslip", headers=_cookie_header(expired)),
        "unknown": client.get("/me/payslip", headers=_cookie_header(unknown)),
    }

    for shape, response in responses.items():
        assert response.status_code == 401, shape
        assert response.json() == {"error": "unauthorized"}, shape

    bodies = {response.text for response in responses.values()}
    assert len(bodies) == 1, "the four rejection shapes must be indistinguishable"


# --- the cross-origin decision --------------------------------------------------------


def test_allowlisted_origin_is_granted_a_credentialed_read(client: TestClient) -> None:
    cookie, _ = _login(client)

    response = client.get(
        "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_cookie_header(cookie)}
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "origin" in response.headers["vary"].lower()

    payload = response.json()
    assert payload["employee_id"] == VICTIM_EMPLOYEE_ID
    assert payload["payslip"]["net_pay_minor"] == 371_845
    assert payload["payout_account"]["account_tail"] == "8842"
    assert payload["api_token"] == "mp_demo_tok_4417_NOT_A_REAL_TOKEN"


@pytest.mark.parametrize("origin", REFUSED_ORIGINS)
def test_non_allowlisted_origin_receives_no_grant(client: TestClient, origin: str) -> None:
    cookie, _ = _login(client)

    response = client.get("/me/payslip", headers={"origin": origin, **_cookie_header(cookie)})

    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers
    assert "origin" in response.headers["vary"].lower()


def test_vary_origin_is_present_even_on_a_refusal(client: TestClient) -> None:
    response = client.get("/healthz", headers={"origin": ATTACKER_ORIGIN})

    assert "access-control-allow-origin" not in response.headers
    assert "origin" in response.headers["vary"].lower()


def test_the_server_behaves_identically_and_offers_no_allowlist_oracle(
    client: TestClient,
) -> None:
    """Only the browser-facing grant differs; the server's answer does not.

    If a refused origin could tell it had been refused by anything other than the
    missing ``Access-Control-Allow-Origin`` — a different status, body, or header set —
    the API would be leaking its allowlist.
    """
    cookie, _ = _login(client)

    granted = client.get(
        "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_cookie_header(cookie)}
    )
    refused = client.get(
        "/me/payslip", headers={"origin": ATTACKER_ORIGIN, **_cookie_header(cookie)}
    )

    assert granted.status_code == refused.status_code
    assert granted.json() == refused.json()

    differing = {
        name
        for name in set(granted.headers) | set(refused.headers)
        if granted.headers.get(name) != refused.headers.get(name)
    }
    assert differing <= {
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "x-request-id",
        "date",
    }


# --- preflight ------------------------------------------------------------------------


def test_preflight_from_the_allowlisted_origin_is_narrow(client: TestClient) -> None:
    response = client.options(
        "/me/payout-account",
        headers={
            "origin": FIRST_PARTY_ORIGIN,
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-meridian-csrf",
        },
    )

    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["access-control-allow-methods"] == "GET, POST"
    assert response.headers["access-control-allow-headers"] == "content-type, x-meridian-csrf"
    assert response.headers["access-control-max-age"] == "60"


def test_preflight_from_an_attacker_origin_grants_nothing(client: TestClient) -> None:
    response = client.options(
        "/me/payout-account",
        headers={"origin": ATTACKER_ORIGIN, "access-control-request-method": "POST"},
    )

    assert response.status_code == 204
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-methods" not in response.headers


def test_a_grant_never_widens_on_preflight(client: TestClient) -> None:
    """A preflight cannot be used to talk the policy into more than it already allows."""
    response = client.options(
        "/me/payslip",
        headers={
            "origin": FIRST_PARTY_ORIGIN,
            "access-control-request-method": "DELETE",
            "access-control-request-headers": "x-anything-else",
        },
    )

    assert response.headers["access-control-allow-methods"] == "GET, POST"
    assert response.headers["access-control-allow-headers"] == "content-type, x-meridian-csrf"


# --- the refused-origin audit event ---------------------------------------------------


def test_exactly_one_audit_event_per_refused_request(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    client.get("/me/payslip", headers={"origin": ATTACKER_ORIGIN})

    events = _refusal_events(capsys.readouterr().out)
    assert len(events) == 1
    assert events[0]["refused_origin"] == ATTACKER_ORIGIN
    assert events[0]["path"] == "/me/payslip"
    assert events[0]["preflight"] is False


def test_a_refused_preflight_is_audited_once(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    client.options(
        "/me/payout-account",
        headers={"origin": ATTACKER_ORIGIN, "access-control-request-method": "POST"},
    )

    events = _refusal_events(capsys.readouterr().out)
    assert len(events) == 1
    assert events[0]["preflight"] is True


def test_a_granted_request_is_never_audited_as_a_refusal(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    client.get("/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN})

    assert _refusal_events(capsys.readouterr().out) == []


def test_a_request_without_an_origin_is_not_a_refusal(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    client.get("/healthz")

    assert _refusal_events(capsys.readouterr().out) == []


def test_audit_output_carries_no_credential(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    cookie, csrf = _login(client)
    capsys.readouterr()

    client.get("/me/payslip", headers={"origin": ATTACKER_ORIGIN, **_cookie_header(cookie)})
    captured = capsys.readouterr().out

    assert cookie not in captured
    assert csrf not in captured
    assert "mp_demo_tok_4417_NOT_A_REAL_TOKEN" not in captured


# --- the state-changing route ---------------------------------------------------------


def test_the_first_party_can_change_the_payout_account(client: TestClient) -> None:
    cookie, csrf = _login(client)

    response = client.post(
        "/me/payout-account",
        headers={
            "origin": FIRST_PARTY_ORIGIN,
            "content-type": "application/json",
            "x-meridian-csrf": csrf,
            **_cookie_header(cookie),
        },
        json={"bank_name": "Ledgerbrook Mutual (fictional)", "account_tail": "7311"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "bank_name": "Ledgerbrook Mutual (fictional)",
        "account_tail": "7311",
    }
    assert response.headers["access-control-allow-origin"] == FIRST_PARTY_ORIGIN


def test_a_simple_cross_site_post_cannot_reach_the_state_change(
    client: TestClient, secure_app: FastAPI
) -> None:
    """The shape a cross-site form can send: a simple content type and no custom header.

    CORS would not have stopped it — CORS governs reading a response, not sending a
    request — so the route itself has to, and does.
    """
    cookie, _ = _login(client)
    before = _directory(secure_app).canonical_state()

    response = client.post(
        "/me/payout-account",
        headers={
            "origin": ATTACKER_ORIGIN,
            "content-type": "text/plain;charset=UTF-8",
            **_cookie_header(cookie),
        },
        content='{"bank_name": "Redirected Holdings (fictional)", "account_tail": "0001"}',
    )

    assert response.status_code == 415
    assert _directory(secure_app).canonical_state() == before


def test_json_without_a_matching_csrf_token_is_refused(
    client: TestClient, secure_app: FastAPI
) -> None:
    cookie, _ = _login(client)
    before = _directory(secure_app).canonical_state()

    missing = client.post(
        "/me/payout-account",
        headers={"content-type": "application/json", **_cookie_header(cookie)},
        json={"bank_name": "Redirected Holdings (fictional)", "account_tail": "0001"},
    )
    wrong = client.post(
        "/me/payout-account",
        headers={
            "content-type": "application/json",
            "x-meridian-csrf": "not-the-right-token",
            **_cookie_header(cookie),
        },
        json={"bank_name": "Redirected Holdings (fictional)", "account_tail": "0001"},
    )

    assert missing.status_code == 403
    assert wrong.status_code == 403
    assert _directory(secure_app).canonical_state() == before


def test_the_state_change_validates_its_input(client: TestClient) -> None:
    cookie, csrf = _login(client)
    headers = {
        "content-type": "application/json",
        "x-meridian-csrf": csrf,
        **_cookie_header(cookie),
    }

    for body in (
        {"bank_name": "", "account_tail": "1234"},
        {"bank_name": "Ledgerbrook Mutual (fictional)", "account_tail": "12"},
        {"bank_name": "Ledgerbrook Mutual (fictional)", "account_tail": "abcd"},
        {"bank_name": 42, "account_tail": "1234"},
    ):
        response = client.post("/me/payout-account", headers=headers, json=body)
        assert response.status_code == 400, body


def test_an_unauthenticated_state_change_is_a_generic_401(client: TestClient) -> None:
    response = client.post(
        "/me/payout-account",
        headers={"content-type": "application/json", "x-meridian-csrf": "anything"},
        json={"bank_name": "Redirected Holdings (fictional)", "account_tail": "0001"},
    )

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


# --- canonical state ------------------------------------------------------------------


def test_refused_cross_origin_traffic_leaves_canonical_state_untouched(
    client: TestClient, secure_app: FastAPI
) -> None:
    cookie, _ = _login(client)
    before = _directory(secure_app).canonical_state()

    for origin in REFUSED_ORIGINS:
        client.get("/me/payslip", headers={"origin": origin, **_cookie_header(cookie)})
        client.options(
            "/me/payout-account",
            headers={"origin": origin, "access-control-request-method": "POST"},
        )

    assert _directory(secure_app).canonical_state() == before


def test_legitimate_reads_leave_canonical_state_untouched(
    client: TestClient, secure_app: FastAPI
) -> None:
    cookie, _ = _login(client)
    before = _directory(secure_app).canonical_state()

    for _ in range(3):
        assert (
            client.get(
                "/me/payslip", headers={"origin": FIRST_PARTY_ORIGIN, **_cookie_header(cookie)}
            ).status_code
            == 200
        )

    assert _directory(secure_app).canonical_state() == before
