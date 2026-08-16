"""The Meridian Payroll API surface, shared by every CORS policy the demo ships.

The routes, the domain, the session contract, and the payloads are identical whatever
policy is installed. Only the policy differs — which is the point: when a later slice
adds the misconfigured variants, the difference between "safe" and "catastrophic" is one
object, not one behaviour.
"""

from __future__ import annotations

import json
from typing import Any, Final
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from originjack import audit, sessions
from originjack.config import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, Settings
from originjack.cors import CorsPolicy, response_headers
from originjack.domain import PayrollDirectory, UnknownEmployeeError
from originjack.sessions import Session, SessionError

MAX_BODY_BYTES: Final = 4096


def _generic_unauthorized() -> JSONResponse:
    """One indistinguishable answer for missing, malformed, expired, and unknown."""
    return JSONResponse({"error": "unauthorized"}, status_code=401)


def _append_vary_origin(response: Response) -> None:
    """``Vary: Origin`` on every response, granted or refused.

    Always, not only on grants: the response body and headers depend on the request's
    origin, so any shared cache has to be told, or it will hand one origin's answer to
    another.
    """
    existing = response.headers.get("vary")
    if existing is None:
        response.headers["vary"] = "Origin"
        return
    if "origin" not in {part.strip().lower() for part in existing.split(",")}:
        response.headers["vary"] = f"{existing}, Origin"


class CrossOriginBoundary(BaseHTTPMiddleware):
    """Applies the installed policy's decision to every response, and audits refusals.

    Deliberately hand-written rather than delegated to a framework CORS middleware, so
    the vulnerable/secure contrast a later slice introduces reads as a diff.
    """

    def __init__(self, app: ASGIApp, *, policy: CorsPolicy) -> None:
        super().__init__(app)
        self._policy = policy

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id") or uuid4().hex
        origin = request.headers.get("origin")
        is_preflight = (
            request.method == "OPTIONS" and "access-control-request-method" in request.headers
        )

        decision = self._policy.decide(origin)
        request.state.request_id = request_id
        request.state.cors_decision = decision

        response = await call_next(request)

        for name, value in response_headers(decision, preflight=is_preflight).items():
            response.headers[name] = value
        _append_vary_origin(response)
        response.headers["x-request-id"] = request_id

        # Exactly one refusal record per refused cross-origin request (FR-014). A
        # request with no Origin header is not a cross-origin request and is not audited
        # as a refusal.
        if origin is not None and not decision.granted:
            audit.emit_origin_refused(
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                origin=origin,
                preflight=is_preflight,
            )

        audit.emit_request_completed(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            cross_origin=origin is not None,
        )
        return response


def build_session_cookie(token: str, *, samesite: str, max_age: int) -> str:
    """Build the ``Set-Cookie`` value by hand, so the attributes are readable as such.

    ``SameSite=None`` demands ``Secure``, and ``Secure`` demands a trustworthy origin —
    which is why every origin in this demo is served over HTTPS. This is the ordinary
    configuration for an API whose browser application lives on another origin, and it
    is the precondition that makes a CORS misconfiguration exploitable.
    """
    return "; ".join(
        (
            f"{SESSION_COOKIE_NAME}={token}",
            "Path=/",
            f"Max-Age={max_age}",
            "HttpOnly",
            "Secure",
            f"SameSite={samesite.title()}",
        )
    )


def create_app(*, settings: Settings, policy: CorsPolicy) -> FastAPI:
    """Build the API with ``policy`` installed as its cross-origin decision."""
    directory = PayrollDirectory.from_fixtures()

    app = FastAPI(
        title="Meridian Payroll API (fictional demonstration service)",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.policy = policy
    app.state.directory = directory
    app.add_middleware(CrossOriginBoundary, policy=policy)

    def resolve_session(request: Request) -> Session | None:
        """Missing, malformed, expired, and unknown all collapse to ``None``."""
        raw = request.cookies.get(SESSION_COOKIE_NAME)
        if raw is None:
            return None
        try:
            session = sessions.decode(raw, key=settings.session_signing_key)
        except SessionError:
            return None
        try:
            directory.employee(session.employee_id)
        except UnknownEmployeeError:
            return None
        return session

    async def read_json_body(request: Request) -> dict[str, Any] | None:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return None
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "policy": policy.name})

    @app.options("/{rest_of_path:path}")
    async def preflight(rest_of_path: str) -> Response:
        """Answer every preflight identically.

        The grant headers, if any, are attached by :class:`CrossOriginBoundary`. The
        status is the same either way, so the response body is never an allowlist
        oracle — the presence of ``Access-Control-Allow-Origin`` *is* the grant, and
        nothing else distinguishes the two answers.
        """
        return Response(status_code=204)

    @app.post("/session")
    async def create_session(request: Request) -> Response:
        """Demo-only login. Not production authentication, and never pretends to be."""
        body = await read_json_body(request)
        if body is None:
            return _generic_unauthorized()

        employee_id = body.get("employee_id")
        demo_password = body.get("demo_password")
        if not isinstance(employee_id, str) or not isinstance(demo_password, str):
            return _generic_unauthorized()

        employee = directory.authenticate(employee_id, demo_password)
        if employee is None:
            return _generic_unauthorized()

        session = sessions.issue(employee.employee_id, ttl_seconds=settings.session_ttl_seconds)
        response = JSONResponse(
            {
                "employee_id": employee.employee_id,
                "display_name": employee.display_name,
                "job_title": employee.job_title,
                "csrf_token": session.csrf_token,
            }
        )
        response.headers.append(
            "set-cookie",
            build_session_cookie(
                sessions.encode(session, key=settings.session_signing_key),
                samesite=settings.session_samesite,
                max_age=settings.session_ttl_seconds,
            ),
        )
        return response

    @app.get("/me/payslip")
    async def read_payslip(request: Request) -> Response:
        """The read whose exposure the whole demonstration is about."""
        session = resolve_session(request)
        if session is None:
            return _generic_unauthorized()

        employee = directory.employee(session.employee_id)
        account = directory.payout_account(session.employee_id)
        return JSONResponse(
            {
                "employee_id": employee.employee_id,
                "display_name": employee.display_name,
                "job_title": employee.job_title,
                "payslip": {
                    "period": employee.payslip.period,
                    "currency": employee.payslip.currency,
                    "gross_pay_minor": employee.payslip.gross_pay_minor,
                    "net_pay_minor": employee.payslip.net_pay_minor,
                    "tax_reference": employee.payslip.tax_reference,
                },
                "payout_account": {
                    "bank_name": account.bank_name,
                    "account_tail": account.account_tail,
                },
                "api_token": employee.api_token,
            }
        )

    @app.post("/me/payout-account")
    async def change_payout_account(request: Request) -> Response:
        """The state-changing route, deliberately unreachable by a *simple* request.

        It requires ``application/json`` and a matching ``X-Meridian-CSRF`` header —
        neither of which a simple cross-site request can carry — because CORS governs
        whether a response may be *read*, never whether a request may be *sent*.
        """
        session = resolve_session(request)
        if session is None:
            return _generic_unauthorized()

        media_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if media_type != "application/json":
            return JSONResponse({"error": "unsupported_media_type"}, status_code=415)

        if not sessions.csrf_token_matches(session, request.headers.get(CSRF_HEADER_NAME)):
            return JSONResponse({"error": "forbidden"}, status_code=403)

        body = await read_json_body(request)
        if body is None:
            return JSONResponse({"error": "bad_request"}, status_code=400)

        bank_name = body.get("bank_name")
        account_tail = body.get("account_tail")
        if (
            not isinstance(bank_name, str)
            or not isinstance(account_tail, str)
            or not bank_name.strip()
            or not account_tail.isdigit()
            or len(account_tail) != 4
        ):
            return JSONResponse({"error": "bad_request"}, status_code=400)

        updated = directory.set_payout_account(
            session.employee_id, bank_name=bank_name.strip(), account_tail=account_tail
        )
        return JSONResponse({"bank_name": updated.bank_name, "account_tail": updated.account_tail})

    return app
