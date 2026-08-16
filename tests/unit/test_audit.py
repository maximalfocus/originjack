"""The audit log is structured, correlatable, and cannot carry a credential."""

from __future__ import annotations

import io
import json

import pytest

from originjack import audit
from originjack.audit import (
    ORIGIN_REFUSED_EVENT,
    ForbiddenAuditFieldError,
    emit,
    emit_origin_refused,
)


def test_records_are_one_line_of_json() -> None:
    stream = io.StringIO()
    emit("demo.event", stream=stream, request_id="abc", detail="value")

    written = stream.getvalue()
    assert written.count("\n") == 1
    record = json.loads(written)
    assert record["event"] == "demo.event"
    assert record["request_id"] == "abc"
    assert record["ts"].endswith("Z")


@pytest.mark.parametrize(
    "field",
    ["cookie", "Set-Cookie", "authorization", "session_token", "api_token", "csrf_token", "secret"],
)
def test_credential_bearing_fields_are_refused(field: str) -> None:
    with pytest.raises(ForbiddenAuditFieldError):
        emit("demo.event", stream=io.StringIO(), **{field: "anything"})


def test_refusal_record_shape() -> None:
    stream = io.StringIO()
    record = emit_origin_refused(
        request_id="req-1",
        method="GET",
        path="/me/payslip",
        origin="https://promo.attacker.example",
        preflight=False,
        stream=stream,
    )

    assert record["event"] == ORIGIN_REFUSED_EVENT
    assert record["refused_origin"] == "https://promo.attacker.example"
    assert record["outcome"] == "cross_origin_response_withheld"
    assert record["reason"] == "origin_not_allowlisted"
    assert json.loads(stream.getvalue()) == record


def test_refusal_record_names_no_accepted_origin_and_leaks_no_allowlist() -> None:
    """FR-014: the event identifies the refused request, and tells the reader nothing else.

    In particular it must not become an oracle that reveals which origins *would* have
    been accepted. A fixed field set is the check that matters: a record that cannot
    carry an extra field cannot grow into a disclosure later. (The ``reason`` code says
    *why* a request was refused; naming the rule is not disclosing the rule's contents.)
    """
    stream = io.StringIO()
    record = emit_origin_refused(
        request_id="req-1",
        method="GET",
        path="/me/payslip",
        origin="https://promo.attacker.example",
        preflight=False,
        stream=stream,
    )
    written = stream.getvalue()

    assert set(record) == {
        "ts",
        "event",
        "request_id",
        "method",
        "path",
        "refused_origin",
        "preflight",
        "outcome",
        "reason",
    }
    assert "app.meridianpay.example" not in written
    for leaked in ("mp_session", "csrf", "cookie", "password", "mp_demo_tok"):
        assert leaked not in written.lower()


def test_forbidden_field_names_cover_the_obvious_credentials() -> None:
    assert {"cookie", "authorization", "session_token", "api_token"} <= audit.FORBIDDEN_FIELDS
