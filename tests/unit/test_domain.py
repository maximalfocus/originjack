"""Fixtures are deterministic, and the payout account is the only mutable state."""

from __future__ import annotations

import pytest

from originjack.domain import (
    FIXTURE_EMPLOYEES,
    VICTIM_EMPLOYEE_ID,
    PayrollDirectory,
    UnknownEmployeeError,
)


def test_fixtures_rebuild_identically_on_every_start() -> None:
    assert PayrollDirectory.from_fixtures().canonical_state() == (
        PayrollDirectory.from_fixtures().canonical_state()
    )


def test_fixture_counts_and_ordering_are_stable() -> None:
    assert len(FIXTURE_EMPLOYEES) == 2
    assert [e.employee_id for e in FIXTURE_EMPLOYEES] == ["EMP-4417", "EMP-2093"]
    assert VICTIM_EMPLOYEE_ID == "EMP-4417"


def test_authentication_accepts_only_the_demo_credentials() -> None:
    directory = PayrollDirectory.from_fixtures()

    assert directory.authenticate("EMP-4417", "demo-only-password") is not None
    assert directory.authenticate("EMP-4417", "wrong") is None
    assert directory.authenticate("EMP-0000", "demo-only-password") is None


def test_unknown_employee_is_a_distinct_error() -> None:
    directory = PayrollDirectory.from_fixtures()

    with pytest.raises(UnknownEmployeeError):
        directory.employee("EMP-0000")

    with pytest.raises(UnknownEmployeeError):
        directory.payout_account("EMP-0000")


def test_only_the_payout_account_changes_canonical_state() -> None:
    directory = PayrollDirectory.from_fixtures()
    before = directory.canonical_state()

    directory.employee(VICTIM_EMPLOYEE_ID)
    directory.payout_account(VICTIM_EMPLOYEE_ID)
    assert directory.canonical_state() == before

    updated = directory.set_payout_account(
        VICTIM_EMPLOYEE_ID, bank_name="Redirected Holdings (fictional)", account_tail="0001"
    )

    assert updated.account_tail == "0001"
    assert directory.canonical_state() != before


def test_a_fresh_directory_discards_the_change() -> None:
    directory = PayrollDirectory.from_fixtures()
    pristine = directory.canonical_state()
    directory.set_payout_account(
        VICTIM_EMPLOYEE_ID, bank_name="Redirected Holdings (fictional)", account_tail="0001"
    )

    assert PayrollDirectory.from_fixtures().canonical_state() == pristine


def test_fixture_values_are_conspicuously_fake() -> None:
    for employee in FIXTURE_EMPLOYEES:
        assert "NOT_A_REAL_TOKEN" in employee.api_token
        assert employee.demo_password.startswith("demo-only")
        assert employee.payslip.tax_reference.startswith("TAXREF-DEMO-")
