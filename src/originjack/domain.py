"""The fictional Meridian Payroll domain and its deterministic fixtures.

Meridian Payroll does not exist. Every employee, figure, tax reference, bank, account
tail, and API token below is invented for this demonstration, and the directory is
rebuilt from these fixtures every time a service starts, so a run never inherits state
from the run before it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from typing import Final


@dataclass(frozen=True, slots=True)
class Payslip:
    """One period's pay for one fictional employee."""

    period: str
    currency: str
    gross_pay_minor: int
    net_pay_minor: int
    tax_reference: str


@dataclass(frozen=True, slots=True)
class PayoutAccount:
    """Where a fictional employee's pay is sent. The only mutable domain state."""

    bank_name: str
    account_tail: str


@dataclass(frozen=True, slots=True)
class Employee:
    """A fictional Meridian Payroll employee and their demo-only credentials."""

    employee_id: str
    display_name: str
    job_title: str
    demo_password: str
    api_token: str
    payslip: Payslip


#: Deterministic fixtures. Stable ordering, stable values, stable counts across runs, so
#: every payload the demonstration renders is reproducible (FR-001).
FIXTURE_EMPLOYEES: Final[tuple[Employee, ...]] = (
    Employee(
        employee_id="EMP-4417",
        display_name="Rowan Ashcombe",
        job_title="Senior Payroll Analyst",
        demo_password="demo-only-password",
        api_token="mp_demo_tok_4417_NOT_A_REAL_TOKEN",
        payslip=Payslip(
            period="2026-07",
            currency="GBP",
            gross_pay_minor=512_300,
            net_pay_minor=371_845,
            tax_reference="TAXREF-DEMO-4417",
        ),
    ),
    Employee(
        employee_id="EMP-2093",
        display_name="Ines Okonkwo",
        job_title="Payroll Operations Lead",
        demo_password="demo-only-password",
        api_token="mp_demo_tok_2093_NOT_A_REAL_TOKEN",
        payslip=Payslip(
            period="2026-07",
            currency="GBP",
            gross_pay_minor=634_000,
            net_pay_minor=451_902,
            tax_reference="TAXREF-DEMO-2093",
        ),
    ),
)

FIXTURE_PAYOUT_ACCOUNTS: Final[dict[str, PayoutAccount]] = {
    "EMP-4417": PayoutAccount(bank_name="Ledgerbrook Mutual (fictional)", account_tail="8842"),
    "EMP-2093": PayoutAccount(bank_name="Ledgerbrook Mutual (fictional)", account_tail="1160"),
}

#: The employee the walkthrough logs in as.
VICTIM_EMPLOYEE_ID: Final = "EMP-4417"


class UnknownEmployeeError(KeyError):
    """Raised when a session names an employee the directory does not hold."""


class PayrollDirectory:
    """In-memory fictional payroll state, recreated from fixtures on every start."""

    def __init__(
        self,
        employees: tuple[Employee, ...],
        payout_accounts: dict[str, PayoutAccount],
    ) -> None:
        self._employees: dict[str, Employee] = {e.employee_id: e for e in employees}
        self._payout_accounts: dict[str, PayoutAccount] = dict(payout_accounts)

    @classmethod
    def from_fixtures(cls) -> PayrollDirectory:
        """Build a directory that is byte-identical on every run."""
        return cls(FIXTURE_EMPLOYEES, FIXTURE_PAYOUT_ACCOUNTS)

    def employee(self, employee_id: str) -> Employee:
        try:
            return self._employees[employee_id]
        except KeyError as exc:
            raise UnknownEmployeeError(employee_id) from exc

    def authenticate(self, employee_id: str, demo_password: str) -> Employee | None:
        """Check demo-only credentials. Returns ``None`` for any failure, uniformly."""
        employee = self._employees.get(employee_id)
        if employee is None or employee.demo_password != demo_password:
            return None
        return employee

    def payout_account(self, employee_id: str) -> PayoutAccount:
        if employee_id not in self._employees:
            raise UnknownEmployeeError(employee_id)
        return self._payout_accounts[employee_id]

    def set_payout_account(
        self, employee_id: str, *, bank_name: str, account_tail: str
    ) -> PayoutAccount:
        """Change the one piece of mutable, disposable, fictional state in the demo."""
        current = self.payout_account(employee_id)
        updated = replace(current, bank_name=bank_name, account_tail=account_tail)
        self._payout_accounts[employee_id] = updated
        return updated

    def canonical_state(self) -> str:
        """A deterministic serialization of all domain state.

        Used to show that a secure-path or legitimate-path run leaves canonical state
        byte-for-byte unchanged. It is intentionally *not* reachable over HTTP: the demo
        exposes no state-inspection endpoint.
        """
        return json.dumps(
            {
                "employees": [asdict(self._employees[k]) for k in sorted(self._employees)],
                "payout_accounts": {
                    k: asdict(self._payout_accounts[k]) for k in sorted(self._payout_accounts)
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
