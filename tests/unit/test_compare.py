"""The comparison table, exercised directly rather than through a terminal.

`FR-015` asks for the scenario engine to be testable without terminal-input simulation,
and this is what that buys: the table is a pure function of recorded scenarios, so every
column can be pinned exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from originjack.compare import build_parser, main, render, render_exchanges, render_table
from originjack.harness import store
from originjack.harness.models import NetworkObservation, ScenarioResult


def _result(name: str, **overrides: object) -> ScenarioResult:
    base: dict[str, object] = {
        "name": name,
        "summary": "a scenario",
        "calling_origin": "https://promo.attacker.example",
        "credential_mode": "include",
        "preflight": False,
        "browser_released": False,
        "victim_data_rendered": False,
        "state_changed": False,
        "decided_by": "browser",
        "verdict": "secure",
    }
    base.update(overrides)
    return ScenarioResult(**base)  # type: ignore[arg-type]


EXPOSED = _result(
    "attacker read (vulnerable API)",
    browser_released=True,
    victim_data_rendered=True,
    decided_by="server",
    verdict="vulnerable",
    shape="shape 1 — origin reflection with credentials",
    decider_detail="it echoed the caller's own origin back as an allowed one",
    screenshot="screenshots/01-a.png",
    notes=("only the Origin differs",),
    observation=NetworkObservation(
        url="https://legacy-api.meridianpay.example/me/payslip",
        status=200,
        allow_origin="https://promo.attacker.example",
        allow_credentials="true",
        request_origin="https://promo.attacker.example",
    ),
)

BLOCKED = _result(
    "attacker read (secure API)",
    observation=NetworkObservation(
        url="https://api.meridianpay.example/me/payslip",
        status=200,
        failure="net::ERR_FAILED",
    ),
)


# --- the table ------------------------------------------------------------------------


def test_every_required_column_is_present() -> None:
    """`FR-015` names each of these explicitly."""
    header = render_table([EXPOSED]).splitlines()[0]

    for column in ("scenario", "calling origin", "cred", "pre", "ACAO", "ACAC"):
        assert column in header
    for column in ("rel", "data", "state", "decided", "verdict"):
        assert column in header


def test_a_released_row_reports_what_the_page_obtained() -> None:
    row = render_table([EXPOSED]).splitlines()[2]

    assert "attacker read (vulnerable API)" in row
    assert "promo.attacker.example" in row
    assert "include" in row
    assert "true" in row
    assert "YES" in row  # victim data rendered
    assert "VULNERABLE" in row


def test_a_withheld_row_reports_absent_headers_rather_than_blanks() -> None:
    row = render_table([BLOCKED]).splitlines()[2]

    assert "—" in row
    assert "SECURE" in row
    assert "browser" in row


def test_the_decided_column_distinguishes_the_two_deciders() -> None:
    """`NFR-004`: where the browser decided rather than the server, say so."""
    lines = render_table([EXPOSED, BLOCKED]).splitlines()

    assert "server" in lines[2]
    assert "browser" in lines[3]


def test_the_table_is_deterministic() -> None:
    assert render_table([EXPOSED, BLOCKED]) == render_table([EXPOSED, BLOCKED])


def test_the_table_survives_an_empty_scenario_set() -> None:
    assert render_table([]) == "(no scenarios recorded)"


def test_columns_align_across_rows_of_different_widths() -> None:
    lines = render_table([EXPOSED, BLOCKED]).splitlines()
    widths = {len(line.rstrip()) for line in lines}

    assert len(lines) == 4
    # The separator is the full width; rows may be shorter only by trailing trim.
    assert max(widths) == len(lines[1])


# --- the whole rendering --------------------------------------------------------------


def test_the_default_output_carries_narrative_table_and_legend() -> None:
    output = render([EXPOSED, BLOCKED])

    assert "originjack — cross-origin comparison" in output
    assert "Two response headers decide everything" in output
    assert "decided  which component decided the outcome" in output
    assert "2 scenarios — 1 secure, 1 vulnerable" in output


def test_the_narrative_explains_the_decided_column() -> None:
    """It is the column a reader is most likely to skim past and most needs."""
    output = render([EXPOSED])

    assert "the browser withheld the answer from the page" in output


def test_verbose_adds_the_underlying_exchange() -> None:
    plain = render([EXPOSED])
    verbose = render([EXPOSED], verbose=True)

    assert "Underlying exchanges" not in plain
    assert "Underlying exchanges" in verbose
    assert "https://legacy-api.meridianpay.example/me/payslip" in verbose
    assert "sent-Origin=https://promo.attacker.example" in verbose
    assert "screenshots/01-a.png" in verbose
    assert "only the Origin differs" in verbose


def test_the_exchange_reports_the_deciders_own_words() -> None:
    exchanges = render_exchanges([EXPOSED])

    assert "server — it echoed the caller's own origin back as an allowed one" in exchanges


def test_an_unobserved_exchange_says_so_rather_than_inventing_one() -> None:
    exchanges = render_exchanges([_result("nothing observed")])

    assert "(not observed)" in exchanges


# --- the command line -----------------------------------------------------------------


def test_compare_reads_the_recorded_scenarios(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store.save(tmp_path, pass_index=1, label="reflect", results=[EXPOSED, BLOCKED])

    assert main(["compare", "--artifacts", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "attacker read (vulnerable API)" in output
    assert "2 scenarios — 1 secure, 1 vulnerable" in output


def test_compare_accumulates_across_passes_in_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store.save(tmp_path, pass_index=2, label="sloppy", results=[BLOCKED])
    store.save(tmp_path, pass_index=1, label="reflect", results=[EXPOSED])

    assert main(["compare", "--artifacts", str(tmp_path)]) == 0

    rows = [line for line in capsys.readouterr().out.splitlines() if line.startswith(("1 ", "2 "))]
    assert "attacker read (vulnerable API)" in rows[0]
    assert "attacker read (secure API)" in rows[1]


def test_compare_refuses_to_invent_a_table_with_nothing_to_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The comparison reports what a browser did, so a browser has to have done it."""
    assert main(["compare", "--artifacts", str(tmp_path)]) == 1
    assert "Run ./scripts/demo.sh first" in capsys.readouterr().err


def test_verbose_is_available_from_the_command_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store.save(tmp_path, pass_index=1, label="reflect", results=[EXPOSED])

    assert main(["compare", "--artifacts", str(tmp_path), "--verbose"]) == 0
    assert "Underlying exchanges" in capsys.readouterr().out


def test_the_parser_requires_a_command() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
