"""Results survive the round trip between passes, in order and without loss."""

from __future__ import annotations

from pathlib import Path

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


def test_a_result_survives_the_round_trip(tmp_path: Path) -> None:
    original = _result(
        "attacker read",
        browser_released=True,
        victim_data_rendered=True,
        decided_by="server",
        verdict="vulnerable",
        shape="shape 1 — origin reflection with credentials",
        screenshot="screenshots/01-a.png",
        notes=("one", "two"),
        observation=NetworkObservation(
            url="https://legacy-api.meridianpay.example/me/payslip",
            status=200,
            allow_origin="https://promo.attacker.example",
            allow_credentials="true",
            request_origin="https://promo.attacker.example",
        ),
    )

    store.save(tmp_path, pass_index=1, label="reflect", results=[original])

    assert store.load_all(tmp_path) == [original]


def test_passes_accumulate_in_order(tmp_path: Path) -> None:
    store.save(tmp_path, pass_index=2, label="sloppy", results=[_result("second")])
    store.save(tmp_path, pass_index=1, label="reflect", results=[_result("first")])
    store.save(tmp_path, pass_index=3, label="null", results=[_result("third")])

    assert [r.name for r in store.load_all(tmp_path)] == ["first", "second", "third"]


def test_clearing_discards_an_earlier_run(tmp_path: Path) -> None:
    store.save(tmp_path, pass_index=1, label="reflect", results=[_result("stale")])

    store.clear(tmp_path)

    assert store.load_all(tmp_path) == []


def test_loading_an_empty_artifacts_directory_is_not_an_error(tmp_path: Path) -> None:
    assert store.load_all(tmp_path) == []
    store.clear(tmp_path)


def test_a_result_without_an_observation_round_trips(tmp_path: Path) -> None:
    store.save(tmp_path, pass_index=1, label="reflect", results=[_result("bare")])

    loaded = store.load_all(tmp_path)

    assert loaded[0].observation is None
    assert loaded[0].notes == ()
