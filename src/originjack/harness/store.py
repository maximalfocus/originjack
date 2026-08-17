"""Accumulating results across the demonstration's passes.

The three misconfiguration shapes are mutually exclusive, so the vulnerable API is
recreated between them and the harness runs once per shape. Each pass writes its own
results file and then re-renders the transcript from *all* of them, so the final artifact
is one document covering every scenario in order rather than a pile of fragments.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any, Final

from originjack.harness.models import NetworkObservation, ScenarioResult

RESULTS_DIRNAME: Final = "results"


def results_dir(artifacts_dir: Path) -> Path:
    return artifacts_dir / RESULTS_DIRNAME


def clear(artifacts_dir: Path) -> None:
    """Discard any earlier run's results, so a fresh run cannot inherit them."""
    directory = results_dir(artifacts_dir)
    if not directory.is_dir():
        return
    for path in directory.glob("*.json"):
        path.unlink()


def save(
    artifacts_dir: Path,
    *,
    pass_index: int,
    label: str,
    results: Sequence[ScenarioResult],
) -> Path:
    directory = results_dir(artifacts_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{pass_index:02d}-{label}.json"
    payload = {
        "pass": pass_index,
        "label": label,
        "scenarios": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_all(artifacts_dir: Path) -> list[ScenarioResult]:
    """Every scenario recorded so far, in pass order."""
    directory = results_dir(artifacts_dir)
    if not directory.is_dir():
        return []

    collected: list[ScenarioResult] = []
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        collected.extend(_scenario(raw) for raw in payload.get("scenarios", []))
    return collected


def _scenario(raw: dict[str, Any]) -> ScenarioResult:
    data = dict(raw)
    observation = data.pop("observation", None)
    notes = tuple(data.pop("notes", None) or ())
    return ScenarioResult(
        **data,
        notes=notes,
        observation=NetworkObservation(**observation) if observation else None,
    )
