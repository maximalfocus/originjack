"""The containerized headless-browser verification harness.

The browser — not the server — is what enforces the same-origin policy, so this is the
only place the project can honestly demonstrate impact rather than configuration.

The whole run is one function so that local verification, CI, and (later) the comparison
CLI all drive exactly the same engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from originjack.harness import store, transcript
from originjack.harness.lab import BrowserLab, LabSettings
from originjack.harness.models import NetworkObservation, ScenarioResult
from originjack.harness.scenarios import PASS_RUNNERS, run_secure_baseline

__all__ = [
    "BrowserLab",
    "HarnessRun",
    "LabSettings",
    "NetworkObservation",
    "ScenarioResult",
    "run",
]

SECURE_ONLY_SUBJECT = "the secure API only — no vulnerable service or attacker origin is running"
VULNERABLE_SUBJECT = (
    "the secure API and the opt-in vulnerable API across its misconfiguration shapes and "
    "the negative controls — started only after two deliberate opt-in actions"
)

TRANSCRIPT_NAME = "transcript.txt"


@dataclass(frozen=True, slots=True)
class HarnessRun:
    """Everything one harness run produced."""

    engine: str
    results: tuple[ScenarioResult, ...]
    transcript: str
    transcript_path: Path

    def by_name(self, name: str) -> ScenarioResult:
        for result in self.results:
            if result.name == name:
                return result
        raise KeyError(name)


def run(settings: LabSettings | None = None) -> HarnessRun:
    """Drive the whole demonstration in a real browser and write its artifacts."""
    resolved = LabSettings.from_env() if settings is None else settings

    # Pass 1 owns the fresh start; later passes accumulate onto it.
    if resolved.pass_index <= 1:
        store.clear(resolved.artifacts_dir)

    # Screenshot numbering is spaced per pass so it stays unique and in order across a
    # multi-shape run.
    start = (resolved.pass_index - 1) * 10 + 1

    with BrowserLab(resolved) as lab:
        collected: list[ScenarioResult] = []
        if resolved.include_vulnerable:
            runner = PASS_RUNNERS.get(resolved.pass_label)
            if runner is None:
                raise ValueError(f"no scenarios for pass {resolved.pass_label!r}")
            # The exposure first, then the reference — the order the walkthrough tells it.
            collected.extend(runner(lab, start=start))
        if resolved.pass_index <= 1:
            # The secure baseline is the reference, not a per-shape observation, so it
            # runs once.
            collected.extend(run_secure_baseline(lab, start=start + len(collected)))
        results = tuple(collected)
        engine = lab.engine

    label = resolved.pass_label if resolved.include_vulnerable else "secure-baseline"
    store.save(
        resolved.artifacts_dir,
        pass_index=resolved.pass_index,
        label=label,
        results=results,
    )

    text = transcript.render(
        store.load_all(resolved.artifacts_dir),
        engine=engine,
        generated_at=datetime.now(tz=UTC).isoformat(timespec="seconds"),
        subject=VULNERABLE_SUBJECT if resolved.include_vulnerable else SECURE_ONLY_SUBJECT,
    )

    resolved.artifacts_dir.mkdir(parents=True, exist_ok=True)
    path = resolved.artifacts_dir / TRANSCRIPT_NAME
    path.write_text(text, encoding="utf-8")

    return HarnessRun(engine=engine, results=results, transcript=text, transcript_path=path)
