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

from originjack.harness import transcript
from originjack.harness.lab import BrowserLab, LabSettings
from originjack.harness.models import NetworkObservation, ScenarioResult
from originjack.harness.scenarios import run_secure_baseline

__all__ = [
    "BrowserLab",
    "HarnessRun",
    "LabSettings",
    "NetworkObservation",
    "ScenarioResult",
    "run",
]

SUBJECT = "the secure API only — this build contains no vulnerable service and no attacker origin"

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

    with BrowserLab(resolved) as lab:
        results = tuple(run_secure_baseline(lab))
        engine = lab.engine

    text = transcript.render(
        results,
        engine=engine,
        generated_at=datetime.now(tz=UTC).isoformat(timespec="seconds"),
        subject=SUBJECT,
    )

    resolved.artifacts_dir.mkdir(parents=True, exist_ok=True)
    path = resolved.artifacts_dir / TRANSCRIPT_NAME
    path.write_text(text, encoding="utf-8")

    return HarnessRun(engine=engine, results=results, transcript=text, transcript_path=path)
