"""The walkthrough covers what the acceptance boundary says it must.

Documentation tests earn their keep only when they check *coverage* rather than wording,
so this asserts that each required subject is present and that the safety statements have
not quietly gone missing — not how any of it is phrased.
"""

from __future__ import annotations

from pathlib import Path

import pytest

WALKTHROUGH = Path(__file__).resolve().parents[2] / "docs" / "WALKTHROUGH.md"


@pytest.fixture(scope="module")
def walkthrough() -> str:
    """Normalised, so these assert coverage rather than line wrapping.

    Blockquote markers are stripped first — the safety warnings live in one, and their
    wrapping should not be able to break a test about whether they are present.
    """
    raw = WALKTHROUGH.read_text(encoding="utf-8")
    unquoted = " ".join(line.lstrip().removeprefix(">").strip() for line in raw.splitlines())
    return " ".join(unquoted.split())


def test_the_walkthrough_exists(walkthrough: str) -> None:
    assert len(walkthrough) > 5_000


@pytest.mark.parametrize(
    "subject",
    [
        "same-origin policy",
        "controlled relaxation",
        "origin reflection",
        "sloppy allowlist match",
        "allowlisted `null` origin",
        "wildcard",
        "simple",
        "SameSite",
        "exact-match origin allowlist",
    ],
)
def test_it_covers_every_required_subject(walkthrough: str, subject: str) -> None:
    assert subject in walkthrough


@pytest.mark.parametrize("identifier", ["A05:2021", "API8:2023", "CWE-942", "CWE-346", "CWE-1385"])
def test_it_maps_the_terminology(walkthrough: str, identifier: str) -> None:
    assert identifier in walkthrough


def test_it_says_which_component_enforces_which_rule(walkthrough: str) -> None:
    """The single most load-bearing sentence in the document."""
    assert "Decides" in walkthrough
    assert "Enforces" in walkthrough
    assert "not an access-control mechanism the server gains" in walkthrough


def test_it_explains_the_boundary_each_control_establishes(walkthrough: str) -> None:
    assert walkthrough.count("The boundary this establishes") >= 2
    assert "The limits:" in walkthrough
    assert "not a CSRF defence" in walkthrough
    assert "not the dangerous shape" in walkthrough


def test_it_warns_that_this_must_never_be_deployed(walkthrough: str) -> None:
    assert "must never be deployed or hosted anywhere" in walkthrough
    assert "deliberately misconfigured" in walkthrough
    assert "deliberately malicious" in walkthrough


def test_it_states_the_fiction_and_the_certificate_boundary(walkthrough: str) -> None:
    assert "RFC 2606" in walkthrough
    assert "non-resolvable" in walkthrough
    assert "throwaway demonstration CA generated at image-build time" in walkthrough
    assert "no certificate or key is committed" in walkthrough


def test_it_names_the_out_of_scope_cache_poisoning_variant(walkthrough: str) -> None:
    assert "cache poisoning" in walkthrough
    assert "named here rather than built" in walkthrough
    assert "`Vary: Origin`" in walkthrough


def test_it_documents_the_commands_and_their_expected_outcome(walkthrough: str) -> None:
    assert "./scripts/demo.sh" in walkthrough
    assert "ALLOW_VULNERABLE_DEMO=true" in walkthrough
    assert "17 scenarios — 12 secure, 5 vulnerable" in walkthrough


def test_it_explains_why_the_legitimate_application_keeps_working(walkthrough: str) -> None:
    assert "the legitimate application keeps working" in walkthrough
    assert "byte-identical" in walkthrough


def test_it_records_the_pinned_engine_and_its_limits(walkthrough: str) -> None:
    assert "pins Chromium" in walkthrough
    assert "Intelligent Tracking Prevention" in walkthrough
