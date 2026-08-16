"""One browser run for the whole session, shared by every browser suite."""

from __future__ import annotations

import pytest

from originjack.harness import HarnessRun, run


@pytest.fixture(scope="session")
def harness() -> HarnessRun:
    """Drive the demonstration once; each test then interrogates one recorded outcome."""
    return run()
