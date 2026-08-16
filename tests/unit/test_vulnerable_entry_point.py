"""The vulnerable service refuses to start without being told to, in as many words."""

from __future__ import annotations

import pytest

from originjack.vulnerable import (
    ACKNOWLEDGEMENT_ENV,
    REQUIRED_ACKNOWLEDGEMENT,
    VulnerableDemoNotAcknowledgedError,
    build,
    require_acknowledgement,
)

ACKNOWLEDGED = {ACKNOWLEDGEMENT_ENV: REQUIRED_ACKNOWLEDGEMENT}


@pytest.mark.parametrize(
    "env",
    [
        {},
        {ACKNOWLEDGEMENT_ENV: ""},
        {ACKNOWLEDGEMENT_ENV: "1"},
        {ACKNOWLEDGEMENT_ENV: "yes"},
        {ACKNOWLEDGEMENT_ENV: "True"},
        {ACKNOWLEDGEMENT_ENV: "TRUE"},
        {ACKNOWLEDGEMENT_ENV: "false"},
    ],
    ids=["absent", "empty", "one", "yes", "True", "TRUE", "false"],
)
def test_anything_but_the_exact_acknowledgement_is_refused(env: dict[str, str]) -> None:
    """Near-misses do not count. The operator has to type the thing.

    Case and truthiness are deliberately not accepted: a gate that quietly interprets
    "1" or "TRUE" is a gate that can be tripped by a stray default somewhere.
    """
    with pytest.raises(VulnerableDemoNotAcknowledgedError):
        require_acknowledgement(env)


def test_the_refusal_says_what_to_do_and_why() -> None:
    with pytest.raises(VulnerableDemoNotAcknowledgedError) as excinfo:
        require_acknowledgement({})

    message = str(excinfo.value)
    assert ACKNOWLEDGEMENT_ENV in message
    assert "any origin that asks" in message
    assert "local educational use only" in message


def test_the_application_cannot_be_built_without_it() -> None:
    """The gate is in the application, not only in the Compose file.

    A control that lives solely in orchestration configuration is one `docker run` away
    from not existing.
    """
    with pytest.raises(VulnerableDemoNotAcknowledgedError):
        build({})


def test_the_application_builds_once_acknowledged() -> None:
    app = build(dict(ACKNOWLEDGED))

    assert app.state.policy.name == "vulnerable-reflected-origin"


def test_the_shape_is_selectable() -> None:
    app = build({**ACKNOWLEDGED, "ORIGINJACK_VULNERABLE_SHAPE": "reflect"})

    assert app.state.policy.name == "vulnerable-reflected-origin"
