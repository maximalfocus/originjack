"""Trusting the throwaway demonstration certificate authority.

The CA is generated at image-build time inside the container, is never written to this
repository, and is trusted only by the demo's own containers. It is not, and never
claims to be, a real certificate authority.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Final

DEFAULT_CA_BUNDLE: Final = "/certs/ca/ca.pem"


def ca_bundle_path(env: dict[str, str] | None = None) -> Path:
    source = os.environ if env is None else env
    return Path(source.get("ORIGINJACK_CA_BUNDLE", DEFAULT_CA_BUNDLE))


def ssl_context(env: dict[str, str] | None = None) -> ssl.SSLContext:
    """An SSL context that trusts the demo CA and nothing else it would not already."""
    return ssl.create_default_context(cafile=str(ca_bundle_path(env)))
