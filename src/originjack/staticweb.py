"""A minimal HTTPS static-file origin.

The first-party Meridian Payroll application is plain HTML and JavaScript with no build
step and no third-party asset, so serving it needs nothing more than this. Later slices
serve further origins from the same image by pointing a second container at a different
document root and network alias.
"""

from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from originjack.config import static_root_from_env


def create_static_app(root: Path) -> Starlette:
    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Mount("/", app=StaticFiles(directory=root, html=True)),
        ]
    )


app = create_static_app(static_root_from_env())
