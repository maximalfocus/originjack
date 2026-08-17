"""The comparison CLI — every scenario, side by side.

The point of a table here is that the interesting facts are *differences*, and differences
are invisible in prose. Read down the `ACAO` column and the whole vulnerability is one
glance: the same request, the same credentials, the same victim, and one server telling
the browser to hand the answer to whoever asked.

Rendering is a pure function of the recorded scenarios, so it is exercised directly by
tests rather than by driving a terminal. The scenarios themselves come from the browser
harness — nothing here re-derives an outcome, and nothing here can claim one the run did
not observe.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from originjack.harness import store
from originjack.harness.models import ScenarioResult

DEFAULT_ARTIFACTS = Path("/artifacts")

NARRATIVE: Final = """\
originjack — cross-origin comparison

Every row below is the same request: GET /me/payslip, with the victim's own session
cookie, from a page in a real browser. What differs is which origin asked and which
deployment answered.

Two response headers decide everything. `ACAO` is the Access-Control-Allow-Origin the
server sent; `ACAC` is Access-Control-Allow-Credentials. When ACAO names the caller (or
is a value the caller can produce), the browser hands the response to the page — and the
`data` column shows what that page then had.

The `decided` column is the one to read twice. `browser` means the server answered in
full and the browser withheld the answer from the page. `server` means the server itself
decided, either by granting an origin it never properly compared, or by refusing.\
"""

LEGEND: Final = """\
cred     credential mode on the request
pre      did the browser send a preflight?
ACAO     Access-Control-Allow-Origin the server returned
ACAC     Access-Control-Allow-Credentials the server returned
rel      did the browser release the response to the page?
data     was the victim's payslip data actually rendered on that page?
state    did the request change server-side state?
decided  which component decided the outcome\
"""

_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("#", ""),
    ("scenario", "name"),
    ("calling origin", "origin"),
    ("cred", "credential"),
    ("pre", "preflight"),
    ("ACAO", "acao"),
    ("ACAC", "acac"),
    ("rel", "released"),
    ("data", "rendered"),
    ("state", "state"),
    ("decided", "decided"),
    ("verdict", "verdict"),
)


def _short_origin(origin: str) -> str:
    return origin.removeprefix("https://").removeprefix("http://")


def _tri(value: bool | None) -> str:
    if value is None:
        return "—"
    return "yes" if value else "no"


def _row(index: int, result: ScenarioResult) -> dict[str, str]:
    observation = result.observation
    allow_origin = observation.allow_origin if observation else None
    allow_credentials = observation.allow_credentials if observation else None
    return {
        "": str(index),
        "name": result.name,
        "origin": _short_origin(result.calling_origin),
        "credential": result.credential_mode,
        "preflight": _tri(result.preflight),
        "acao": _short_origin(allow_origin) if allow_origin else "—",
        "acac": allow_credentials or "—",
        "released": _tri(result.browser_released),
        "rendered": "YES" if result.victim_data_rendered else "no",
        "state": _tri(result.state_changed),
        "decided": result.decided_by,
        "verdict": result.verdict.upper(),
    }


def render_table(results: Sequence[ScenarioResult]) -> str:
    """The comparison table. Deterministic for a given scenario set."""
    if not results:
        return "(no scenarios recorded)"

    rows = [_row(index, result) for index, result in enumerate(results, start=1)]
    widths = {key: max(len(header), *(len(row[key]) for row in rows)) for header, key in _COLUMNS}

    lines = [
        "  ".join(header.ljust(widths[key]) for header, key in _COLUMNS).rstrip(),
        "  ".join("-" * widths[key] for _, key in _COLUMNS),
    ]
    lines.extend(
        "  ".join(row[key].ljust(widths[key]) for _, key in _COLUMNS).rstrip() for row in rows
    )
    return "\n".join(lines)


def render_exchanges(results: Sequence[ScenarioResult]) -> str:
    """The underlying exchange behind each row, for `--verbose`."""
    blocks: list[str] = []
    for index, result in enumerate(results, start=1):
        block = [f"[{index}] {result.name}", f"    {result.summary}"]
        if result.shape:
            block.append(f"    shape        {result.shape}")
        block.append(
            f"    request      from {result.calling_origin} (credentials: {result.credential_mode})"
        )
        if result.observation is not None:
            block.append(f"    url          {result.observation.url}")
            block.append(f"    exchange     {result.observation.describe()}")
        else:
            block.append("    exchange     (not observed)")
        if result.decider_detail:
            block.append(f"    decided      {result.decided_by} — {result.decider_detail}")
        else:
            block.append(f"    decided      {result.decided_by}")
        if result.screenshot:
            block.append(f"    screenshot   {result.screenshot}")
        block.extend(f"    · {note}" for note in result.notes)
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


def render(results: Sequence[ScenarioResult], *, verbose: bool = False) -> str:
    """The whole comparison, narrative and all."""
    secure = sum(1 for r in results if r.verdict == "secure")
    vulnerable = len(results) - secure

    sections = [
        NARRATIVE,
        "",
        render_table(results),
        "",
        LEGEND,
        "",
        f"{len(results)} scenarios — {secure} secure, {vulnerable} vulnerable",
    ]
    if verbose:
        sections.extend(["", "Underlying exchanges", "", render_exchanges(results)])
    return "\n".join(sections) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="originjack",
        description=(
            "Compare what the browser did with each cross-origin scenario the "
            "demonstration recorded."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compare = subparsers.add_parser("compare", help="print the cross-origin comparison table")
    compare.add_argument(
        "--artifacts",
        type=Path,
        default=DEFAULT_ARTIFACTS,
        help="directory holding the harness run artifacts (default: %(default)s)",
    )
    compare.add_argument(
        "--verbose",
        action="store_true",
        help="also print the underlying exchange behind each row",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))

    results = store.load_all(args.artifacts)
    if not results:
        print(
            f"No recorded scenarios in {args.artifacts}. Run ./scripts/demo.sh first — "
            "the comparison reports what a browser did, so a browser has to have done it.",
            file=sys.stderr,
        )
        return 1

    print(render(results, verbose=args.verbose), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
