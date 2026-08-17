"""The containerized browser lab: one Chromium, one trust store, one victim session.

The browser is the enforcement point this project is about, so the harness takes some
care to be a *real* browser in a real trust relationship:

* the throwaway demo CA is imported into Chromium's own NSS trust store at start-up,
  rather than launching with certificate errors ignored;
* every scenario shares one browser context, because there is one victim with one
  session, and a fresh context per scenario would quietly discard the very cookie the
  demonstration is about; and
* what the browser saw on the wire is captured separately from what the page could
  render, so the transcript can say which component made the decision.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self

from playwright.sync_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Page,
    Playwright,
    Request,
    Response,
    sync_playwright,
)

from originjack.harness.models import NetworkObservation

#: One engine, pinned. Chromium is the only engine this harness claims anything about.
ENGINE: Final = "chromium"

DEFAULT_TIMEOUT_MS: Final = 15_000

#: Chromium's own sandbox cannot start under Docker's default seccomp profile. The
#: container is the sandbox instead: non-root, every Linux capability dropped,
#: no-new-privileges, a read-only root filesystem, and a network with no egress that
#: reaches nothing but this demo's own fictional services.
LAUNCH_ARGS: Final[tuple[str, ...]] = ("--no-sandbox",)


@dataclass(frozen=True, slots=True)
class LabSettings:
    """Where the lab points and where it writes."""

    api_origin: str
    app_origin: str
    partner_origin: str
    ca_bundle: Path
    artifacts_dir: Path
    home: Path
    vulnerable_api_origin: str = "https://legacy-api.meridianpay.example"
    attacker_origin: str = "https://promo.attacker.example"
    attacker_prefix_origin: str = "https://app.meridianpay.example.attacker.example"
    attacker_suffix_origin: str = "https://notmeridianpay.example"
    include_vulnerable: bool = False
    #: Which misconfiguration shape the vulnerable API is serving right now.
    vulnerable_shape: str = "reflect"
    #: Which pass of the run this is, by name. Usually the shape, but the negative
    #: controls reuse a shape under a different label — the simple-request control runs
    #: under the sloppy shape, so that the attacker demonstrably reads nothing.
    pass_label: str = "reflect"
    #: Which pass of the multi-shape run this is. Pass 1 clears any earlier results.
    pass_index: int = 1

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LabSettings:
        source = os.environ if env is None else env
        return cls(
            api_origin=source.get("ORIGINJACK_API_BASE", "https://api.meridianpay.example"),
            app_origin=source.get("ORIGINJACK_APP_BASE", "https://app.meridianpay.example"),
            partner_origin=source.get(
                "ORIGINJACK_PARTNER_BASE", "https://partner.othercorp.example"
            ),
            ca_bundle=Path(source.get("ORIGINJACK_CA_BUNDLE", "/certs/ca/ca.pem")),
            artifacts_dir=Path(source.get("ORIGINJACK_ARTIFACTS", "/artifacts")),
            home=Path(source.get("HOME", "/home/originjack")),
            vulnerable_api_origin=source.get(
                "ORIGINJACK_VULNERABLE_API_BASE", "https://legacy-api.meridianpay.example"
            ),
            attacker_origin=source.get(
                "ORIGINJACK_ATTACKER_BASE", "https://promo.attacker.example"
            ),
            attacker_prefix_origin=source.get(
                "ORIGINJACK_ATTACKER_PREFIX_BASE",
                "https://app.meridianpay.example.attacker.example",
            ),
            attacker_suffix_origin=source.get(
                "ORIGINJACK_ATTACKER_SUFFIX_BASE", "https://notmeridianpay.example"
            ),
            vulnerable_shape=source.get("ORIGINJACK_VULNERABLE_SHAPE", "reflect").strip()
            or "reflect",
            pass_label=source.get("ORIGINJACK_PASS_LABEL", "").strip()
            or source.get("ORIGINJACK_VULNERABLE_SHAPE", "reflect").strip()
            or "reflect",
            pass_index=int(source.get("ORIGINJACK_PASS", "1")),
            # The vulnerable services only exist when the operator opted in twice, so the
            # harness only looks for them when told to.
            include_vulnerable=source.get("ORIGINJACK_INCLUDE_VULNERABLE", "").strip().lower()
            in {"1", "true", "yes"},
        )


class DemoCaTrustError(RuntimeError):
    """Raised when the demo CA cannot be installed into the browser's trust store."""


def trust_demo_ca(*, home: Path, ca_bundle: Path) -> None:
    """Import the throwaway demo CA into Chromium's NSS trust store.

    Chromium on Linux reads locally-added roots from ``$HOME/.pki/nssdb``. Adding the CA
    there is a real trust decision, scoped to this container and this run, and it is what
    makes the demo's HTTPS origins verify normally instead of being waved through.
    """
    certutil = shutil.which("certutil")
    if certutil is None:
        raise DemoCaTrustError("certutil is unavailable; the demo CA cannot be trusted")
    if not ca_bundle.is_file():
        raise DemoCaTrustError(f"demo CA bundle is missing: {ca_bundle}")

    nssdb = home / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        # Fixed executable path and fixed arguments; no user input reaches this call.
        return subprocess.run(  # noqa: S603
            [certutil, *args], capture_output=True, text=True, check=False
        )

    if not (nssdb / "cert9.db").exists():
        created = run("-N", "--empty-password", "-d", f"sql:{nssdb}")
        if created.returncode != 0:
            raise DemoCaTrustError(f"could not create NSS database: {created.stderr.strip()}")

    added = run(
        "-A",
        "-d",
        f"sql:{nssdb}",
        "-t",
        "C,,",
        "-n",
        "originjack throwaway demo CA",
        "-i",
        str(ca_bundle),
    )
    if added.returncode != 0:
        raise DemoCaTrustError(f"could not import the demo CA: {added.stderr.strip()}")


class NetworkLog:
    """Records what the browser saw on the wire, per request URL.

    Kept deliberately separate from what the page could render. The gap between the two
    is the entire subject of the demonstration: the server answers, and the browser
    decides whether the page is allowed to see the answer.
    """

    def __init__(self) -> None:
        self._responses: dict[str, NetworkObservation] = {}
        self._failures: dict[str, str] = {}
        self._methods: dict[str, set[str]] = {}
        self._url_by_request: dict[str, str] = {}
        self._method_by_request: dict[str, str] = {}
        self._raw_by_request: dict[str, tuple[int | None, str | None, str | None]] = {}
        self._sent_origin_by_request: dict[str, str] = {}

    def attach(self, page: Page) -> None:
        page.on("response", self._record_response)
        page.on("requestfailed", self._record_failure)

    def attach_devtools(self, session: CDPSession) -> None:
        """Also listen at the DevTools protocol level.

        Two things are only visible here, and both matter:

        * a CORS **preflight** is issued by the browser's network service rather than by
          the page, so it never reaches the page-level request events — which is why
          "did a preflight happen?" is so easy to assume and so rarely checked; and
        * when the browser blocks a response for CORS reasons, the page is told only
          that the request failed. The **response still arrived**, and DevTools reports
          it with its real status and its real headers. Capturing it there is what lets
          this harness say — from observation rather than inference — that the server
          answered and the browser is what withheld the answer.
        """
        session.on("Network.requestWillBeSent", self._record_devtools_request)
        session.on("Network.requestWillBeSentExtraInfo", self._record_devtools_request_headers)
        session.on("Network.responseReceivedExtraInfo", self._record_devtools_response)

    def _record_devtools_request(self, event: dict[str, Any]) -> None:
        request = event.get("request")
        if not isinstance(request, dict):
            return
        url = str(request.get("url", ""))
        method = str(request.get("method", ""))
        if not (url and method):
            return
        self._methods.setdefault(url, set()).add(method)
        request_id = str(event.get("requestId", ""))
        if request_id:
            self._url_by_request[request_id] = url
            self._method_by_request[request_id] = method

    def _record_devtools_request_headers(self, event: dict[str, Any]) -> None:
        """Capture the ``Origin`` the browser actually put on the wire.

        The network stack adds it, not the page, so this is the only place the value can
        be read rather than inferred — which matters most for a sandboxed frame, whose
        origin is opaque and therefore sent as the literal string ``null``.
        """
        request_id = str(event.get("requestId", ""))
        raw = event.get("headers")
        if not request_id or not isinstance(raw, dict):
            return
        for key, value in raw.items():
            if str(key).lower() == "origin":
                self._sent_origin_by_request[request_id] = str(value)
                return

    def _record_devtools_response(self, event: dict[str, Any]) -> None:
        request_id = str(event.get("requestId", ""))
        if not request_id:
            return
        raw = event.get("headers")
        headers = {str(k).lower(): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
        status = event.get("statusCode")
        self._raw_by_request[request_id] = (
            status if isinstance(status, int) else None,
            headers.get("access-control-allow-origin"),
            headers.get("access-control-allow-credentials"),
        )

    def _wire_observations(self) -> dict[str, NetworkObservation]:
        """What the server actually sent, before the browser decided anything about it."""
        merged: dict[str, NetworkObservation] = {}
        for request_id, (status, allow_origin, allow_credentials) in self._raw_by_request.items():
            url = self._url_by_request.get(request_id)
            if url is None or self._method_by_request.get(request_id) == "OPTIONS":
                continue
            merged[url] = NetworkObservation(
                url=url,
                status=status,
                allow_origin=allow_origin,
                allow_credentials=allow_credentials,
                request_origin=self._sent_origin_by_request.get(request_id),
            )
        return merged

    def _record_response(self, response: Response) -> None:
        method = response.request.method
        self._methods.setdefault(response.url, set()).add(method)
        if method == "OPTIONS":
            # A preflight is recorded as having happened, but it is not the exchange the
            # scenario is about.
            return
        headers = response.headers
        self._responses[response.url] = NetworkObservation(
            url=response.url,
            status=response.status,
            allow_origin=headers.get("access-control-allow-origin"),
            allow_credentials=headers.get("access-control-allow-credentials"),
        )

    def _record_failure(self, request: Request) -> None:
        self._methods.setdefault(request.url, set()).add(request.method)
        if request.method == "OPTIONS":
            return
        self._failures[request.url] = str(request.failure or "request failed")

    def saw_preflight(self, url_suffix: str) -> bool:
        """Whether the browser actually sent a preflight — observed, not assumed."""
        return any(
            "OPTIONS" in methods
            for url, methods in self._methods.items()
            if url.endswith(url_suffix)
        )

    def observation_for(self, url_suffix: str) -> NetworkObservation | None:
        """What the server sent, plus whatever the browser then told the page.

        The wire view wins for status and headers, because it is what actually arrived;
        the page-level view contributes the failure, because that is what the page was
        allowed to know. Holding both is the point.
        """
        wire = self._wire_observations()
        matches = sorted(
            url for url in {*self._responses, *self._failures, *wire} if url.endswith(url_suffix)
        )
        if not matches:
            return None

        url = matches[-1]
        base = wire.get(url) or self._responses.get(url) or NetworkObservation(url=url)
        return NetworkObservation(
            url=base.url,
            status=base.status,
            allow_origin=base.allow_origin,
            allow_credentials=base.allow_credentials,
            failure=self._failures.get(url),
            request_origin=base.request_origin or self._sent_origin_for(url),
        )

    def _sent_origin_for(self, url: str) -> str | None:
        for request_id, recorded in self._url_by_request.items():
            if recorded == url and request_id in self._sent_origin_by_request:
                return self._sent_origin_by_request[request_id]
        return None


class BrowserLab:
    """Owns the browser process, its trust store, and the run's artifacts."""

    def __init__(self, settings: LabSettings) -> None:
        self.settings = settings
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self.screenshots_dir = settings.artifacts_dir / "screenshots"

    def __enter__(self) -> Self:
        trust_demo_ca(home=self.settings.home, ca_bundle=self.settings.ca_bundle)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(args=list(LAUNCH_ARGS))
        self._context = self._browser.new_context(ignore_https_errors=False)
        self._context.set_default_timeout(DEFAULT_TIMEOUT_MS)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._context is not None:
            self._context.close()
        if self._browser is not None:
            self._browser.close()
        if self._playwright is not None:
            self._playwright.stop()

    @property
    def context(self) -> BrowserContext:
        if self._context is None:
            raise RuntimeError("BrowserLab must be used as a context manager")
        return self._context

    @property
    def engine(self) -> str:
        if self._browser is None:
            raise RuntimeError("BrowserLab must be used as a context manager")
        return f"{ENGINE} {self._browser.version}"

    def open(self, url: str) -> tuple[Page, NetworkLog]:
        """Open a page with its network activity recorded from the first request."""
        page = self.context.new_page()
        log = NetworkLog()
        log.attach(page)

        session = self.context.new_cdp_session(page)
        session.send("Network.enable")
        log.attach_devtools(session)

        page.goto(url, wait_until="domcontentloaded")
        return page, log

    def sign_in(self, api_origin: str, *, employee_id: str, demo_password: str) -> None:
        """Establish the victim's session on one API deployment, in the browser.

        Setup, not a demonstrated outcome — the scenarios are about what a page on
        somebody else's origin can do with a session that already exists, so the session
        has to already exist.

        Done through page script rather than through Playwright's API request context,
        which is backed by the Node driver and knows nothing about the demo CA in
        Chromium's NSS store. And more to the point, this is how it happens in life: the
        victim signed in, in their own browser, in another tab.

        The request is made **same-origin**, from a document on the API's own origin. That
        is both faithful and necessary: signing in is not the thing under demonstration,
        and one of the shapes — the wildcard with credentials — refuses every credentialed
        cross-origin request there is, including a legitimate one. Establishing the
        session through the policy under test would make the setup fail for the very
        reason the scenario exists to show.
        """
        page = self.context.new_page()
        try:
            page.goto(f"{api_origin}/healthz", wait_until="domcontentloaded")
            status = page.evaluate(
                """async ({ api, employeeId, password }) => {
                    const response = await fetch(`${api}/session`, {
                        method: "POST",
                        credentials: "include",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({
                            employee_id: employeeId,
                            demo_password: password,
                        }),
                    });
                    return response.status;
                }""",
                {"api": api_origin, "employeeId": employee_id, "password": demo_password},
            )
        finally:
            page.close()

        if status != 200:
            raise RuntimeError(
                f"could not establish the victim's session on {api_origin}: HTTP {status}"
            )

    def probe_credentialed_read(self, *, page_origin: str, api_origin: str) -> str:
        """Attempt a credentialed cross-origin read from ``page_origin`` and report it.

        Returns ``"released: <status>"`` or ``"blocked: <error>"``. Used to record a
        consequence in passing — chiefly that a shape which breaks attackers may be
        breaking the legitimate application too.
        """
        page = self.context.new_page()
        try:
            page.goto(f"{page_origin}/", wait_until="domcontentloaded")
            return str(
                page.evaluate(
                    """async (api) => {
                        try {
                            const response = await fetch(`${api}/me/payslip`, {
                                method: "GET",
                                credentials: "include",
                            });
                            return `released: HTTP ${response.status}`;
                        } catch (error) {
                            return `blocked: ${error.name}: ${error.message}`;
                        }
                    }""",
                    api_origin,
                )
            )
        finally:
            page.close()

    def capture(self, page: Page, name: str) -> str:
        """Screenshot the page and return the artifact's path relative to the run."""
        path = self.screenshots_dir / f"{name}.png"
        page.screenshot(path=str(path), full_page=True)
        return str(path.relative_to(self.settings.artifacts_dir))
