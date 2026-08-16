# originjack

A local, containerized educational demonstration of **CORS misconfiguration** — how a
permissive cross-origin policy lets a page on an unrelated site read a logged-in victim's
private data out of an API, in the victim's own browser, with the victim's own session
cookie — and how a **strict, exact-match origin allowlist** prevents it.

> **This is educational material.** Every organization, employee, payroll figure, bank,
> hostname, cookie, and API token here is fictional. All hostnames are non-resolvable
> RFC 2606 `.example` names. The demo runs on a hermetic container network with **no
> egress**, contacts no real system, and must never be deployed anywhere.

## Status

`SLICE-002` — the containerized headless-browser verification harness.

What exists today is the *correct* configuration only, now demonstrated through a real
browser: the fictional Meridian Payroll domain, demo authentication with a
`SameSite=None; Secure` session cookie, three HTTPS origins on an egress-less network,
the exact-match origin allowlist, the refused-origin audit event, the first-party
application, and Chromium driving all of it. **There is no vulnerable service and no
attacker origin in this repository yet**; the misconfiguration ladder and the negative
controls arrive in later slices.

## Run it

```sh
./scripts/demo.sh
```

That is the whole supported workflow. It builds the images (generating a throwaway
demonstration CA and one certificate per origin *inside the build*), starts the origins
on the hermetic network, runs the verification gate — Ruff, mypy, unit tests, HTTPS
boundary tests — from inside that network, then drives the whole demonstration through a
real headless Chromium, copies the transcript and screenshots to `./artifacts/`, and
tears everything down.

The host needs **Docker and nothing else**: no Python, no browser, no hosts-file entry,
no trusted certificate, and no published port. GitHub Actions runs the same command.

## The origins

| Origin | Role |
|---|---|
| `https://app.meridianpay.example` | the legitimate first-party application — the **one** allowlisted origin |
| `https://api.meridianpay.example` | the secure API |
| `https://partner.othercorp.example` | an unrelated third party the allowlist does not name |

The first two are separate on purpose. That separation is the ordinary real-world
arrangement that makes a CORS policy necessary at all, and it is why the session cookie
must be issued `SameSite=None; Secure`. The third is not an attacker — it is simply an
origin the allowlist does not contain, which turns out to be the only qualification
needed for the browser to withhold a response.

## The browser is the enforcement point

The server can describe its policy, but only the browser enforces it — so a header
assertion can show a misconfiguration exists and can never show what it costs. Every
cross-origin claim this project makes is produced by Chromium executing the pages' own
JavaScript against the real network, with the demo CA imported into the browser's own NSS
trust store. Certificate errors are **not** ignored: a demonstration about a trust
decision should not work by switching trust off.

The harness records, per scenario, what the server sent, what the browser did with it,
what the page could actually render, and which component decided. That last column is the
whole point. From a run:

```
[3] third-party read                                          VERDICT: SECURE
    calling origin        https://partner.othercorp.example
    server response       status=200  ACAO=(absent)  ACAC=(absent)  browser-failure=net::ERR_FAILED
    browser released      no
    victim data rendered  no
    decided by            THE BROWSER — the server answered 200; the browser withheld
                          that answer from the page
```

The request was sent. The session cookie was carried. The server produced the victim's
full payslip and it arrived at the browser. The page was told only that its request
failed — because one response header was missing.

Two details the harness observes rather than assumes: whether a **preflight** actually
happened (it is issued by the browser's network service, so it never reaches page-level
network events — the harness watches the DevTools protocol, where it does appear), and
what the server really sent on a blocked response (also only visible there, since the
page is told nothing).

The pinned engine is **Chromium**, and the transcript records its version and the
behaviour known to differ elsewhere — most importantly third-party cookie policy, which
decides whether a cross-site request carries the session at all.

Run artifacts land in `./artifacts/` (transcript plus one screenshot per scenario) and
are never committed.

## Where the security boundary lives

[`src/originjack/cors.py`](src/originjack/cors.py) holds the entire cross-origin
decision, written as explicit application code rather than delegated to a framework CORS
middleware — so that when a later slice adds the misconfigured shapes beside it, the
difference between safe and catastrophic reads as a diff.

The rule: the request's `Origin` is compared as a **whole string** against a fixed,
server-side set. On a match, the response carries `Access-Control-Allow-Origin` set to
*the value held in that set* — never the value the request supplied — plus
`Access-Control-Allow-Credentials: true`, `Vary: Origin`, and a narrow, enumerated set of
methods and request headers. Anything else gets no `Access-Control-Allow-Origin` and no
credential grant, and one generic audit event is emitted that names no accepted origin.

There is no substring test, no prefix or suffix check, and no regular expression anywhere
in that decision — and a test asserts their continued absence.

## Certificates

The demonstration CA is generated at image-build time inside the container, its private
key is destroyed in the same build layer once the server certificates are signed, and it
is trusted only by the demo's own containers. No certificate or key is committed to this
repository, and none is issued by or for any real authority.

## Layout

```
docker/                  images, throwaway CA generation, origin list
scripts/                 demo.sh (the one command) and the in-container gates
src/originjack/          the API, the origin policy, sessions, fixtures, audit log
src/originjack/harness/  the browser lab, its scenarios, and the transcript
web/app/                 the first-party application (static HTML/JS, no build step)
web/partner/             the unrelated third-party page
tests/                   unit · in-process HTTP contract · HTTPS boundary · browser
artifacts/               per-run transcript and screenshots (never committed)
```
