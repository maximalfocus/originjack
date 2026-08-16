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

`SLICE-001` — the hermetic multi-origin TLS baseline and the **secure** API.

What exists today is the *correct* configuration only: the fictional Meridian Payroll
domain, demo authentication with a `SameSite=None; Secure` session cookie, two HTTPS
origins on an egress-less network, the exact-match origin allowlist, the refused-origin
audit event, and the first-party application that exercises them. **There is no
vulnerable service and no attacker origin in this repository yet**; the misconfiguration
ladder, the negative controls, and the headless-browser harness arrive in later slices.

## Run it

```sh
./scripts/demo.sh
```

That is the whole supported workflow. It builds the image (generating a throwaway
demonstration CA and one certificate per origin *inside the build*), starts the secure
API and the first-party application on the hermetic network, runs the full verification
gate — Ruff, mypy, unit tests, and HTTPS boundary tests — from inside that network, and
tears everything down.

The host needs **Docker and nothing else**: no Python, no browser, no hosts-file entry,
no trusted certificate, and no published port. GitHub Actions runs the same command.

## The origins

| Origin | Role |
|---|---|
| `https://app.meridianpay.example` | the legitimate first-party application — the **one** allowlisted origin |
| `https://api.meridianpay.example` | the secure API |

They are separate on purpose. That separation is the ordinary real-world arrangement
that makes a CORS policy necessary at all, and it is why the session cookie must be
issued `SameSite=None; Secure`.

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
docker/          image, throwaway CA generation, origin list
scripts/         demo.sh (the one command) and the in-container verification gate
src/originjack/  the API, the origin policy, sessions, fixtures, audit log
web/app/         the first-party application (static HTML/JS, no build step)
tests/           unit · in-process HTTP contract · HTTPS boundary
```
