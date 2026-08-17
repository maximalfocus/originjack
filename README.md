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

`SLICE-003c` — the negative controls, the `SameSite` contrast, and the full regression
matrix. The demonstration is complete: the correct configuration, all three ways of
getting it wrong, and the three things people mistake for a fix. Still to come are the
comparison CLI and the educational walkthrough.

## Run it

```sh
./scripts/demo.sh                                              # secure baseline only
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh --with-vulnerable # the full contrast
```

The default builds the images (generating a throwaway demonstration CA and one
certificate per origin *inside the build*), starts the secure origins on the hermetic
network, runs the verification gate — Ruff, mypy, unit tests, HTTPS boundary tests — from
inside that network, then drives the demonstration through a real headless Chromium,
copies the transcript and screenshots to `./artifacts/`, and tears everything down.

The vulnerable run walks six passes — the three misconfiguration shapes and the three
controls — recreating the vulnerable API between them, because the configurations are
mutually exclusive. Every scenario accumulates into one transcript.

The host needs **Docker and nothing else**: no Python, no browser, no hosts-file entry,
no trusted certificate, and no published port. GitHub Actions runs both commands.

## ⚠️ The vulnerable service

`legacy-api.meridianpay.example` is **deliberately misconfigured**, and
`promo.attacker.example` is **deliberately malicious**. They exist to be run inside this
demo's own hermetic container network against its own fictional services, and must never
be deployed or hosted anywhere.

Starting them takes **two deliberate actions**, and neither alone does anything:

1. the opt-in Compose profile (`--with-vulnerable`, or `--profile vulnerable`), and
2. the acknowledgement `ALLOW_VULNERABLE_DEMO=true`.

The second is checked by the vulnerable application itself, not only by Compose — a
control that lives solely in orchestration configuration is one `docker run` away from
not existing. Every run of `./scripts/demo.sh`, in either mode, first proves the gate
still refuses, and the default mode additionally proves no opt-in service came up.

## The origins

| Origin | Role | Default |
|---|---|---|
| `https://app.meridianpay.example` | the legitimate first-party application — the **one** allowlisted origin | ✅ |
| `https://api.meridianpay.example` | the **secure** API | ✅ |
| `https://partner.othercorp.example` | an unrelated third party the allowlist does not name | ✅ |
| `https://legacy-api.meridianpay.example` | the **vulnerable** API | opt-in |
| `https://promo.attacker.example` | the attacker's page | opt-in |
| `https://app.meridianpay.example.attacker.example` | a lookalike that defeats a prefix or unanchored-regex check | opt-in |
| `https://notmeridianpay.example` | a lookalike that defeats a suffix check | opt-in |

The first two are separate on purpose. That separation is the ordinary real-world
arrangement that makes a CORS policy necessary at all, and it is why the session cookie
must be issued `SameSite=None; Secure`. The third is not an attacker — it is simply an
origin the allowlist does not contain, which turns out to be the only qualification
needed for the browser to withhold a response.

## The whole vulnerability, side by side

Both API deployments serve identical routes, sessions, and payloads. They are built with
different policy objects, and that is the only difference between them:

```python
# cors.py — the secure policy answers with the value it holds
for allowlisted in self.allowed_origins:
    if origin == allowlisted:
        return CorsDecision(granted=True, allow_origin=allowlisted, ...)
return REFUSED

# vulnerable_cors.py — this one answers with the value the request supplied
return CorsDecision(granted=True, allow_origin=origin, allow_credentials=True, ...)
```

Run with `--with-vulnerable`, the same attacker page is pointed at each deployment in
turn. The transcript:

```
[1] attacker read (vulnerable API)                            VERDICT: VULNERABLE
    calling origin        https://promo.attacker.example
    server response       status=200  ACAO=https://promo.attacker.example  ACAC=true
    browser released      yes
    victim data rendered  yes
    decided by            THE SERVER — it echoed the caller's own origin back as an
                          allowed one; the browser complied, correctly

[2] attacker read (secure API)                                VERDICT: SECURE
    calling origin        https://promo.attacker.example
    server response       status=200  ACAO=(absent)  ACAC=(absent)  browser-failure=net::ERR_FAILED
    browser released      no
    victim data rendered  no
    decided by            THE BROWSER — the server answered 200; the browser withheld
                          that answer from the page
```

Same page, same URL path, same credentials, same logged-in victim. Both servers answered
in full. One of them told the browser to share the answer with an origin it had never
compared to anything.

## The ladder of three shapes

They are the same mistake at three levels of effort, and the later two are **more**
dangerous than the first, because they arrive with the reassurance of looking deliberate.
The three are mutually exclusive, so `--with-vulnerable` recreates the vulnerable API once
per shape and accumulates every scenario into one transcript.

**Shape 1 — origin reflection.** Answers with whatever origin asked. No comparison of any
kind.

**Shape 2 — the sloppy allowlist match.** An unanchored check against the corporate
domain. `promo.attacker.example` is now **blocked**, so the obvious attack stops working
and the configuration looks repaired — while both of these walk straight through it:

| Origin | Why it matches | Who owns it |
|---|---|---|
| `app.meridianpay.example.attacker.example` | the corporate domain appears in the middle | the attacker |
| `notmeridianpay.example` | it appears at the end | the attacker |

A plain `in`, an `endswith` that forgets the leading dot, and a regex missing its anchors
all have this hole. The bug is not the technique — it is comparing anything other than
whole origins.

**Shape 3 — the allowlisted `null`.** This one does everything right except the one thing:
it compares whole strings against a fixed server-side set, and someone added `null` to
that set because a sandboxed frame needed it. `null` is not an origin — it is what the
browser sends when a document has none, and any page can arrange that in one attribute:

```
[11] null origin — sandboxed frame                            VERDICT: VULNERABLE
     server response   status=200  sent-Origin=null  ACAO=null  ACAC=true
     decided by        THE SERVER — `null` was in its accepted set, and any page can
                       arrange to send it; the browser complied, correctly
     · The browser reported that frame's origin to its parent as: null.
```

Under every shape, the secure API refuses all of them and releases nothing.

## What CORS is *not*

Three controls, each correcting a belief people hold confidently.

**"We don't use `*`, so we're fine."** The wildcard *with credentials* is refused by the
browser itself — the specification forbids the combination. So the wildcard is not the
dangerous shape; under credentials it fails safe, and it fails safe indiscriminately:

```
[14] wildcard with credentials                                VERDICT: SECURE
     server response   status=200  ACAO=*  ACAC=true  browser-failure=net::ERR_FAILED
     decided by        THE BROWSER — the server answered 200; the browser withheld
                       that answer from the page
     · The server refused nothing here. It granted *every* origin and asked for
       credentials as well.
     · The refusal is indiscriminate. The legitimate first-party origin attempting the
       identical read against this deployment: blocked: TypeError: Failed to fetch.
       A wildcard with credentials is not a lax policy — it is a broken one.
```

Reflection, which looks more careful, is the shape that hands the data over.

**"CORS protects our write endpoints."** It does not, and never did. A *simple*
cross-origin `POST` — a CORS-safelisted content type, no custom header — triggers no
preflight at all:

```
[15] simple cross-origin POST — vulnerable API                VERDICT: VULNERABLE
     preflight         no (none sent)
     browser released  no
     state changed     yes
     decided by        THE SERVER — it processed the write on a valid session alone,
                       asking nothing about where the request came from
     · The victim's payout account tail went from 8842 to 0001. The attacker never saw
       the response, and changed the victim's bank details anyway.
```

The secure API refuses the identical request (`415`) because its route requires a
non-simple header and a matching CSRF token — neither of which a simple cross-site
request can carry. CORS governs **reading** a response, never **sending** a request, and
is therefore not a CSRF defence.

**"`SameSite` fixed this."** It withholds the *credential*, not the cross-origin read:

```
[17] SameSite=Lax contrast                                    VERDICT: SECURE
     server response   status=401  ACAO=https://promo.attacker.example  ACAC=true
     browser released  yes
     victim data rendered  no
     · The cross-origin read still succeeded — the browser released the response to the
       attacker's origin, exactly as the policy told it to. There is simply nothing in
       it, because Lax withheld the cookie.
```

The misconfiguration is untouched. For the many real APIs that must set
`SameSite=None; Secure` — a separate front-end domain, an embedded third-party surface, a
deliberately cross-site API — it withholds nothing at all.

> Not built, and named here because it is a real variant: CORS response-header cache
> poisoning through a shared HTTP cache, where a missing `Vary: Origin` lets a cache hand
> one origin's grant to another. It needs a cache tier this vulnerability does not, so it
> is out of scope. This demo sends `Vary: Origin` on every response, refusals included.

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
  cors.py                the secure decision  ─┐ read these two
  vulnerable_cors.py     the misconfigured ones ┘ together
  statechange.py         what each deployment demands before it will change anything
  secure.py              the secure entry point
  vulnerable.py          the opt-in entry point and its acknowledgement gate
  harness/               the browser lab, its scenarios, and the transcript
web/app/                 the first-party application (static HTML/JS, no build step)
web/partner/             the unrelated third-party page
web/attacker/            the attacker's page (opt-in origin)
tests/                   unit · in-process HTTP contract · HTTPS boundary · browser
artifacts/               per-run transcript and screenshots (never committed)
```
