# originjack — a walkthrough

How a page on an attacker's site reads a logged-in victim's private data out of an API —
in the victim's own browser, with the victim's own session cookie — because that API
answers the browser's cross-origin question with *whatever origin asked*. And how a
strict, exact-match origin allowlist prevents it.

> ## ⚠️ Read this first
>
> `legacy-api.meridianpay.example` is **deliberately misconfigured** and
> `promo.attacker.example`, `app.meridianpay.example.attacker.example` and
> `notmeridianpay.example` are **deliberately malicious pages**. They exist to run inside
> this demo's own hermetic container network, against this demo's own fictional services,
> and **must never be deployed or hosted anywhere**.
>
> Starting any of them takes two deliberate actions, and neither alone does anything.
>
> Everything here is invented. Meridian Payroll does not exist; neither do Rowan
> Ashcombe, their salary, their tax reference, their bank, or their API token. Every
> hostname is a non-resolvable **RFC 2606 `.example`** name that can never exist on the
> public internet. The transport certificates come from a **throwaway demonstration CA
> generated at image-build time inside the containers**, whose private key is destroyed in
> that same build layer; nothing here is issued by, or for, any real authority, and no
> certificate or key is committed to this repository.

---

## 1. What the same-origin policy actually protects

The same-origin policy stops one origin **reading another origin's responses**. That is a
narrower rule than it sounds, and the narrowness is where the confusion starts.

It does **not** stop your browser *sending* requests to other origins. Every image, script,
stylesheet and form post that crosses an origin boundary is a cross-origin request, and
they have always been allowed — with your cookies attached. What the policy withholds is
the *answer*.

**CORS is a controlled relaxation of that rule.** It is not an access-control mechanism the
server gains; it is a way for the responding server to tell the browser *"you may show this
answer to that origin"*. Two things follow, and almost every CORS mistake is a failure to
hold both in mind at once:

| | Decides | Enforces |
|---|---|---|
| the **server** | whether to permit a cross-origin read, by sending `Access-Control-Allow-Origin` | nothing |
| the **browser** | nothing | whether the calling page may read the response |

The server has no idea whether its answer reached the page. The browser has no idea whether
the policy is sensible. Between them sits a permission the server grants and cannot revoke,
and a rule the browser enforces and cannot question.

That division is why this project drives a real headless Chromium rather than asserting
response headers. A header assertion can show a misconfiguration exists; only a browser can
show what it costs.

### What this vulnerability is called

| Name | Where |
|---|---|
| CORS Misconfiguration · permissive cross-origin resource sharing · origin reflection · cross-domain policy misconfiguration | common names |
| **A05:2021 – Security Misconfiguration** | OWASP Top 10 |
| **API8:2023 – Security Misconfiguration** | OWASP API Security Top 10 |
| **CWE-942** – permissive cross-domain policy with untrusted domains | CWE |
| **CWE-346** – origin validation error | CWE |

In plain language: *the server telling the browser it is fine to hand this response to a
site that should never have seen it.*

---

## 2. The fixture

**Meridian Payroll** is a fictional payroll SaaS whose browser application and API are
deployed on **separate origins** — the ordinary arrangement that makes a CORS policy
necessary in the first place, and the reason its session cookie is issued
`SameSite=None; Secure`.

| Origin | Role | Default |
|---|---|---|
| `https://app.meridianpay.example` | the legitimate first-party app — the **one** allowlisted origin | ✅ |
| `https://api.meridianpay.example` | the **secure** API | ✅ |
| `https://partner.othercorp.example` | an unrelated third party the allowlist does not name | ✅ |
| `https://legacy-api.meridianpay.example` | the **vulnerable** API | opt-in |
| `https://promo.attacker.example` | the attacker's page | opt-in |
| `https://app.meridianpay.example.attacker.example` | a lookalike defeating a prefix or unanchored-regex check | opt-in |
| `https://notmeridianpay.example` | a lookalike defeating a suffix check | opt-in |

The victim is Rowan Ashcombe (`EMP-4417`), logged in. `GET /me/payslip` returns their gross
and net pay, tax reference, payout-account tail, and the session-scoped API token the
first-party app uses. `POST /me/payout-account` changes where their salary is sent.

---

## 3. Run it

```sh
./scripts/demo.sh                                              # secure baseline only
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh --with-vulnerable # the full contrast
```

The host needs **Docker and nothing else**: no Python, no browser, no hosts-file entry, no
trusted certificate, no published port.

The default run starts only the secure services, proves the opt-in gate still refuses, and
drives three browser scenarios. The vulnerable run walks **six passes** — the three
misconfiguration shapes and the three controls — recreating the vulnerable API between
them, because the configurations are mutually exclusive. Both write a transcript and
screenshots to `./artifacts/`, and the vulnerable run finishes by printing the comparison:

```sh
docker compose run --rm --no-deps browser python -m originjack.compare --verbose
```

Expected outcome of the full run: **17 scenarios — 12 secure, 5 vulnerable**, and a green
gate. The five vulnerable verdicts are shapes 1, 2 (twice — both lookalikes) and 3, plus
the simple-`POST` control.

---

## 4. The exposure

The victim is logged in to Meridian Payroll in another tab. They click a link and land on
`https://promo.attacker.example`, which runs one `fetch`:

```js
fetch("https://legacy-api.meridianpay.example/me/payslip", { credentials: "include" })
```

No exploit. No injection. No stolen password. It is the same request the payroll
provider's own front-end makes, written by someone else, on a domain that has nothing to
do with payroll. What happens next is decided entirely by the two headers the API sends
back:

```
[1] attacker read (vulnerable API)                            VERDICT: VULNERABLE
    server response       status=200  ACAO=https://promo.attacker.example  ACAC=true
    browser released      yes
    victim data rendered  yes
    decided by            THE SERVER — it echoed the caller's own origin back as an
                          allowed one; the browser complied, correctly
```

The attacker's page now shows Rowan's net pay, tax reference, payout-account tail, and
session API token. The browser did nothing wrong: it was told this origin was allowed, and
it believed the only party entitled to say so.

Point the identical page at the secure API and:

```
[2] attacker read (secure API)                                VERDICT: SECURE
    server response       status=200  ACAO=(absent)  ACAC=(absent)  browser-failure=net::ERR_FAILED
    browser released      no
    victim data rendered  no
    decided by            THE BROWSER — the server answered 200; the browser withheld
                          that answer from the page
```

**Both servers answered in full.** The request was sent, the cookie was carried, the
payslip was generated and put on the wire. The page was told only `TypeError: Failed to
fetch`, because one response header was missing.

---

## 5. The ladder of three shapes

They are the same mistake at three levels of effort — and the later two are **more**
dangerous than the first, because they arrive with the reassurance of looking deliberate.

### Shape 1 — origin reflection

```python
return CorsDecision(granted=True, allow_origin=origin, allow_credentials=True)
```

No comparison. No set. No check of any kind. Usually arrived at honestly: several
front-ends needed to work, a wildcard was refused by the browser because credentials were
involved, and echoing the request's own origin made the error go away. It does make the
error go away. It also means every origin on the internet is now an allowed origin.

### Shape 2 — the sloppy allowlist match

An unanchored check against the corporate domain. `promo.attacker.example` is now
**blocked**, so the obvious attack stops working and the configuration looks repaired.
Both of these walk straight through it:

| Origin | Why it matches | Who owns it |
|---|---|---|
| `app.meridianpay.example.attacker.example` | the corporate domain appears in the middle | the attacker |
| `notmeridianpay.example` | it appears at the end | the attacker |

A plain `in`, an `endswith` that forgets the leading dot, and a regular expression missing
its anchors all have this hole. **The bug is not the technique — it is comparing anything
other than whole origins.** A domain is not a prefix of another domain by accident; anyone
can register `notmeridianpay.example`, and anyone who owns `attacker.example` owns every
name under it.

### Shape 3 — the allowlisted `null` origin

```python
allowed_origins = (*settings.allowed_origins, "null")   # the one-entry difference
```

This shape does everything right except the one thing. It compares whole strings against a
fixed server-side set — exactly as a correct policy does. Someone added `null` to that set,
because a sandboxed iframe or a redirect chain needed it and the request looked harmless.

`null` is not an origin. It is what the browser sends *instead of* one, when a document has
no origin to report. Any page can arrange that in a single HTML attribute:

```html
<iframe sandbox="allow-scripts" src="/sandboxed.html"></iframe>
```

```
[11] null origin — sandboxed frame                            VERDICT: VULNERABLE
     server response   status=200  sent-Origin=null  ACAO=null  ACAC=true
     decided by        THE SERVER — `null` was in its accepted set, and any page can
                       arrange to send it; the browser complied, correctly
     · The browser reported that frame's origin to its parent as: null.
```

An allowlist containing `null` allows everybody. It is the most instructive of the three
precisely because it is *so nearly right*, and because it would survive most code review.

---

## 6. What CORS is *not*

Three controls, each correcting a belief people hold confidently.

### "We don't use `*`, so we're fine"

The wildcard *with credentials* is refused **by the browser itself** — the specification
forbids the combination:

```
[14] wildcard with credentials                                VERDICT: SECURE
     server response   status=200  ACAO=*  ACAC=true  browser-failure=net::ERR_FAILED
     decided by        THE BROWSER — the server answered 200; the browser withheld
                       that answer from the page
```

**The boundary this establishes:** the wildcard is not the dangerous shape. Under
credentials it fails safe — and it fails safe *indiscriminately*: the legitimate
first-party origin attempting the identical read against this deployment is blocked too. A
wildcard with credentials is not a lax policy; it is a broken one, which is why nobody ships
it and why "we never use `*`" is not evidence of a correct policy.

Reflection, which looks more careful, is the shape that hands the data over.

### "CORS protects our write endpoints"

It does not, and never did. A **simple** cross-origin `POST` — a CORS-safelisted content
type, no custom header — triggers no preflight at all, because it is a request an HTML form
could already have made:

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

The attacker could not read the answer. CORS did its job perfectly. The victim's salary is
going somewhere else.

**The boundary this establishes:** CORS governs **reading** a response, never **sending** a
request, and is therefore not a CSRF defence. The secure API refuses the identical request
with `415` because its route requires a non-simple content type *and* a matching CSRF
token — neither of which a simple cross-site request can carry — and canonical state is
byte-for-byte unchanged.

### "`SameSite` fixed this"

It withholds the *credential*, not the cross-origin read:

```
[17] SameSite=Lax contrast                                    VERDICT: SECURE
     server response       status=401  ACAO=https://promo.attacker.example  ACAC=true
     browser released      yes
     victim data rendered  no
```

Look at what succeeded. The grant is intact. The browser released the response to the
attacker's origin, exactly as the policy told it to. There is simply nothing in it, because
`Lax` withheld the cookie on a cross-site request and the API answered an unauthenticated
`401`.

**The limits:** the misconfiguration is completely unchanged, and `SameSite` protects
nothing at all for the many real services that legitimately set `SameSite=None; Secure` — a
separate front-end domain, an embedded third-party surface, a deliberately cross-site API.
Meridian Payroll is one of them, which is why the default configuration of this demo is the
one where it is fatal.

---

## 7. The fix

A **strict, exact-match origin allowlist**:

```python
for allowlisted in self.allowed_origins:      # a fixed, server-side set
    if origin == allowlisted:                 # whole-string comparison
        return CorsDecision(
            granted=True,
            allow_origin=allowlisted,         # the value we hold, not the one we were sent
            allow_credentials=True,
            ...
        )
return REFUSED
```

Every clause is load-bearing:

- **a fixed server-side set** — not derived from the request, not read from a header;
- **whole-string comparison** — no substring, prefix, suffix, or regular expression;
- **the allowlisted value in the response** — equal to the request's value here by
  construction, but distinct as a matter of policy. This is what makes the policy
  structurally incapable of degenerating into reflection, and the test that guards it
  asserts *identity*, not equality, because equality cannot tell them apart;
- **never `*`, never `null`** — one allows nobody usefully, the other allows everybody;
- **`Vary: Origin` on every response**, refusals included, so no shared cache can hand one
  origin's answer to another;
- **narrow, enumerated methods and headers**, and a preflight response that never widens
  the policy.

A non-matching origin receives **no** `Access-Control-Allow-Origin` and no credential
grant, and the API emits exactly one generic audit event that names no accepted origin and
gives no allowlist oracle — a refused caller learns only that it was refused.

**And the legitimate application keeps working, unchanged.** `app.meridianpay.example` is on
the allowlist; it performs the same credentialed cross-origin read and the same
CSRF-protected write it always did, and receives a payslip payload byte-identical to the
vulnerable API's. That is the whole test of a fix: it changes the security-relevant
behaviour and nothing else.

---

## 8. What to look for in your own systems

- **The client-side symptom of a blocked read** is a `fetch` that rejects with a bare
  network error — `TypeError: Failed to fetch` in Chromium — carrying no status and no
  body. The page cannot tell a CORS refusal from a dropped connection, by design.
- **The server-side evidence of a refusal** is the audit event: one generic structured
  record per refused cross-origin request, naming the refused origin and nothing else.
- **The regression matrix** proves both halves at once — that every attacker origin is
  refused, and that the first-party origin still receives exactly what it did before. A
  security change that only proves the first half has not been tested.
- **The shape to grep for** is not `*`. It is any code path where the value written into
  `Access-Control-Allow-Origin` can be traced back to the request.

---

## 9. Deliberately not covered

**CORS response-header cache poisoning through a shared HTTP cache.** Where a response
varies by `Origin` but is cached without `Vary: Origin`, a shared cache can serve one
origin's grant to another — turning a correct policy into a broken one at a layer the
application never sees. It is a real variant and it is **named here rather than built**,
because it needs a caching tier this vulnerability does not. This demo sends `Vary: Origin`
on every response, refusals included.

Also out of scope, each a different demonstration: cross-site scripting, CSRF as its own
subject beyond the boundary control above, clickjacking, WebSocket origin validation
(CWE-1385), `postMessage` origin handling, `document.domain`, and Flash/Silverlight
`crossdomain.xml` policies.

**Browser engines.** This harness pins Chromium and claims nothing about any other engine.
The behaviour most likely to differ is third-party cookie policy: WebKit's Intelligent
Tracking Prevention and Firefox's Total Cookie Protection withhold or partition cookies on
cross-site requests by default, and Chromium has its own phase-out. Where the cookie is
withheld, a cross-site read returns an unauthenticated response — the origin policy is
unchanged and still decides whether the page may read it; only the credential is missing.
That is section 6's `SameSite` contrast arriving by a different route, and it is not a fix
for anything.
