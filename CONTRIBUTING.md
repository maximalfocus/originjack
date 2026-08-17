# Contributing

Thanks for looking. This is a small educational project with a narrow purpose, so the most
useful contribution is usually one that makes the demonstration *clearer* rather than bigger.

## The one command

```sh
./scripts/demo.sh
```

That builds the images, brings the secure origins up on the hermetic network, runs Ruff,
mypy and the test suite from inside that network, drives a real headless Chromium through
the scenarios, writes the transcript and screenshots to `./artifacts/`, and tears everything
down. Your host needs **Docker and nothing else** — no Python, no browser, no hosts-file
entry, no trusted certificate.

The full contrast, including the intentionally vulnerable services, takes two deliberate
actions:

```sh
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh --with-vulnerable
```

`--with-vulnerable` selects the opt-in Compose profile; `ALLOW_VULNERABLE_DEMO=true` is
checked by the vulnerable application itself. Either alone does nothing, deliberately.

**GitHub Actions runs exactly these two commands.** There is no separate CI recipe, so if
both are green locally they are green in CI. Please run them before opening a pull request.

## Boundaries that are requirements, not conventions

These come from the project's requirements, and a change that crosses one will not be
merged, however good it is otherwise:

- **Everything is fictional.** Organizations, employees, payroll figures, banks, cookies and
  API tokens are invented, and every hostname is a non-resolvable RFC 2606 `.example` name.
  Do not add a real organization, domain, identifier, or credential — not even in a comment.
- **No egress.** The demo network reaches nothing outside itself. Nothing may contact, test,
  or reproduce behaviour against any real system.
- **Two opt-in actions.** No vulnerable or attacker service may become reachable through the
  default path, and the application-level acknowledgement must stay application-level — a
  control that lives only in Compose configuration is one `docker run` away from not
  existing.
- **No committed certificate material.** The demonstration CA and every certificate are
  generated at image-build time inside the containers, and the CA key is destroyed in the
  same build layer. Nothing of that kind belongs in the repository.
- **No published ports beyond loopback**, and no cloud or deployment configuration.
- **The browser decides.** A cross-origin claim must be produced by the real browser
  executing real page script. A response-header assertion is supporting evidence and never
  a substitute — that distinction is the whole point of the project.
- **The secure policy compares whole origins.** No substring, prefix, suffix, or regular
  expression may enter `src/originjack/cors.py`; a test asserts their continued absence.

## Raising a change

Open an issue describing the outcome you want before a large change, so the scope can be
agreed first. Small fixes — a typo, a confusing sentence in the walkthrough, a broken
command — are welcome as a direct pull request.

Keep pull requests focused on one outcome, follow the surrounding style rather than
introducing a new one, and add a test at the boundary the change actually affects.

Found something that looks like a *real* vulnerability rather than the demonstrated one?
Read [`SECURITY.md`](SECURITY.md) first — it explains which is which and gives a private
reporting path.

## What this project is not taking on

Out of scope by design: a second vulnerability class as a headline, browser-engine
comparison, real certificates or domains, production authentication, cloud deployment, and
publishing a package, image, or hosted demo. Contributions in those directions will be
declined regardless of quality.

There is no service-level agreement, support commitment, or guaranteed review time. This is
maintained on a best-effort basis.

By contributing you agree that your contribution is licensed under the [MIT
License](LICENSE).
