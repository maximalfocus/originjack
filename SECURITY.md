# Security policy

This project is a deliberately vulnerable teaching artifact. That makes the usual security
policy the wrong shape, so read the first section before reporting anything.

## The vulnerability is the point

`originjack` exists to demonstrate **CORS misconfiguration**. The following are the subject
of the project, not defects in it, and reports about them will be closed as working as
intended:

- the permissive cross-origin policies in `src/originjack/vulnerable_cors.py` — origin
  reflection with credentials, the unanchored allowlist match, the allowlisted `null`
  origin, and the wildcard-with-credentials control;
- the vulnerable API entry point (`src/originjack/vulnerable.py`) and the origins it serves;
- the attacker pages under `web/attacker/`, including the sandboxed frame;
- the conspicuously fake fixture credentials — the demo passwords, the published session
  signing key, and the `NOT_A_REAL_TOKEN` API tokens — which are published constants so a
  reader can mint and inspect the fictional sessions themselves;
- the demonstration certificate authority generated at image-build time.

None of that is reachable by accident. Every vulnerable and attacker service is behind an
opt-in Compose profile **and** an explicit `ALLOW_VULNERABLE_DEMO=true` acknowledgement that
the application itself checks, and the whole demonstration runs on a container network with
no egress.

## What is worth reporting

An **unintended** vulnerability is something else: a defect in the parts of this repository
that are not the demonstration. For example —

- a way to start a vulnerable or attacker service **without** both opt-in actions;
- a weakness in the *secure* policy in `src/originjack/cors.py` — a substring, prefix,
  suffix, or regular-expression comparison, an origin granted that is not in the allowlist,
  or an allowlist oracle exposed to a caller;
- an escape from the hermetic network, any egress from a demo container, or a service
  reachable beyond its intended boundary;
- a real secret, real credential, or real personal data committed anywhere in this
  repository or in its history;
- a supply-chain or build-time issue in the images, dependencies, or the CA generation.

## How to report

**Use GitHub's private vulnerability reporting.** On this repository, go to the **Security**
tab and choose **Report a vulnerability**. That channel is private between you and the
maintainer.

Please do not open a public issue for an unintended vulnerability, and please do not include
any real credential or real personal data in a report.

A useful report says what you expected, what happened, and how to reproduce it — ideally the
exact commands, since the whole project runs from one.

## Scope and limits

This is local educational material. It is not a service, it is not hosted anywhere, and
there is no deployment of it to attack. It is designed to run on its own hermetic container
network against its own fictional services, and it makes **no claim of safety in any other
setting** — running the vulnerable profile anywhere reachable by anything else is outside
its design and outside this policy.

There is no service-level agreement, no guaranteed response time, and no security-update
commitment. Reports are read and handled on a best-effort basis.
