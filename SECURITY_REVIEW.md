# Security review

Review date: 2026-08-01

## Scope and methods

The review covered the current working tree and all commits currently reachable
in the local Git repository. It included route authorization, CSRF and session
handling, outbound CONNX requests, Azure OpenAI data handling, SQLite storage,
background-job ownership, response headers, deployment configuration, ignored
files, common secret patterns, Python static analysis, declared dependencies,
and vendored browser assets.

Automated checks included:

- a Git-history scan for tracked environment/database/generated files and
  common private-key and provider-token patterns;
- Bandit 1.9.4 against the application Python modules;
- pip-audit 2.10.1 against the cleanly installed, hashed `requirements.lock`;
- a generated license inventory for all locked dependencies;
- the existing server, browser, accessibility, visual, and deployment tests.

These checks reduce risk but do not prove the absence of vulnerabilities or
secrets. Provider-side secret scanning and human review are still required
before publication.

## Results

- No `.env`, SQLite database, generated browser artifact, private-key block, or
  common GitHub, OpenAI, or AWS token pattern was found in reachable Git
  history.
- Files containing credential-related identifiers were reviewed and contained
  configuration placeholders, test fixtures, or credential-handling code—not
  an identified active credential.
- Bandit reported no findings in `connx_rest_app.py`, `connx_platform.py`,
  `connx_ai.py`, or `wsgi.py`.
- pip-audit reported no known vulnerability in the locked application,
  development, and CI dependency set. The lock relies on each isolated
  environment's bootstrap `pip` rather than replacing a running installer.
- The dependency license inventory contained permissive, Python Software
  Foundation, and MPL-2.0 terms; no strong-copyleft package was identified.
- Bootstrap and axe-core retain their upstream license texts and are summarized
  in `THIRD_PARTY_NOTICES.md`.

## Publication status

The previously identified internal-looking default CONNX hostname has been
removed from the source and all reachable Git history. A final scan of commit
history found only documented configuration placeholders, synthetic test
fixtures, and credential-handling identifiers—not an identified active secret.
No local security-review blocker to public repository creation remains. Enable
GitHub secret scanning and private vulnerability reporting after publication.

## Remediated hardening findings

The application now enforces HTTPS and certificate verification in production,
rate-limits login attempts atomically, refuses unsafe production startup
configuration, prevents dynamic response caching, and keeps upstream exception
detail in correlated server logs. The remaining publication and repository
governance tasks are maintained in `TODO.md`.

## CONNX REST Swagger guardrails

The dashboard intentionally uses read-only, customer-facing DataSync endpoints
for monitoring, trend analysis, schedule coverage, inventory counts, safe
configuration posture, and low-sensitivity server metadata. Optional endpoints
must fail independently with compact unavailable states when the logged-in
CONNX role lacks access.

The following Swagger areas remain out of scope unless a separate product and
security review approves a narrower design: cached CDD database account data,
password-like fields, SMTP recipients, server filesystem paths, script/task
paths, license-server infrastructure, SQL preview output, sync start/cancel
actions, configuration writes, user/group administration, and CDD object
mutation endpoints. If any of these areas are later exposed, the implementation
must define role requirements, redaction rules, audit expectations, tests, and
operator confirmation flows before code is merged.

## Positive controls observed

The application uses CSRF protection, an origin-constrained CONNX request
helper, server-side bearer-token storage with expiration and rotation,
session-scoped analysis authorization, owner-scoped durable AI jobs, AI input
field selection and configurable redaction, quotas, CSP and HSTS support,
trusted-host and proxy controls, request-size limits, locally vendored browser
assets, pinned CI actions, hashed dependencies, and tests for the major security
boundaries.
