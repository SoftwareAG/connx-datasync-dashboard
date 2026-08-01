# CONNX Data Sync Operations Dashboard

[Apache License 2.0](LICENSE) · [Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md) · [Security review](SECURITY_REVIEW.md)

A standalone Flask dashboard for monitoring CONNX Data Sync operations and
requesting operator-reviewed Azure OpenAI recommendations from filtered job
history.

The dashboard is read-only with respect to CONNX Data Sync: it reads status and
object endpoints, retains saved AI analyses locally, and never starts, edits, or
cancels a sync.

## Run locally

Python 3.12 and 3.13 are supported. Python 3.13 is the preferred local and
production runtime.

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
cp .env.example .env
# Populate .env with your CONNX and Azure OpenAI settings.
.venv/bin/python connx_rest_app.py
```

Open `http://127.0.0.1:5000` and sign in with the CONNX REST credentials.
`CONNX_BASE_URL` is required and must identify the dedicated CONNX REST service
origin; the application has no built-in URL and must not be pointed at the
CONNX Web Admin interface.

For production, use the supported Gunicorn and reverse-proxy topology described
in [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Configuration and safety

`.env` is intentionally ignored by Git. It may contain the Flask signing key,
CONNX server details, and an Azure OpenAI API key; commit only `.env.example`.
CONNX bearer tokens are stored server-side in the configured SQLite database;
the signed browser cookie contains only an opaque handle. Tokens expire after
one hour by default, rotate at login, and are deleted at logout. Protect the
database as a secret-bearing file and enable `SESSION_COOKIE_SECURE` when the
application is served over HTTPS.
The Help & About panel shows only safe, non-secret metadata. Optional version,
build, support, documentation, and privacy values are documented in
`.env.example`.

## Tests

```bash
PLAYWRIGHT_BROWSERS_PATH=0 .venv/bin/python -m playwright install chromium
.venv/bin/python -W error -m unittest discover -s tests -v
```

The browser suite uses local fixtures rather than the live CONNX or Azure OpenAI
services. It covers responsive workflows, accessibility, keyboard behavior, and
visual regression states. A failed visual comparison preserves its actual image
and pixel diff under `tests/visual_actual/` for CI artifact collection.

## GitHub handoff

Before the first public push, verify the committed tree and complete reachable
history carefully:

```bash
git status
git log --oneline --all
git show --check --stat HEAD
```

Confirm that `.env`, `.venv/`, `instance/`, and generated test artifacts are
not tracked and that the history contains no credentials or sensitive
infrastructure metadata. Create an empty GitHub repository, add it as `origin`,
then push:

```bash
git remote add origin <your-github-repository-url>
git push -u origin main
```

## License

Licensed under the [Apache License 2.0](LICENSE). Third-party assets and their
retained license locations are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
