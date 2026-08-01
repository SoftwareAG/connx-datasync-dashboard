# Contributing

Thank you for helping improve the CONNX Data Sync Operations Dashboard.

## Before opening an issue

- Do not include credentials, bearer tokens, `.env` contents, internal
  hostnames, customer names, job payloads, or unredacted operational data.
- Use GitHub's private vulnerability-reporting flow for security concerns; see
  [`SECURITY.md`](SECURITY.md).
- Search existing issues and the roadmap in [`TODO.md`](TODO.md).

## Local development

Use Python 3.12 or 3.13 and an isolated environment:

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
cp .env.example .env
PLAYWRIGHT_BROWSERS_PATH=0 .venv/bin/python -m playwright install chromium
```

Populate `.env` only with development or test credentials. Never commit it.
The application must remain read-only with respect to CONNX Data Sync.

## Tests

Run the complete suite and production configuration check before submitting a
pull request:

```bash
.venv/bin/python -W error -m unittest discover -s tests -v
.venv/bin/gunicorn --check-config --config gunicorn.conf.py wsgi:app
git diff --check
bandit -c pyproject.toml -r connx_ai.py connx_platform.py connx_rest_app.py wsgi.py
pip-audit -r requirements.lock
pip-licenses --format=plain
```

Browser tests use local fixtures and must not contact live CONNX or Azure
services. If a visual test fails, inspect the actual and diff images under
`tests/visual_actual/` before deciding whether behavior changed intentionally.
Update checked-in baselines only for an approved UI change:

```bash
UPDATE_VISUAL_BASELINES=1 \
  .venv/bin/python -W error -m unittest \
  tests.test_browser_ui.ConnxBrowserUITests.test_visual_regression_states -v
```

Include the reviewed baseline changes in the pull request and describe the
visual difference. Do not raise the pixel threshold to hide instability.
The checked-in baselines are separated into
`tests/visual_baselines/macos/` and `tests/visual_baselines/linux/` because
browser font rendering differs by operating system. Generate Linux baselines
with the locked Playwright version and an Ubuntu environment; never copy macOS
images into the Linux set merely to make CI pass.

To update Linux baselines, open the GitHub Actions **CI** workflow, choose
**Run workflow**, enable **Generate reviewed Linux visual baselines as an
artifact**, and run it from the intended branch. Download the
`linux-visual-baselines` artifact, inspect every image, and place the reviewed
files in `tests/visual_baselines/linux/`. Run CI again in normal comparison mode
before merging.

## Dependency updates

`requirements.txt` and `requirements-dev.txt` are the human-reviewed direct
dependency lists. After changing either file, regenerate the cross-platform,
hashed lock using Python 3.12 as the lowest supported resolver target:

```bash
uv pip compile requirements-dev.txt --python-version 3.12 \
  --no-emit-package pip --generate-hashes --output-file requirements.lock
```

Review both the direct change and the transitive lock diff. Run the security,
license, server, and browser checks above before submitting the update.
The lock intentionally relies on the isolated environment's bootstrap `pip`;
pinning and replacing a running installer can leave a partial environment.

## Pull requests

- Keep changes focused and add tests for behavior changes and regressions.
- Preserve CSRF, session ownership, redaction, quotas, trusted-host, and
  read-only endpoint protections.
- Document new environment variables in `.env.example` without real values.
- Call out changes affecting authentication, persisted data, AI inputs,
  third-party dependencies, deployment, or accessibility.
- Confirm that generated files and local databases are not staged.

By submitting a contribution, you agree that it is licensed under the Apache
License 2.0 included in this repository.
