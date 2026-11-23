# Production deployment

The supported production topology is an HTTPS reverse proxy or ingress in
front of Gunicorn, with every Gunicorn worker sharing one local persistent
SQLite database. Start the application from the repository root with:

```bash
.venv/bin/gunicorn --config gunicorn.conf.py wsgi:app
```

## Required configuration

- Set `CONNX_ENVIRONMENT=production`. Production mode refuses to start unless
  every required transport, cookie, host, signing-key, and storage safeguard is
  configured.
- Set `CONNX_BASE_URL` to the dedicated HTTPS CONNX REST service origin, keep
  `CONNX_VERIFY_TLS=true`, and keep `CONNX_ALLOW_INSECURE_TLS=false`. Do not use
  the CONNX Web Admin origin.
- Set a stable `FLASK_SECRET_KEY` (or `FLASK_SECRET_KEY_FILE`) consistently for
  every worker and restart.
- Put `ANALYSIS_DB_PATH` on persistent local storage shared by all workers. The
  file contains CONNX bearer tokens and must be readable only by the service
  account. SQLite databases on NFS or other network filesystems are unsupported.
- Terminate HTTPS at the proxy and set `SESSION_COOKIE_SECURE=true`.
- Set `TRUSTED_HOSTS` to a JSON list containing the public hostname, for example
  `["connx-ops.example.com"]`.
- Set `TRUST_PROXY_HEADERS=true` only when exactly one trusted reverse proxy
  overwrites `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`.
  Never enable it when clients can connect directly to Gunicorn.
- Login throttling uses pseudonymous hashes of the login principal and Flask's
  `request.remote_addr`. With trusted proxy headers enabled, `ProxyFix` obtains
  that address from the single proxy's `X-Forwarded-For` value. The proxy must
  overwrite—not append untrusted client input to—forwarded headers. Tune
  `LOGIN_ATTEMPTS_PER_PRINCIPAL`, `LOGIN_ATTEMPTS_PER_SOURCE`, and
  `LOGIN_ATTEMPT_WINDOW_SECONDS` for the deployment's authentication policy.
- Mount Azure and Flask secrets as files where the platform supports it.

Useful resource controls include `MAX_CONTENT_LENGTH` (one MiB by default),
`GUNICORN_WORKERS`, `GUNICORN_THREADS`, and `GUNICORN_TIMEOUT`. The default
Gunicorn configuration supports multiple workers; background AI jobs use
SQLite leases so polling can continue on any worker. A worker renews its lease
while processing. After an abrupt worker exit, another worker can recover the
job when the 60-second lease expires. Completed and failed job records expire
after 24 hours. Azure API keys are supplied to workers at runtime and are never
written into job payloads.

Pending job payloads contain only the filtered history selected for analysis,
after configured redaction has been applied. Payloads are erased when a job
completes or fails. Protect and back up the database according to the data
classification of that history, or set a lower background threshold only when
that temporary persistence is acceptable.

## Proxy and health checks

Route application traffic to Gunicorn on its private bind address. Configure
the platform liveness probe to request `GET /healthz`; a healthy process returns
HTTP 200 with `{"status":"ok"}`. Keep the CONNX server and Gunicorn port off the
public network.

Before rollout, run:

```bash
.venv/bin/python -W error -m unittest discover -s tests -v
.venv/bin/gunicorn --check-config --config gunicorn.conf.py wsgi:app
```
