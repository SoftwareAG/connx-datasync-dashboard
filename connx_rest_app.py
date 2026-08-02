#!/usr/bin/env python3
"""Small Flask front end for the CONNX REST Server.

The server URL is configured with CONNX_BASE_URL.  Credentials are used only
to obtain a bearer token and are never persisted by the application.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import textwrap
from contextlib import closing
from csv import DictWriter
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from connx_ai import (
    duration_seconds,
    history_trends,
    redact_history,
    request_ai_analysis,
    summarize_history,
)
from connx_platform import (
    analysis_jobs,
    consume_analysis_quota,
    consume_login_attempt,
    delete_connx_token,
    load_connx_refresh_token,
    load_connx_token,
    read_json_string_list,
    read_secret,
    store_connx_token,
)


# The server's REST namespace is ``/api/svr`` (not ``/api/srv``).
LOGIN_PATH = "/api/svr/security/login"
REFRESH_PATH = "/api/svr/security/refreshtoken"
LOGOUT_PATH = "/api/svr/security/logout"


load_dotenv()


class OperatorError(ValueError):
    """A bounded validation or policy error that is safe to show to an operator."""


def safe_http_url(value: str | None) -> str:
    """Return a displayable external URL only when it is HTTP(S)."""
    candidate = (value or "").strip()
    parsed = urlparse(candidate)
    return (
        candidate
        if parsed.scheme in {"http", "https"}
        and parsed.netloc
        and not parsed.username
        and not parsed.password
        else ""
    )


def public_server_identity(value: str) -> str:
    """Remove paths and any embedded credentials from a configured server URL."""
    parsed = urlparse(value)
    if not parsed.hostname:
        return "Not configured"
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return "Not configured"
    return f"{parsed.scheme or 'https'}://{host}{port}"

def save_analysis(
    database_path: str,
    *,
    deployment: str,
    filters: dict[str, str],
    stats: dict[str, int],
    analysis: dict[str, Any],
) -> dict[str, Any]:
    """Persist analysis provenance without storing credentials or raw history."""
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    deployment TEXT NOT NULL,
                    filters_json TEXT NOT NULL,
                    stats_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS finding_workflow (
                    analysis_id INTEGER NOT NULL,
                    finding_index INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    runbook_url TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, finding_index),
                    FOREIGN KEY (analysis_id) REFERENCES ai_analyses(id)
                )
                """
            )
            cursor = connection.execute(
                """
                INSERT INTO ai_analyses
                    (created_at, deployment, filters_json, stats_json, analysis_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    deployment,
                    json.dumps(filters, separators=(",", ":")),
                    json.dumps(stats, separators=(",", ":")),
                    json.dumps(analysis, separators=(",", ":")),
                ),
            )
    return {"id": cursor.lastrowid, "created_at": created_at, "deployment": deployment}


def load_analysis(database_path: str, analysis_id: int) -> dict[str, Any] | None:
    path = Path(database_path)
    if not path.exists():
        return None
    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT id, created_at, deployment, filters_json, stats_json, analysis_json
            FROM ai_analyses WHERE id = ?
            """,
            (analysis_id,),
        ).fetchone()
    if row is None:
        return None
    record = {
        "id": row["id"],
        "created_at": row["created_at"],
        "deployment": row["deployment"],
        "filters": json.loads(row["filters_json"]),
        "stats": json.loads(row["stats_json"]),
        "analysis": json.loads(row["analysis_json"]),
    }
    record["finding_workflow"] = load_finding_workflow(database_path, analysis_id)
    return record


def load_finding_workflow(database_path: str, analysis_id: int) -> dict[int, dict[str, str]]:
    path = Path(database_path)
    if not path.exists():
        return {}
    try:
        with closing(sqlite3.connect(path)) as connection:
            rows = connection.execute(
                """
                SELECT finding_index, status, owner, notes, runbook_url, updated_at
                FROM finding_workflow WHERE analysis_id = ?
                """,
                (analysis_id,),
            ).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {
        row[0]: {
            "status": row[1],
            "owner": row[2],
            "notes": row[3],
            "runbook_url": row[4],
            "updated_at": row[5],
        }
        for row in rows
    }


def save_finding_workflow(
    database_path: str,
    analysis_id: int,
    finding_index: int,
    *,
    status: str,
    owner: str,
    notes: str,
    runbook_url: str,
) -> None:
    if status not in {"open", "acknowledged", "in progress", "resolved"}:
        raise ValueError("Invalid finding status.")
    if runbook_url and not re.match(r"^https?://", runbook_url, re.IGNORECASE):
        raise ValueError("Runbook URL must start with http:// or https://.")
    path = Path(database_path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS finding_workflow (
                    analysis_id INTEGER NOT NULL,
                    finding_index INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    runbook_url TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, finding_index)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO finding_workflow
                    (analysis_id, finding_index, status, owner, notes, runbook_url, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id, finding_index) DO UPDATE SET
                    status=excluded.status,
                    owner=excluded.owner,
                    notes=excluded.notes,
                    runbook_url=excluded.runbook_url,
                    updated_at=excluded.updated_at
                """,
                (
                    analysis_id,
                    finding_index,
                    status,
                    owner[:100],
                    notes[:2000],
                    runbook_url[:500],
                    datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                ),
            )


def load_previous_analysis(
    database_path: str, analysis_id: int, filters: dict[str, str]
) -> dict[str, Any] | None:
    path = Path(database_path)
    if not path.exists():
        return None
    filters_json = json.dumps(filters, separators=(",", ":"))
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            """
            SELECT id FROM ai_analyses
            WHERE id < ? AND filters_json = ?
            ORDER BY id DESC LIMIT 1
            """,
            (analysis_id, filters_json),
        ).fetchone()
    return load_analysis(database_path, row[0]) if row else None


def list_analyses(database_path: str, analysis_ids: list[int]) -> list[dict[str, Any]]:
    records = []
    for analysis_id in reversed(analysis_ids[-50:]):
        if record := load_analysis(database_path, analysis_id):
            records.append(record)
    return records


def delete_analysis(database_path: str, analysis_id: int) -> bool:
    path = Path(database_path)
    if not path.exists():
        return False
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            try:
                connection.execute(
                    "DELETE FROM finding_workflow WHERE analysis_id = ?", (analysis_id,)
                )
            except sqlite3.OperationalError:
                pass
            cursor = connection.execute("DELETE FROM ai_analyses WHERE id = ?", (analysis_id,))
    return cursor.rowcount > 0


def purge_expired_analyses(database_path: str, retention_days: int) -> int:
    path = Path(database_path)
    if not path.exists():
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
    with closing(sqlite3.connect(path)) as connection:
        try:
            rows = connection.execute("SELECT id, created_at FROM ai_analyses").fetchall()
        except sqlite3.OperationalError:
            return 0
        expired = []
        for analysis_id, created_at in rows:
            try:
                if datetime.fromisoformat(created_at).timestamp() < cutoff:
                    expired.append(analysis_id)
            except ValueError:
                continue
        with connection:
            for analysis_id in expired:
                try:
                    connection.execute(
                        "DELETE FROM finding_workflow WHERE analysis_id = ?", (analysis_id,)
                    )
                except sqlite3.OperationalError:
                    pass
                connection.execute("DELETE FROM ai_analyses WHERE id = ?", (analysis_id,))
    return len(expired)


def compare_analysis_stats(
    current: dict[str, int], baseline: dict[str, Any]
) -> dict[str, Any]:
    def rate(stats: dict[str, int]) -> float:
        return stats["failures"] * 100 / stats["total"] if stats["total"] else 0

    baseline_stats = baseline["stats"]
    rate_delta = round(rate(current) - rate(baseline_stats), 1)
    return {
        "created_at": baseline["created_at"],
        "failure_rate_direction": "up" if rate_delta > 0 else "down" if rate_delta < 0 else "unchanged",
        "failure_rate_delta": abs(rate_delta),
        "failures_delta_label": f"{current['failures'] - baseline_stats['failures']:+d}",
        "total_delta_label": f"{current['total'] - baseline_stats['total']:+d}",
    }


def analysis_as_markdown(record: dict[str, Any]) -> str:
    analysis = record["analysis"]
    stats = record["stats"]
    filters = record["filters"]
    filter_summary = ", ".join(
        f"{key}={value or 'all'}" for key, value in filters.items()
    )
    lines = [
        "# CONNX Data Sync AI analysis",
        "",
        f"- Generated: {record['created_at']}",
        f"- Azure deployment: {record['deployment']}",
        f"- Filters: {filter_summary}",
        f"- Jobs analyzed: {stats['total']}",
        f"- Successful: {stats['successes']}",
        f"- Failed: {stats['failures']}",
        f"- Affected objects: {stats['affected_objects']}",
        "",
    ]
    if not analysis.get("structured"):
        return "\n".join(lines + [str(analysis.get("raw_text", "")), ""])
    lines.extend(
        [
            "## Executive summary",
            "",
            f"**Severity:** {analysis['overall_severity']}  ",
            f"**Confidence:** {analysis['confidence']}",
            "",
            analysis["executive_summary"],
            "",
        ]
    )
    for index, finding in enumerate(analysis["findings"], 1):
        lines.extend(
            [
                f"## {index}. {finding['title']}",
                "",
                f"**Severity:** {finding['severity']}  ",
                f"**Confidence:** {finding['confidence']}",
                "",
                f"**Observation:** {finding['observation']}",
                "",
                "### Evidence",
                "",
                *(f"- {item}" for item in finding["evidence"]),
                "",
                f"**Impact:** {finding['impact']}",
                "",
                "### Recommended actions",
                "",
                *(f"{number}. {item}" for number, item in enumerate(finding["recommendations"], 1)),
                "",
            ]
        )
        workflow = record.get("finding_workflow", {}).get(index - 1)
        if workflow:
            lines.extend(
                [
                    "### Operator follow-up",
                    "",
                    f"- Status: {workflow['status']}",
                    f"- Owner: {workflow['owner'] or 'Unassigned'}",
                    f"- Runbook: {workflow['runbook_url'] or 'Not linked'}",
                    f"- Notes: {workflow['notes'] or 'None'}",
                    "",
                ]
            )
    if analysis["limitations"]:
        lines.extend(
            ["## Analysis limitations", "", *(f"- {item}" for item in analysis["limitations"]), ""]
        )
    return "\n".join(lines)


def analysis_as_pdf(record: dict[str, Any]) -> bytes:
    """Render a dependency-free, multi-page text PDF from the Markdown report."""
    plain = analysis_as_markdown(record)
    plain = re.sub(r"^[#]+\s*", "", plain, flags=re.MULTILINE)
    plain = plain.replace("**", "").replace("  ", " ")
    wrapped: list[str] = []
    for line in plain.splitlines():
        wrapped.extend(textwrap.wrap(line, width=88) or [""])
    pages = [wrapped[index : index + 48] for index in range(0, len(wrapped), 48)] or [[""]]

    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    page_ids = []
    next_id = 4
    for lines in pages:
        page_id, content_id = next_id, next_id + 1
        next_id += 2
        page_ids.append(page_id)
        commands = ["BT", "/F1 9 Tf", "48 750 Td", "14 TL"]
        for line in lines:
            safe = line.encode("latin-1", "replace").decode("latin-1")
            safe = safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.extend([f"({safe}) Tj", "T*"])
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode()
        objects[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()

    output = BytesIO()
    output.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id in range(1, next_id):
        offsets.append(output.tell())
        output.write(f"{object_id} 0 obj\n".encode())
        output.write(objects[object_id])
        output.write(b"\nendobj\n")
    xref = output.tell()
    output.write(f"xref\n0 {next_id}\n".encode())
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode())
    output.write(
        f"trailer\n<< /Size {next_id} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return output.getvalue()


def create_app() -> Flask:
    app = Flask(__name__)
    configured_secret_key = read_secret("FLASK_SECRET_KEY")
    environment = os.environ.get("CONNX_ENVIRONMENT", "development").strip().lower()
    configured_database_path = os.environ.get("ANALYSIS_DB_PATH", "").strip()
    app.config.update(
        SECRET_KEY=configured_secret_key or os.urandom(32),
        CONNX_ENVIRONMENT=environment,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=(
            os.environ.get("SESSION_COOKIE_SAMESITE", "Lax").strip().title() or "Lax"
        ),
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower()
        in {"1", "true", "yes"},
        TRUSTED_HOSTS=list(read_json_string_list("TRUSTED_HOSTS")) or None,
        TRUST_PROXY_HEADERS=os.environ.get("TRUST_PROXY_HEADERS", "false").lower()
        in {"1", "true", "yes"},
        MAX_CONTENT_LENGTH=max(
            16384, min(int(os.environ.get("MAX_CONTENT_LENGTH", "1048576")), 16777216)
        ),
        HSTS_MAX_AGE=max(0, int(os.environ.get("HSTS_MAX_AGE", "31536000"))),
        LOGIN_ATTEMPTS_PER_PRINCIPAL=max(
            1, min(int(os.environ.get("LOGIN_ATTEMPTS_PER_PRINCIPAL", "10")), 1000)
        ),
        LOGIN_ATTEMPTS_PER_SOURCE=max(
            1, min(int(os.environ.get("LOGIN_ATTEMPTS_PER_SOURCE", "30")), 10000)
        ),
        LOGIN_ATTEMPT_WINDOW_SECONDS=max(
            60, min(int(os.environ.get("LOGIN_ATTEMPT_WINDOW_SECONDS", "900")), 86400)
        ),
        CONNX_BASE_URL=os.environ.get("CONNX_BASE_URL", "").strip().rstrip("/"),
        CONNX_VERIFY_TLS=os.environ.get("CONNX_VERIFY_TLS", "true").lower() not in {"0", "false", "no"},
        CONNX_ALLOW_INSECURE_TLS=os.environ.get(
            "CONNX_ALLOW_INSECURE_TLS", "false"
        ).lower()
        in {"1", "true", "yes"},
        REQUEST_TIMEOUT=float(os.environ.get("CONNX_REQUEST_TIMEOUT", "30")),
        AZURE_OPENAI_ENDPOINT=os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip(),
        AZURE_OPENAI_API_KEY=read_secret("AZURE_OPENAI_API_KEY"),
        AZURE_OPENAI_DEPLOYMENT=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip(),
        AZURE_OPENAI_AUTH_MODE=os.environ.get("AZURE_OPENAI_AUTH_MODE", "api_key").strip().lower(),
        AZURE_OPENAI_ENTRA_SCOPE=os.environ.get(
            "AZURE_OPENAI_ENTRA_SCOPE", "https://ai.azure.com/.default"
        ).strip(),
        CONNX_HEALTH_PATH=os.environ.get("CONNX_HEALTH_PATH", "").strip(),
        CONNX_HEALTH_REQUIRED=os.environ.get("CONNX_HEALTH_REQUIRED", "false").lower()
        in {"1", "true", "yes"},
        AI_REQUESTS_PER_HOUR=max(
            1, min(int(os.environ.get("AI_REQUESTS_PER_HOUR", "10")), 10000)
        ),
        AI_REQUESTS_PER_DAY=max(
            1, min(int(os.environ.get("AI_REQUESTS_PER_DAY", "25")), 10000)
        ),
        AI_HISTORY_LIMIT=max(1, min(int(os.environ.get("AI_HISTORY_LIMIT", "100")), 500)),
        AI_BACKGROUND_THRESHOLD=max(
            1, min(int(os.environ.get("AI_BACKGROUND_THRESHOLD", "200")), 500)
        ),
        AI_REDACT_OBJECT_NAMES=os.environ.get("AI_REDACT_OBJECT_NAMES", "false").lower()
        in {"1", "true", "yes"},
        AI_REDACT_ERROR_TEXT=os.environ.get("AI_REDACT_ERROR_TEXT", "false").lower()
        in {"1", "true", "yes"},
        AI_REDACTION_PATTERNS=read_json_string_list("AI_REDACTION_PATTERNS"),
        ANALYSIS_RETENTION_DAYS=max(
            1, min(int(os.environ.get("ANALYSIS_RETENTION_DAYS", "30")), 3650)
        ),
        CSRF_ENABLED=os.environ.get("CSRF_ENABLED", "true").lower() not in {"0", "false", "no"},
        ANALYSIS_DB_PATH=configured_database_path
        or os.path.join(app.instance_path, "connx_rest_app.db"),
        CONNX_SESSION_TTL_SECONDS=max(
            60, min(int(os.environ.get("CONNX_SESSION_TTL_SECONDS", "3600")), 86400)
        ),
        CONNX_APP_VERSION=os.environ.get("CONNX_APP_VERSION", "Development").strip()
        or "Development",
        CONNX_APP_BUILD=os.environ.get("CONNX_APP_BUILD", "Local").strip() or "Local",
        CONNX_SUPPORT_URL=os.environ.get("CONNX_SUPPORT_URL", "").strip(),
        CONNX_DOCUMENTATION_URL=os.environ.get("CONNX_DOCUMENTATION_URL", "").strip(),
        CONNX_PRIVACY_URL=os.environ.get("CONNX_PRIVACY_URL", "").strip(),
    )
    if app.config["CONNX_ENVIRONMENT"] not in {"development", "test", "production"}:
        raise ValueError(
            "CONNX_ENVIRONMENT must be 'development', 'test', or 'production'."
        )
    if app.config["AZURE_OPENAI_AUTH_MODE"] not in {"api_key", "entra"}:
        raise ValueError("AZURE_OPENAI_AUTH_MODE must be 'api_key' or 'entra'.")
    if app.config["CONNX_BASE_URL"]:
        connx_url = urlparse(app.config["CONNX_BASE_URL"])
        if (
            connx_url.scheme not in {"http", "https"}
            or not connx_url.netloc
            or connx_url.username
            or connx_url.password
        ):
            raise ValueError("CONNX_BASE_URL must be an HTTP(S) origin without credentials.")
    if not app.config["CONNX_VERIFY_TLS"] and not app.config["CONNX_ALLOW_INSECURE_TLS"]:
        raise ValueError(
            "CONNX_ALLOW_INSECURE_TLS must be true before TLS verification can be disabled."
        )
    if app.config["CONNX_ENVIRONMENT"] == "production":
        production_errors = []
        if not configured_secret_key:
            production_errors.append("FLASK_SECRET_KEY or FLASK_SECRET_KEY_FILE")
        if not app.config["CONNX_BASE_URL"] or urlparse(
            app.config["CONNX_BASE_URL"]
        ).scheme != "https":
            production_errors.append("an HTTPS CONNX_BASE_URL")
        if not app.config["CONNX_VERIFY_TLS"] or app.config["CONNX_ALLOW_INSECURE_TLS"]:
            production_errors.append("verified CONNX TLS")
        if not app.config["SESSION_COOKIE_SECURE"]:
            production_errors.append("SESSION_COOKIE_SECURE=true")
        if not app.config["TRUSTED_HOSTS"]:
            production_errors.append("at least one TRUSTED_HOSTS entry")
        if not configured_database_path:
            production_errors.append("an explicit ANALYSIS_DB_PATH")
        if production_errors:
            raise ValueError(
                "Unsafe production configuration; required: "
                + ", ".join(production_errors)
                + "."
            )
    if app.config["SESSION_COOKIE_SAMESITE"] not in {"Lax", "Strict", "None"}:
        raise ValueError("SESSION_COOKIE_SAMESITE must be 'Lax', 'Strict', or 'None'.")
    if (
        app.config["SESSION_COOKIE_SAMESITE"] == "None"
        and not app.config["SESSION_COOKIE_SECURE"]
    ):
        raise ValueError("SESSION_COOKIE_SECURE must be true when SameSite=None.")
    if app.config["CONNX_HEALTH_PATH"] and (
        not app.config["CONNX_HEALTH_PATH"].startswith("/")
        or app.config["CONNX_HEALTH_PATH"].startswith("//")
    ):
        raise ValueError("CONNX_HEALTH_PATH must start with one slash.")
    if app.config["TRUST_PROXY_HEADERS"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    def csrf_token() -> str:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    def log_private_error(context: str, exc: BaseException) -> str:
        """Log private exception detail and return a short support reference."""
        reference = secrets.token_hex(6)
        app.logger.warning(
            "%s [reference=%s]",
            context,
            reference,
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        return reference

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), geolocation=(), microphone=()"
        )
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        if request.is_secure and app.config["HSTS_MAX_AGE"]:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={app.config['HSTS_MAX_AGE']}; includeSubDomains",
            )
        return response

    @app.before_request
    def protect_post_requests():
        if request.method != "POST" or not app.config["CSRF_ENABLED"]:
            return None
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid or missing CSRF token.")
        return None

    def verify_tls() -> bool:
        if not app.config["CONNX_ALLOW_INSECURE_TLS"]:
            return True
        return session.get("verify_tls", app.config["CONNX_VERIFY_TLS"])

    def access_token() -> str:
        """Resolve the bearer token from the server-side session store once per request."""
        if hasattr(g, "connx_access_token"):
            return g.connx_access_token
        handle = session.get("connx_session_handle", "")
        token = load_connx_token(app.config["ANALYSIS_DB_PATH"], handle)
        if not token and handle:
            session.pop("connx_session_handle", None)
        g.connx_access_token = token or ""
        return g.connx_access_token

    def token_value(data: dict[str, Any], *names: str) -> str:
        for name in names:
            value = data.get(name)
            if value:
                return str(value)
        return ""

    def refresh_connx_session() -> bool:
        handle = session.get("connx_session_handle", "")
        refresh_token = load_connx_refresh_token(app.config["ANALYSIS_DB_PATH"], handle)
        if not refresh_token:
            return False
        try:
            response = requests.request(
                "POST",
                urljoin(f"{app.config['CONNX_BASE_URL']}/", REFRESH_PATH.lstrip("/")),
                headers={"Accept": "application/json"},
                json={"refreshToken": refresh_token},
                timeout=app.config["REQUEST_TIMEOUT"],
                verify=verify_tls(),
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("The refresh response was not a JSON object.")
            new_access_token = token_value(
                data, "accessToken", "access_token", "token"
            )
            if not new_access_token:
                raise ValueError("The refresh response did not contain an access token.")
            new_refresh_token = token_value(
                data, "refreshToken", "refresh_token"
            ) or refresh_token
            new_handle = store_connx_token(
                app.config["ANALYSIS_DB_PATH"],
                new_access_token,
                refresh_token=new_refresh_token,
                ttl_seconds=app.config["CONNX_SESSION_TTL_SECONDS"],
                previous_handle=handle,
            )
            session["connx_session_handle"] = new_handle
            g.connx_access_token = new_access_token
            return True
        except (requests.RequestException, ValueError) as exc:
            log_private_error("CONNX token refresh failed", exc)
            return False

    def remember_analysis(analysis_id: int) -> None:
        analysis_ids = [
            value for value in session.get("analysis_ids", []) if isinstance(value, int)
        ]
        if analysis_id not in analysis_ids:
            analysis_ids.append(analysis_id)
        session["analysis_ids"] = analysis_ids[-50:]
        session["last_ai_analysis_id"] = analysis_id

    def can_access_analysis(analysis_id: int) -> bool:
        return analysis_id == session.get("last_ai_analysis_id") or analysis_id in session.get(
            "analysis_ids", []
        )

    def saved_dashboard_url(anchor: str = "") -> str:
        saved = session.get("dashboard_filters", {})
        filters = saved if isinstance(saved, dict) else {}
        return url_for("jobs", **filters) + anchor

    def analysis_principal() -> str:
        if "analysis_principal" not in session:
            session["analysis_principal"] = secrets.token_urlsafe(24)
        return session["analysis_principal"]

    def pseudonymous_value(value: str) -> str:
        signing_key = app.secret_key
        if isinstance(signing_key, str):
            signing_key = signing_key.encode("utf-8")
        return hmac.new(
            signing_key, value.strip().casefold().encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def redaction_summary() -> str:
        if app.config["AI_REDACT_OBJECT_NAMES"] and app.config["AI_REDACT_ERROR_TEXT"]:
            return "object names pseudonymized, error text removed"
        if app.config["AI_REDACT_OBJECT_NAMES"]:
            return "object names pseudonymized"
        if app.config["AI_REDACT_ERROR_TEXT"]:
            return "error text removed"
        if app.config["AI_REDACTION_PATTERNS"]:
            return f"{len(app.config['AI_REDACTION_PATTERNS'])} custom pattern(s)"
        return "disabled"

    @app.context_processor
    def help_about_context() -> dict[str, Any]:
        return {
            "help_about": {
                "version": app.config["CONNX_APP_VERSION"],
                "build": app.config["CONNX_APP_BUILD"],
                "server_identity": public_server_identity(app.config["CONNX_BASE_URL"]),
                "ai_deployment": app.config["AZURE_OPENAI_DEPLOYMENT"] or "Not configured",
                "ai_auth_mode": (
                    "Microsoft Entra ID"
                    if app.config["AZURE_OPENAI_AUTH_MODE"] == "entra"
                    else "API key"
                ),
                "history_limit": app.config["AI_HISTORY_LIMIT"],
                "hourly_limit": app.config["AI_REQUESTS_PER_HOUR"],
                "daily_limit": app.config["AI_REQUESTS_PER_DAY"],
                "retention_days": app.config["ANALYSIS_RETENTION_DAYS"],
                "redaction": redaction_summary(),
                "preflight": (
                    "required"
                    if app.config["CONNX_HEALTH_PATH"]
                    and app.config["CONNX_HEALTH_REQUIRED"]
                    else "enabled"
                    if app.config["CONNX_HEALTH_PATH"]
                    else "not configured"
                ),
                "support_url": safe_http_url(app.config["CONNX_SUPPORT_URL"]),
                "documentation_url": safe_http_url(
                    app.config["CONNX_DOCUMENTATION_URL"]
                ),
                "privacy_url": safe_http_url(app.config["CONNX_PRIVACY_URL"]),
            }
        }

    def call(
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        allow_refresh: bool = True,
    ) -> requests.Response:
        if not app.config["CONNX_BASE_URL"]:
            raise ValueError("CONNX_BASE_URL is not configured.")
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Path must start with one slash.")
        headers = {"Accept": "application/json"}
        if token := access_token():
            headers["Authorization"] = f"bearer {token}"
        response = requests.request(
            method,
            urljoin(f"{app.config['CONNX_BASE_URL']}/", path.lstrip("/")),
            headers=headers,
            json=body,
            params=params,
            timeout=app.config["REQUEST_TIMEOUT"],
            verify=verify_tls(),
        )
        if (
            allow_refresh
            and response.status_code == 401
            and path not in {LOGIN_PATH, REFRESH_PATH, LOGOUT_PATH}
            and refresh_connx_session()
        ):
            retry_headers = {**headers, "Authorization": f"bearer {access_token()}"}
            response = requests.request(
                method,
                urljoin(f"{app.config['CONNX_BASE_URL']}/", path.lstrip("/")),
                headers=retry_headers,
                json=body,
                params=params,
                timeout=app.config["REQUEST_TIMEOUT"],
                verify=verify_tls(),
            )
        return response

    def get_json(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = call("GET", path, params=params)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("The server returned an unexpected response.")
        return data

    def dashboard_filters() -> dict[str, str]:
        source = request.args if request.method == "GET" else request.form
        filters = {
            "search": source.get("search", "").strip(),
            "status": source.get("status", "").lower(),
            "item_type": source.get("item_type", "All"),
            "period": source.get("period", "24 hours"),
            "page": source.get("page", "1"),
        }
        if filters["status"] not in {"", "success", "failure"}:
            filters["status"] = ""
        if filters["item_type"] not in {"All", "Table", "Group", "Transform"}:
            filters["item_type"] = "All"
        if filters["period"] not in {"24 hours", "1 week", "1 month", "1 year", "all time"}:
            filters["period"] = "24 hours"
        if not filters["page"].isdigit() or int(filters["page"]) < 1:
            filters["page"] = "1"
        return filters

    def nonempty_params(**values: Any) -> dict[str, Any]:
        """Match the CONNX web client: omit empty optional query parameters."""
        return {key: value for key, value in values.items() if value not in {None, ""}}

    def error_summary(row: dict[str, Any]) -> str:
        error = row.get("error") or row.get("lasterrordescription") or ""
        compact = " ".join(str(error).split())
        return compact if len(compact) <= 180 else f"{compact[:177]}…"

    def first_value(data: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in data:
                return data[key]
        lowered = {key.lower(): value for key, value in data.items()}
        for key in keys:
            if key.lower() in lowered:
                return lowered[key.lower()]
        return None

    def is_enabled(value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "available"}
        return bool(value)

    def yes_no_status(value: Any) -> str:
        return "Available" if is_enabled(value) else "Unavailable"

    def optional_json(title: str, path: str) -> dict[str, Any]:
        try:
            return {"data": get_json(path), "error": ""}
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status in {401, 403, 404}:
                return {
                    "data": {},
                    "error": (
                        f"{title} is not available for this session "
                        f"(HTTP {status})."
                    ),
                }
            reference = log_private_error(f"Unable to load {title}", exc)
            return {
                "data": {},
                "error": f"{title} is temporarily unavailable. Reference {reference}.",
            }
        except (requests.RequestException, ValueError) as exc:
            reference = log_private_error(f"Unable to load {title}", exc)
            return {
                "data": {},
                "error": f"{title} is temporarily unavailable. Reference {reference}.",
            }

    def list_value(data: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
        value = first_value(data, *keys)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        for container_key in (
            "ObjectCollection",
            "objectCollection",
            "ScheduleList",
            "scheduleList",
        ):
            nested = first_value(data, container_key)
            if isinstance(nested, dict):
                nested_value = first_value(nested, *keys)
                if isinstance(nested_value, list):
                    return [item for item in nested_value if isinstance(item, dict)]
        return []

    def text_value(row: dict[str, Any], *keys: str) -> str:
        value = first_value(row, *keys)
        return "" if value is None or value == "" else str(value)

    def truthy_value(row: dict[str, Any], *keys: str, default: bool = False) -> bool:
        value = first_value(row, *keys)
        return default if value is None else is_enabled(value)

    def datasync_environment() -> dict[str, Any]:
        try:
            data = get_json("/api/ds/env")
            messages = first_value(
                data,
                "transformLicenseMessages",
                "TransformLicenseMessages",
            )
            if isinstance(messages, str):
                license_messages = [messages] if messages.strip() else []
            elif isinstance(messages, list):
                license_messages = [
                    str(message)
                    for message in messages
                    if str(message).strip()
                ]
            else:
                license_messages = []
            connected = is_enabled(first_value(data, "isconnected", "isConnected"))
            datasync_available = is_enabled(
                first_value(data, "dataSyncAvailable", "DataSyncAvailable")
            )
            transforms_available = is_enabled(
                first_value(data, "transformsAvailable", "TransformsAvailable")
            )
            return {
                "state": (
                    "healthy"
                    if connected and datasync_available and transforms_available
                    else "warning"
                ),
                "cdd_name": first_value(data, "CDDName", "cddName") or "Not reported",
                "checks": [
                    ("CDD connection", yes_no_status(connected)),
                    ("DataSync", yes_no_status(datasync_available)),
                    ("Transforms", yes_no_status(transforms_available)),
                ],
                "license_messages": license_messages,
                "error": "",
            }
        except (requests.RequestException, ValueError) as exc:
            reference = log_private_error("Unable to load DataSync environment", exc)
            return {
                "state": "unavailable",
                "cdd_name": "Unavailable",
                "checks": [],
                "license_messages": [],
                "error": f"DataSync environment is unavailable. Reference {reference}.",
            }

    def schedule_insights() -> dict[str, Any]:
        result = optional_json("Schedule health", "/api/object/schedules")
        if result["error"]:
            return {"error": result["error"], "metrics": [], "rows": []}
        schedules = list_value(
            result["data"], "ScheduleItems", "scheduleItems", "ItemList", "items"
        )
        rows = []
        for schedule in schedules[:25]:
            name = text_value(schedule, "Name", "name")
            item_type = text_value(schedule, "ItemType", "itemtype", "type")
            item_name = text_value(schedule, "ItemName", "itemname", "SyncObjectName")
            enabled = truthy_value(schedule, "Enabled", "enabled", default=True)
            uses_trigger = truthy_value(schedule, "UseTriggerFile", "useTriggerFile")
            has_tasks = any(
                text_value(schedule, key)
                for key in ("BeforeSyncTask", "OnSuccessTask", "OnFailureTask")
            )
            rows.append(
                {
                    "name": name or item_name or "Unnamed schedule",
                    "item": item_name or "Not reported",
                    "item_type": item_type or "Unknown",
                    "sync_type": text_value(schedule, "SyncType", "synctype") or "Not reported",
                    "cadence": " / ".join(
                        value
                        for value in (
                            text_value(schedule, "DateFrequency", "dateFrequency"),
                            text_value(schedule, "TimeFrequency", "timeFrequency"),
                        )
                        if value
                    )
                    or "Not reported",
                    "enabled": yes_no_status(enabled),
                    "trigger": yes_no_status(uses_trigger),
                    "dependencies": yes_no_status(has_tasks),
                    "end_date": text_value(schedule, "EndDate", "endDate") or "None",
                }
            )
        metrics = [
            ("Schedules", len(schedules)),
            ("Enabled", sum(1 for row in rows if row["enabled"] == "Available")),
            ("Trigger files", sum(1 for row in rows if row["trigger"] == "Available")),
            ("Task hooks", sum(1 for row in rows if row["dependencies"] == "Available")),
        ]
        return {"error": "", "metrics": metrics, "rows": rows}

    def object_key(item_type: str, item_name: str) -> str:
        return f"{item_type.strip().lower()}:{item_name.strip().casefold()}"

    def inventory_insights(
        *,
        schedules: dict[str, Any],
        table_rows: list[dict[str, Any]],
        group_rows: list[dict[str, Any]],
        transform_rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        result = optional_json("Syncable inventory", "/api/object/allobjects")
        if result["error"]:
            return {"error": result["error"], "metrics": [], "stale": []}
        objects = list_value(result["data"], "ItemList", "ObjectList", "items")
        counts = {"Table": 0, "Group": 0, "Transform": 0, "Other": 0}
        scheduled = {
            object_key(row["item_type"], row["item"])
            for row in schedules.get("rows", [])
            if row.get("item") and row.get("item") != "Not reported"
        }
        scheduled_count = 0
        for item in objects:
            item_type = text_value(item, "ItemType", "itemtype", "type") or "Other"
            item_name = text_value(
                item, "ItemName", "itemname", "Name", "name", "table", "groupname"
            )
            normalized_type = item_type.capitalize()
            if normalized_type not in counts:
                normalized_type = "Other"
            counts[normalized_type] += 1
            if item_name and object_key(item_type, item_name) in scheduled:
                scheduled_count += 1
        asset_rows = [*table_rows, *group_rows, *transform_rows]
        stale = []
        recurring_failures = 0
        never_run = 0
        for row in asset_rows:
            status = text_value(row, "laststatus").lower()
            started = text_value(row, "laststarttime")
            if not started:
                never_run += 1
            if status in {"failure", "failed", "false"}:
                recurring_failures += 1
                stale.append(
                    {
                        "name": text_value(
                            row,
                            "table",
                            "groupname",
                            "transformname",
                            "itemname",
                        )
                        or "Unknown",
                        "status": text_value(row, "laststatus") or "Unknown",
                        "started": started or "Never",
                    }
                )
        total_objects = len(objects)
        metrics = [
            ("Syncable objects", total_objects),
            ("Tables", counts["Table"]),
            ("Groups", counts["Group"]),
            ("Transforms", counts["Transform"]),
            ("Scheduled", scheduled_count),
            ("Unscheduled", max(total_objects - scheduled_count, 0)),
            ("Never run", never_run),
            ("Failed last sync", recurring_failures),
        ]
        return {"error": "", "metrics": metrics, "stale": stale[:10]}

    def percentile(values: list[float], percent: float) -> float:
        if not values:
            return 0
        ordered = sorted(values)
        index = (len(ordered) - 1) * percent
        lower = int(index)
        upper = min(lower + 1, len(ordered) - 1)
        if lower == upper:
            return ordered[lower]
        return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)

    def analytics_insights(history_rows: list[dict[str, Any]]) -> dict[str, Any]:
        durations = [duration_seconds(row.get("duration")) for row in history_rows]
        rows_processed = []
        failures_by_error: dict[str, int] = {}
        sync_mix: dict[str, int] = {}
        for row in history_rows:
            try:
                rows_processed.append(int(row.get("processedrows") or 0))
            except (TypeError, ValueError):
                rows_processed.append(0)
            sync_type = text_value(row, "synctype") or "Unknown"
            sync_mix[sync_type] = sync_mix.get(sync_type, 0) + 1
            if str(row.get("success", "")).lower() not in {"true", "1", "yes", "success"}:
                signature = text_value(row, "error_summary", "error") or "Unspecified failure"
                failures_by_error[signature] = failures_by_error.get(signature, 0) + 1
        total_duration = sum(durations)
        total_rows = sum(rows_processed)
        metrics = [
            ("Median duration", round(percentile(durations, 0.50), 1)),
            ("95th percentile duration", round(percentile(durations, 0.95), 1)),
            ("Processed rows", total_rows),
            (
                "Rows/sec",
                round(total_rows / total_duration, 1) if total_duration else 0,
            ),
        ]
        return {
            "metrics": metrics,
            "sync_mix": sorted(sync_mix.items()),
            "failures": sorted(
                failures_by_error.items(), key=lambda item: item[1], reverse=True
            )[:5],
        }

    def config_posture() -> dict[str, Any]:
        result = optional_json("DataSync configuration", "/api/config/settings")
        if result["error"]:
            return {"error": result["error"], "settings": []}
        data = result["data"]
        nested_settings = first_value(data, "settings", "Settings")
        if isinstance(nested_settings, dict):
            data = nested_settings
        safe_fields = [
            ("Max worker threads", "maxworkerthreads", "MaxWorkerThreads"),
            ("History retention days", "historydays", "HistoryDays"),
            ("Batch size", "batchsize", "BatchSize"),
            ("Full reload threshold", "fullreloadthreshold", "FullReloadThreshold"),
            ("Retry failed syncs", "retryfailedsyncs", "RetryFailedSyncs"),
            ("Retry count", "retrycount", "RetryCount"),
            ("Drop on full reload", "droponfull", "DropOnFull"),
            ("Delete on purge", "deleteonpurge", "DeleteOnPurge"),
            ("Add CNXSYNCDATE", "addcnxsyncdate", "AddCnxSyncDate"),
            ("Disable logging", "disablelogging", "DisableLogging"),
        ]
        settings = []
        for label, *keys in safe_fields:
            value = first_value(data, *keys)
            if value is not None and value != "":
                settings.append((label, str(value)))
        return {"error": "", "settings": settings}

    def server_metadata() -> dict[str, Any]:
        result = optional_json("Server environment", "/api/svr/env")
        if result["error"]:
            return {"error": result["error"], "metadata": []}
        data = result["data"]
        safe_fields = [
            ("Version", "version", "Version"),
            ("Server time", "currentTime", "CurrentTime"),
            ("Timezone", "timezone", "TimeZone"),
            ("Client timeout", "clientTimeout", "ClientTimeout"),
        ]
        metadata = []
        for label, *keys in safe_fields:
            value = first_value(data, *keys)
            if value is not None and value != "":
                metadata.append((label, str(value)))
        return {"error": "", "metadata": metadata}

    @app.get("/")
    def index():
        if access_token():
            return redirect(url_for("jobs"))
        return render_template(
            "login.html",
            base_url=public_server_identity(app.config["CONNX_BASE_URL"]),
            connx_configured=bool(app.config["CONNX_BASE_URL"]),
            allow_insecure_tls=app.config["CONNX_ALLOW_INSECURE_TLS"],
            verify_tls=verify_tls(),
        )

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.route("/jobs", methods=["GET", "POST"])
    def jobs():
        if not access_token():
            flash("Sign in before opening the Data Sync dashboard.")
            return redirect(url_for("index"))

        filters = dashboard_filters()
        session["dashboard_filters"] = filters
        analysis_scope = request.form.get("analysis_scope", "all") if request.method == "POST" else "all"
        if analysis_scope not in {"all", "failures", "selected"}:
            analysis_scope = "all"
        selected_indices: set[int] = set()
        purge_expired_analyses(
            app.config["ANALYSIS_DB_PATH"], app.config["ANALYSIS_RETENTION_DAYS"]
        )

        def panel(title: str, path: str, list_key: str, columns: list[tuple[str, str]], params: dict[str, Any]) -> dict[str, Any]:
            try:
                data = get_json(path, params)
                rows = [{**row, "error_summary": error_summary(row)} for row in data.get(list_key, []) if isinstance(row, dict)]
                return {
                    "title": title,
                    "columns": columns,
                    "rows": rows,
                    "total": data.get("TotalNumberOfMatches"),
                    "successes": data.get("NumberOfSuccess"),
                    "failures": data.get("NumberOfFailures"),
                    "last_page": data.get("LastPageFlag"),
                }
            except (requests.RequestException, ValueError) as exc:
                reference = log_private_error(f"Unable to load {title}", exc)
                return {
                    "title": title,
                    "columns": columns,
                    "rows": [],
                    "error": f"Data is temporarily unavailable. Reference {reference}.",
                }

        overview: list[tuple[str, Any]] = []
        running_columns = [("itemname", "Item"), ("itemtype", "Type"), ("currentaction", "Action"), ("processid", "Process"), ("elapsedtime", "Elapsed"), ("progresspercent", "Progress %")]
        running_process_columns = [
            ("itemname", "Item"),
            ("itemtype", "Type"),
            ("rowsprocessed", "Rows"),
            ("processid", "Process"),
            ("starttime", "Started"),
            ("elapsedtime", "Elapsed"),
            ("estimatedcompletiontime", "ETA"),
        ]
        try:
            running = get_json("/api/status/runningjobs")
            overview = [("Active syncs", running.get("ActiveSyncs", 0)), ("Queued", running.get("QueuedSyncs", 0)), ("Completed", running.get("CompletedSyncs", 0)), ("Records/sec", running.get("RecordsPerSecond", 0)), ("MB/sec", running.get("DataVolumeVelocity", 0))]
            running_panel = {
                "title": "Running threads",
                "columns": running_columns,
                "rows": running.get("RunningThreads", []),
                "process_columns": running_process_columns,
                "processes": running.get("RunningProcesses", []),
                "high_water": [
                    ("Records/sec high-water", running.get("RecordsPerSecondHighWater", 0)),
                    ("MB/sec high-water", running.get("DataVolumeVelocityHighWater", 0)),
                ],
            }
        except (requests.RequestException, ValueError) as exc:
            reference = log_private_error("Unable to load running threads", exc)
            running_panel = {
                "title": "Running threads",
                "columns": running_columns,
                "rows": [],
                "process_columns": running_process_columns,
                "processes": [],
                "high_water": [],
                "error": f"Data is temporarily unavailable. Reference {reference}.",
            }

        datasync_env = datasync_environment()

        history_params = nonempty_params(
            SearchPattern=filters["search"],
            StatusSearchPattern=filters["status"],
            TypeSearchPattern="" if filters["item_type"] == "All" else filters["item_type"],
            TimePeriod=filters["period"],
            PageNumber=int(filters["page"]),
            PageSize=app.config["AI_HISTORY_LIMIT"],
        )
        history_columns = [("success", "Status"), ("itemname", "Item"), ("itemtype", "Type"), ("synctype", "Sync type"), ("starttime", "Started"), ("duration", "Duration"), ("processedrows", "Rows"), ("insertedrows", "Inserted"), ("updatedrows", "Updated"), ("deletedrows", "Deleted"), ("error_summary", "Error")]
        history_panel = panel("Completed job history", "/api/status/completedjobs", "JobList", history_columns, history_params)
        trends = history_trends(history_panel["rows"])
        history_total = history_panel.get("total")
        history_page_number = int(filters["page"])
        has_next_page = (
            not history_panel["last_page"]
            if isinstance(history_panel.get("last_page"), bool)
            else history_page_number * app.config["AI_HISTORY_LIMIT"] < history_total
            if isinstance(history_total, int)
            else len(history_panel["rows"]) == app.config["AI_HISTORY_LIMIT"]
        )
        pagination = {
            "page": history_page_number,
            "previous_url": url_for(
                "jobs", **{**filters, "page": history_page_number - 1}
            )
            if history_page_number > 1
            else None,
            "next_url": url_for("jobs", **{**filters, "page": history_page_number + 1})
            if has_next_page
            else None,
        }
        failure_panel = panel("Failed jobs", "/api/status/completedjobs", "JobList", history_columns, {**history_params, "StatusSearchPattern": "failure"})
        if overview:
            overview.insert(0, ("Failures", history_panel.get("failures", failure_panel.get("total", 0))))

        table_panel = panel("Tables — last sync", "/api/object/tableswithstatus", "TableList", [("catalog", "Catalog"), ("schema", "Schema"), ("table", "Table"), ("laststatus", "Status"), ("lastsynctype", "Sync type"), ("laststarttime", "Started"), ("lastduration", "Duration"), ("lastprocessedrows", "Rows"), ("error_summary", "Error")], nonempty_params(TableSearchPattern=filters["search"], StatusSearchPattern=filters["status"], Pagination="false"))
        group_panel = panel("Groups — last sync", "/api/object/groupswithstatus", "GroupList", [("groupname", "Group"), ("laststatus", "Status"), ("lastsynctype", "Sync type"), ("laststarttime", "Started"), ("lastduration", "Duration"), ("lastprocessedrows", "Rows"), ("error_summary", "Error")], nonempty_params(GroupSearchPattern=filters["search"], StatusSearchPattern=filters["status"]))
        transform_panel = panel("Transforms — last sync", "/api/object/transformswithstatus", "TransformList", [("transformname", "Transform"), ("targettablename", "Target table"), ("laststatus", "Status"), ("lastsynctype", "Sync type"), ("laststarttime", "Started"), ("lastduration", "Duration"), ("lastprocessedrows", "Rows"), ("error_summary", "Error")], nonempty_params(TransformSearchPattern=filters["search"], StatusSearchPattern=filters["status"]))
        schedules = schedule_insights()
        inventory = inventory_insights(
            schedules=schedules,
            table_rows=table_panel["rows"],
            group_rows=group_panel["rows"],
            transform_rows=transform_panel["rows"],
        )
        reliability = analytics_insights(history_panel["rows"])
        configuration = config_posture()
        server_environment = server_metadata()
        ai_configured = bool(
            app.config["AZURE_OPENAI_ENDPOINT"]
            and app.config["AZURE_OPENAI_DEPLOYMENT"]
            and (
                app.config["AZURE_OPENAI_AUTH_MODE"] == "entra"
                or app.config["AZURE_OPENAI_API_KEY"]
            )
        )
        ai_analysis = None
        ai_stats = None
        ai_metadata = None
        ai_comparison = None
        ai_error = None
        ai_job_status = None
        preflight_status = {
            "state": "not-configured",
            "message": "Destination pre-flight is not configured.",
        }
        if task_id := session.get("ai_analysis_task_id"):
            task = analysis_jobs.take(
                task_id,
                database_path=app.config["ANALYSIS_DB_PATH"],
                principal=analysis_principal(),
                function=request_ai_analysis,
                runtime_arguments={"api_key": app.config["AZURE_OPENAI_API_KEY"]},
            )
            ai_job_status = task["status"]
            if task["status"] == "complete":
                completed = task["result"]
                metadata = save_analysis(
                    app.config["ANALYSIS_DB_PATH"],
                    deployment=completed["deployment"],
                    filters=completed["filters"],
                    stats=completed["stats"],
                    analysis=completed["analysis"],
                )
                remember_analysis(metadata["id"])
                session.pop("ai_analysis_task_id", None)
                ai_job_status = "complete"
            elif task["status"] in {"failed", "missing"}:
                session.pop("ai_analysis_task_id", None)
                background_error = RuntimeError(
                    task.get("error", "job was lost after restart")
                )
                reference = log_private_error(
                    "Background AI analysis failed", background_error
                )
                ai_error = f"Background AI analysis failed. Reference {reference}."
        if analysis_id := session.get("last_ai_analysis_id"):
            persisted = load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id)
            if persisted:
                remember_analysis(persisted["id"])
                ai_analysis = persisted["analysis"]
                ai_stats = persisted["stats"]
                ai_metadata = {
                    "id": persisted["id"],
                    "created_at": persisted["created_at"],
                    "deployment": persisted["deployment"],
                }
                baseline = load_previous_analysis(
                    app.config["ANALYSIS_DB_PATH"], persisted["id"], persisted["filters"]
                )
                if baseline:
                    ai_comparison = compare_analysis_stats(ai_stats, baseline)
        if request.method == "POST" and request.form.get("action") == "analyze":
            if not ai_configured:
                ai_error = "Azure OpenAI is not configured. Add the required values to .env and restart the app."
            elif history_panel.get("error"):
                ai_error = "Job history could not be loaded, so analysis was not started."
            elif not history_panel["rows"]:
                ai_error = "There are no matching job records to analyze."
            else:
                try:
                    analysis_history = history_panel["rows"][: app.config["AI_HISTORY_LIMIT"]]
                    if analysis_scope == "failures":
                        analysis_history = [
                            row
                            for row in analysis_history
                            if str(row.get("success", "")).lower()
                            not in {"true", "1", "yes", "success"}
                        ]
                    elif analysis_scope == "selected":
                        selected_indices = {
                            int(value)
                            for value in request.form.getlist("selected_jobs")
                            if value.isdigit()
                        }
                        analysis_history = [
                            row
                            for index, row in enumerate(analysis_history)
                            if index in selected_indices
                        ]
                    if not analysis_history:
                        raise OperatorError(
                            "The selected analysis scope contains no job records."
                        )
                    if app.config["CONNX_HEALTH_PATH"]:
                        try:
                            get_json(app.config["CONNX_HEALTH_PATH"])
                            preflight_status = {
                                "state": "healthy",
                                "message": "Destination pre-flight succeeded.",
                            }
                        except (requests.RequestException, ValueError) as exc:
                            reference = log_private_error(
                                "Destination pre-flight failed", exc
                            )
                            preflight_status = {
                                "state": "unavailable",
                                "message": (
                                    "Destination pre-flight failed. "
                                    f"Reference {reference}."
                                ),
                            }
                            if app.config["CONNX_HEALTH_REQUIRED"]:
                                raise OperatorError(preflight_status["message"]) from exc
                    quota = consume_analysis_quota(
                        app.config["ANALYSIS_DB_PATH"],
                        analysis_principal(),
                        hourly_limit=app.config["AI_REQUESTS_PER_HOUR"],
                        daily_limit=app.config["AI_REQUESTS_PER_DAY"],
                    )
                    if not quota["allowed"]:
                        raise OperatorError(
                            f"The {quota['reason']} AI analysis quota has been reached "
                            f"({quota[quota['reason'] + '_used']}/"
                            f"{quota[quota['reason'] + '_limit']}). Try again later."
                        )
                    ai_stats = summarize_history(analysis_history)
                    analysis_filters = {**filters, "analysis_scope": analysis_scope}
                    if len(analysis_history) >= app.config["AI_BACKGROUND_THRESHOLD"]:
                        queued_history = redact_history(
                            analysis_history,
                            redact_object_names=app.config["AI_REDACT_OBJECT_NAMES"],
                            redact_error_text=app.config["AI_REDACT_ERROR_TEXT"],
                            redaction_patterns=app.config["AI_REDACTION_PATTERNS"],
                        )
                        task_id = analysis_jobs.submit(
                            request_ai_analysis,
                            database_path=app.config["ANALYSIS_DB_PATH"],
                            principal=analysis_principal(),
                            metadata={
                                "deployment": app.config["AZURE_OPENAI_DEPLOYMENT"],
                                "filters": analysis_filters,
                                "stats": ai_stats,
                            },
                            arguments={
                                "endpoint": app.config["AZURE_OPENAI_ENDPOINT"],
                                "deployment": app.config["AZURE_OPENAI_DEPLOYMENT"],
                                "auth_mode": app.config["AZURE_OPENAI_AUTH_MODE"],
                                "entra_scope": app.config["AZURE_OPENAI_ENTRA_SCOPE"],
                                "history": queued_history,
                                "redact_object_names": False,
                                "redact_error_text": False,
                                "redaction_patterns": (),
                            },
                            runtime_arguments={
                                "api_key": app.config["AZURE_OPENAI_API_KEY"]
                            },
                        )
                        session["ai_analysis_task_id"] = task_id
                        ai_job_status = "pending"
                    else:
                        ai_analysis = request_ai_analysis(
                            endpoint=app.config["AZURE_OPENAI_ENDPOINT"],
                            api_key=app.config["AZURE_OPENAI_API_KEY"],
                            deployment=app.config["AZURE_OPENAI_DEPLOYMENT"],
                            auth_mode=app.config["AZURE_OPENAI_AUTH_MODE"],
                            entra_scope=app.config["AZURE_OPENAI_ENTRA_SCOPE"],
                            history=analysis_history,
                            redact_object_names=app.config["AI_REDACT_OBJECT_NAMES"],
                            redact_error_text=app.config["AI_REDACT_ERROR_TEXT"],
                            redaction_patterns=app.config["AI_REDACTION_PATTERNS"],
                        )
                        ai_metadata = save_analysis(
                            app.config["ANALYSIS_DB_PATH"],
                            deployment=app.config["AZURE_OPENAI_DEPLOYMENT"],
                            filters=analysis_filters,
                            stats=ai_stats,
                            analysis=ai_analysis,
                        )
                        remember_analysis(ai_metadata["id"])
                        baseline = load_previous_analysis(
                            app.config["ANALYSIS_DB_PATH"], ai_metadata["id"], analysis_filters
                        )
                        if baseline:
                            ai_comparison = compare_analysis_stats(ai_stats, baseline)
                except OperatorError as exc:
                    ai_error = str(exc)
                except Exception as exc:
                    reference = log_private_error("Azure OpenAI analysis failed", exc)
                    ai_error = f"AI analysis failed. Reference {reference}."
        if ai_analysis and ai_analysis.get("structured"):
            workflow = (
                load_finding_workflow(app.config["ANALYSIS_DB_PATH"], ai_metadata["id"])
                if ai_metadata
                else {}
            )
            empty_workflow = {"status": "open", "owner": "", "notes": "", "runbook_url": ""}
            for index, finding in enumerate(ai_analysis["findings"]):
                finding["workflow"] = workflow.get(index, empty_workflow)
        return render_template(
            "jobs.html",
            base_url=app.config["CONNX_BASE_URL"],
            filters=filters,
            overview=overview,
            datasync_env=datasync_env,
            schedules=schedules,
            inventory=inventory,
            reliability=reliability,
            configuration=configuration,
            server_environment=server_environment,
            failures=failure_panel.get("rows", []),
            panels=[running_panel, history_panel, table_panel, group_panel, transform_panel],
            pagination=pagination,
            ai_configured=ai_configured,
            ai_deployment=app.config["AZURE_OPENAI_DEPLOYMENT"],
            ai_auth_mode=app.config["AZURE_OPENAI_AUTH_MODE"],
            ai_history_limit=app.config["AI_HISTORY_LIMIT"],
            ai_hourly_limit=app.config["AI_REQUESTS_PER_HOUR"],
            ai_daily_limit=app.config["AI_REQUESTS_PER_DAY"],
            preflight_status=preflight_status,
            ai_analysis=ai_analysis,
            ai_stats=ai_stats,
            ai_metadata=ai_metadata,
            ai_comparison=ai_comparison,
            history_trends=trends,
            ai_error=ai_error,
            ai_job_status=ai_job_status,
            analysis_scope=analysis_scope,
            selected_indices=selected_indices,
            dashboard_url=url_for("jobs", **filters),
            redaction_summary=redaction_summary(),
        )

    @app.get("/jobs/analysis/<int:analysis_id>.md")
    def export_analysis(analysis_id: int):
        if not access_token():
            flash("Sign in before exporting an AI analysis.")
            return redirect(url_for("index"))
        if not can_access_analysis(analysis_id):
            abort(404)
        record = load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id)
        if record is None:
            abort(404)
        return Response(
            analysis_as_markdown(record),
            mimetype="text/markdown",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=connx-ai-analysis-{analysis_id}.md"
                )
            },
        )

    @app.get("/jobs/analysis/<int:analysis_id>.pdf")
    def export_analysis_pdf(analysis_id: int):
        if not access_token():
            flash("Sign in before exporting an AI analysis.")
            return redirect(url_for("index"))
        if not can_access_analysis(analysis_id):
            abort(404)
        record = load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id)
        if record is None:
            abort(404)
        return Response(
            analysis_as_pdf(record),
            mimetype="application/pdf",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=connx-ai-analysis-{analysis_id}.pdf"
                )
            },
        )

    @app.post("/jobs/analysis/<int:analysis_id>/findings/<int:finding_index>")
    def update_finding(analysis_id: int, finding_index: int):
        if not access_token():
            flash("Sign in before updating an AI finding.")
            return redirect(url_for("index"))
        if not can_access_analysis(analysis_id):
            abort(404)
        record = load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id)
        findings = record["analysis"].get("findings", []) if record else []
        if finding_index < 0 or finding_index >= len(findings):
            abort(404)
        try:
            save_finding_workflow(
                app.config["ANALYSIS_DB_PATH"],
                analysis_id,
                finding_index,
                status=request.form.get("status", "open"),
                owner=request.form.get("owner", "").strip(),
                notes=request.form.get("notes", "").strip(),
                runbook_url=request.form.get("runbook_url", "").strip(),
            )
            flash("Finding follow-up saved.")
        except ValueError as exc:
            flash(str(exc))
        return redirect(saved_dashboard_url("#ai"))

    @app.get("/jobs/analyses")
    def analysis_history():
        if not access_token():
            flash("Sign in before opening AI analysis history.")
            return redirect(url_for("index"))
        purge_expired_analyses(
            app.config["ANALYSIS_DB_PATH"], app.config["ANALYSIS_RETENTION_DAYS"]
        )
        all_records = list_analyses(
            app.config["ANALYSIS_DB_PATH"], session.get("analysis_ids", [])
        )
        search = request.args.get("search", "").strip()
        severity = request.args.get("severity", "").lower()
        if severity not in {"", "critical", "high", "medium", "low", "informational"}:
            severity = ""
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        if search:
            needle = search.casefold()
            all_records = [
                record
                for record in all_records
                if needle
                in " ".join(
                    (
                        record["deployment"],
                        record["analysis"].get("executive_summary", ""),
                        record["analysis"].get("raw_text", ""),
                        " ".join(
                            finding.get("title", "")
                            for finding in record["analysis"].get("findings", [])
                            if isinstance(finding, dict)
                        ),
                    )
                ).casefold()
            ]
        if severity:
            all_records = [
                record
                for record in all_records
                if record["analysis"].get("overall_severity") == severity
            ]
        page_size = 10
        total_records = len(all_records)
        total_pages = max(1, (total_records + page_size - 1) // page_size)
        page = min(page, total_pages)
        records = all_records[(page - 1) * page_size : page * page_size]
        return render_template(
            "analysis_history.html",
            base_url=app.config["CONNX_BASE_URL"],
            records=records,
            search=search,
            severity=severity,
            pagination={
                "page": page,
                "total_pages": total_pages,
                "total_records": total_records,
                "previous_url": url_for(
                    "analysis_history", search=search, severity=severity, page=page - 1
                )
                if page > 1
                else None,
                "next_url": url_for(
                    "analysis_history", search=search, severity=severity, page=page + 1
                )
                if page < total_pages
                else None,
            },
            dashboard_url=saved_dashboard_url(),
            retention_days=app.config["ANALYSIS_RETENTION_DAYS"],
        )

    @app.get("/jobs/analyses/<int:analysis_id>/select")
    def select_analysis(analysis_id: int):
        if not access_token() or not can_access_analysis(analysis_id):
            abort(404)
        if load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id) is None:
            abort(404)
        session["last_ai_analysis_id"] = analysis_id
        return redirect(saved_dashboard_url("#ai"))

    @app.post("/jobs/analyses/<int:analysis_id>/delete")
    def delete_analysis_route(analysis_id: int):
        if not access_token() or not can_access_analysis(analysis_id):
            abort(404)
        delete_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id)
        remaining = [value for value in session.get("analysis_ids", []) if value != analysis_id]
        session["analysis_ids"] = remaining
        if session.get("last_ai_analysis_id") == analysis_id:
            if remaining:
                session["last_ai_analysis_id"] = remaining[-1]
            else:
                session.pop("last_ai_analysis_id", None)
        flash("Saved analysis deleted.")
        return redirect(url_for("analysis_history"))

    @app.get("/jobs/history.csv")
    def export_history():
        if not access_token():
            flash("Sign in before exporting Data Sync history.")
            return redirect(url_for("index"))
        filters = dashboard_filters()
        params = nonempty_params(SearchPattern=filters["search"], StatusSearchPattern=filters["status"], TypeSearchPattern="" if filters["item_type"] == "All" else filters["item_type"], TimePeriod=filters["period"], PageNumber=1, PageSize=999)
        try:
            rows = get_json("/api/status/completedjobs", params).get("JobList", [])
        except (requests.RequestException, ValueError) as exc:
            reference = log_private_error("History export failed", exc)
            flash(f"History export failed. Reference {reference}.")
            return redirect(url_for("jobs", **filters))
        fields = ["success", "itemname", "itemtype", "synctype", "starttime", "duration", "processedrows", "insertedrows", "updatedrows", "deletedrows", "error"]
        output = StringIO()
        writer = DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=connx-job-history.csv"})

    @app.post("/login")
    def login():
        session["verify_tls"] = (
            request.form.get("verify_tls") == "on"
            if app.config["CONNX_ALLOW_INSECURE_TLS"]
            else True
        )
        # CXI documentation identifies loginInfo as the POST body for this endpoint.
        payload = {
            "username": request.form.get("username", ""),
            "password": request.form.get("password", ""),
        }
        quota = consume_login_attempt(
            app.config["ANALYSIS_DB_PATH"],
            pseudonymous_value(payload["username"]),
            pseudonymous_value(request.remote_addr or "unknown"),
            principal_limit=app.config["LOGIN_ATTEMPTS_PER_PRINCIPAL"],
            source_limit=app.config["LOGIN_ATTEMPTS_PER_SOURCE"],
            window_seconds=app.config["LOGIN_ATTEMPT_WINDOW_SECONDS"],
        )
        if not quota["allowed"]:
            flash("Sign-in is temporarily unavailable. Wait before trying again.")
            response = redirect(url_for("index"))
            response.headers["Retry-After"] = str(quota["retry_after"])
            return response
        try:
            response = call("POST", LOGIN_PATH, payload)
            response.raise_for_status()
            data = response.json()
            # CONNX REST Server returns accessToken; keep the other spellings
            # for compatibility with deployments that use them.
            token = token_value(data, "accessToken", "access_token", "token")
            if not token:
                raise ValueError("The login response did not contain an access token.")
            refresh_token = token_value(data, "refreshToken", "refresh_token")
            old_handle = session.get("connx_session_handle", "")
            handle = store_connx_token(
                app.config["ANALYSIS_DB_PATH"],
                token,
                refresh_token=refresh_token,
                ttl_seconds=app.config["CONNX_SESSION_TTL_SECONDS"],
                previous_handle=old_handle,
            )
            verify_tls_setting = session.get("verify_tls", app.config["CONNX_VERIFY_TLS"])
            session.clear()
            session["verify_tls"] = verify_tls_setting
            session["connx_session_handle"] = handle
            session["analysis_principal"] = pseudonymous_value(payload["username"])
            flash("Authenticated. The bearer token is stored in the server-side session.")
            return redirect(url_for("jobs"))
        except (requests.RequestException, ValueError) as exc:
            reference = log_private_error("CONNX sign-in failed", exc)
            flash(
                "Sign-in failed. Verify the credentials and try again. "
                f"Reference {reference}."
            )
        return redirect(url_for("index"))

    @app.post("/logout")
    def logout():
        handle = session.get("connx_session_handle", "")
        token = load_connx_token(app.config["ANALYSIS_DB_PATH"], handle) or ""
        refresh_token = load_connx_refresh_token(app.config["ANALYSIS_DB_PATH"], handle) or ""
        if token or refresh_token:
            try:
                call(
                    "POST",
                    LOGOUT_PATH,
                    {"accessToken": token, "refreshToken": refresh_token},
                    allow_refresh=False,
                ).raise_for_status()
            except (requests.RequestException, ValueError) as exc:
                log_private_error("CONNX logout failed", exc)
        delete_connx_token(
            app.config["ANALYSIS_DB_PATH"], handle
        )
        session.clear()
        flash("Session cleared.")
        return redirect(url_for("index"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
