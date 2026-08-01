"""Platform helpers for the CONNX REST application."""

from __future__ import annotations

import os
import json
import secrets
import sqlite3
import threading
import uuid
from contextlib import closing
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


def read_secret(name: str, default: str = "") -> str:
    """Read a secret from NAME_FILE first, then NAME, for mounted-secret support."""
    if file_name := os.environ.get(f"{name}_FILE"):
        return Path(file_name).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default).strip()


def read_json_string_list(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "[]")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be a JSON array of strings.") from exc
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{name} must be a JSON array of strings.")
    return tuple(value for value in values if value)


def store_connx_token(
    database_path: str,
    access_token: str,
    *,
    ttl_seconds: int,
    previous_handle: str = "",
    now: datetime | None = None,
) -> str:
    """Store a CONNX token server-side and return an opaque browser handle."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = (current + timedelta(seconds=ttl_seconds)).isoformat()
    handle = secrets.token_urlsafe(32)
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    with closing(sqlite3.connect(database_path, timeout=10)) as connection:
        with connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS connx_sessions (
                       handle TEXT PRIMARY KEY,
                       access_token TEXT NOT NULL,
                       expires_at TEXT NOT NULL
                   )"""
            )
            connection.execute(
                "DELETE FROM connx_sessions WHERE expires_at <= ?", (current.isoformat(),)
            )
            if previous_handle:
                connection.execute(
                    "DELETE FROM connx_sessions WHERE handle = ?", (previous_handle,)
                )
            connection.execute(
                "INSERT INTO connx_sessions(handle, access_token, expires_at) VALUES (?, ?, ?)",
                (handle, access_token, expires_at),
            )
    return handle


def load_connx_token(
    database_path: str, handle: str, *, now: datetime | None = None
) -> str | None:
    """Return an unexpired server-side CONNX token for an opaque handle."""
    if not handle or not Path(database_path).exists():
        return None
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    with closing(sqlite3.connect(database_path, timeout=10)) as connection:
        try:
            row = connection.execute(
                "SELECT access_token, expires_at FROM connx_sessions WHERE handle = ?",
                (handle,),
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        if row is None:
            return None
        if row[1] <= current:
            with connection:
                connection.execute("DELETE FROM connx_sessions WHERE handle = ?", (handle,))
            return None
        return str(row[0])


def delete_connx_token(database_path: str, handle: str) -> None:
    """Delete a server-side CONNX token, if the session store exists."""
    if not handle or not Path(database_path).exists():
        return
    with closing(sqlite3.connect(database_path, timeout=10)) as connection:
        try:
            with connection:
                connection.execute("DELETE FROM connx_sessions WHERE handle = ?", (handle,))
        except sqlite3.OperationalError:
            return


def consume_analysis_quota(
    database_path: str,
    principal: str,
    *,
    hourly_limit: int,
    daily_limit: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Atomically consume one server-side analysis allowance for a session."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    hourly_start = (current - timedelta(hours=1)).isoformat()
    daily_start = (current - timedelta(hours=24)).isoformat()
    created_at = current.isoformat()
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path, timeout=10)) as connection:
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ai_usage (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   principal TEXT NOT NULL,
                   created_at TEXT NOT NULL
               )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_usage_principal_time "
            "ON ai_usage(principal, created_at)"
        )
        connection.execute("DELETE FROM ai_usage WHERE created_at < ?", (daily_start,))
        hourly_used = connection.execute(
            "SELECT COUNT(*) FROM ai_usage WHERE principal = ? AND created_at >= ?",
            (principal, hourly_start),
        ).fetchone()[0]
        daily_used = connection.execute(
            "SELECT COUNT(*) FROM ai_usage WHERE principal = ? AND created_at >= ?",
            (principal, daily_start),
        ).fetchone()[0]
        allowed = hourly_used < hourly_limit and daily_used < daily_limit
        if allowed:
            connection.execute(
                "INSERT INTO ai_usage(principal, created_at) VALUES (?, ?)",
                (principal, created_at),
            )
            hourly_used += 1
            daily_used += 1
        connection.commit()
    reason = ""
    if not allowed:
        reason = "hourly" if hourly_used >= hourly_limit else "daily"
    return {
        "allowed": allowed,
        "reason": reason,
        "hourly_used": hourly_used,
        "hourly_limit": hourly_limit,
        "daily_used": daily_used,
        "daily_limit": daily_limit,
    }


def consume_login_attempt(
    database_path: str,
    principal: str,
    source: str,
    *,
    principal_limit: int,
    source_limit: int,
    window_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Atomically reserve a bounded login attempt for a principal and source."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cutoff = (current - timedelta(seconds=window_seconds)).isoformat()
    created_at = current.isoformat()
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    with closing(sqlite3.connect(database_path, timeout=10)) as connection:
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS login_attempts (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   principal TEXT NOT NULL,
                   source TEXT NOT NULL,
                   created_at TEXT NOT NULL
               )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_login_attempts_principal_time "
            "ON login_attempts(principal, created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_login_attempts_source_time "
            "ON login_attempts(source, created_at)"
        )
        connection.execute("DELETE FROM login_attempts WHERE created_at < ?", (cutoff,))
        principal_used = connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE principal = ? AND created_at >= ?",
            (principal, cutoff),
        ).fetchone()[0]
        source_used = connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE source = ? AND created_at >= ?",
            (source, cutoff),
        ).fetchone()[0]
        allowed = principal_used < principal_limit and source_used < source_limit
        if allowed:
            connection.execute(
                "INSERT INTO login_attempts(principal, source, created_at) VALUES (?, ?, ?)",
                (principal, source, created_at),
            )
            principal_used += 1
            source_used += 1
        connection.commit()
    return {
        "allowed": allowed,
        "principal_used": principal_used,
        "principal_limit": principal_limit,
        "source_used": source_used,
        "source_limit": source_limit,
        "retry_after": window_seconds,
    }


class AnalysisJobManager:
    """Small in-process executor for analysis calls that should not block HTTP."""

    def __init__(self, max_workers: int = 2):
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="connx-ai")
        self._jobs: dict[str, Future[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        function: Callable[..., dict[str, Any]],
        *,
        metadata: dict[str, Any],
        arguments: dict[str, Any],
    ) -> str:
        job_id = uuid.uuid4().hex

        def run() -> dict[str, Any]:
            return {**metadata, "analysis": function(**arguments)}

        with self._lock:
            self._jobs[job_id] = self._executor.submit(run)
        return job_id

    def take(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            future = self._jobs.get(job_id)
        if future is None:
            return {"status": "missing"}
        if not future.done():
            return {"status": "pending"}
        with self._lock:
            self._jobs.pop(job_id, None)
        try:
            return {"status": "complete", "result": future.result()}
        except Exception as exc:
            return {"status": "failed", "error": str(exc)}


class DurableAnalysisJobManager:
    """SQLite-backed background jobs shared safely across WSGI workers."""

    def __init__(
        self,
        max_workers: int = 2,
        *,
        lease_seconds: int = 60,
        retention_seconds: int = 86400,
    ):
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="connx-ai-durable"
        )
        self._lease_seconds = lease_seconds
        self._retention_seconds = retention_seconds
        self._futures: dict[str, Future[None]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _connect(database_path: str) -> sqlite3.Connection:
        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        connection = sqlite3.connect(database_path, timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ai_background_jobs (
                   id TEXT PRIMARY KEY,
                   principal TEXT NOT NULL,
                   status TEXT NOT NULL,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   lease_owner TEXT NOT NULL,
                   lease_until TEXT NOT NULL,
                   payload_json TEXT NOT NULL,
                   result_json TEXT NOT NULL,
                   error TEXT NOT NULL
               )"""
        )
        connection.commit()
        return connection

    def _cleanup(self, connection: sqlite3.Connection, current: datetime) -> None:
        cutoff = (current - timedelta(seconds=self._retention_seconds)).isoformat()
        with connection:
            connection.execute(
                "DELETE FROM ai_background_jobs WHERE updated_at < ?", (cutoff,)
            )

    def submit(
        self,
        function: Callable[..., dict[str, Any]],
        *,
        database_path: str,
        principal: str,
        metadata: dict[str, Any],
        arguments: dict[str, Any],
        runtime_arguments: dict[str, Any] | None = None,
    ) -> str:
        """Persist and start a job without storing runtime-only secrets."""
        job_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        payload = json.dumps(
            {"metadata": metadata, "arguments": arguments},
            separators=(",", ":"),
            default=str,
        )
        with closing(self._connect(database_path)) as connection:
            self._cleanup(connection, now)
            with connection:
                connection.execute(
                    """INSERT INTO ai_background_jobs
                           (id, principal, status, created_at, updated_at, lease_owner,
                            lease_until, payload_json, result_json, error)
                       VALUES (?, ?, 'pending', ?, ?, '', '', ?, '', '')""",
                    (job_id, principal, now.isoformat(), now.isoformat(), payload),
                )
        self._start(
            job_id,
            database_path=database_path,
            principal=principal,
            function=function,
            runtime_arguments=runtime_arguments or {},
        )
        return job_id

    def _start(
        self,
        job_id: str,
        *,
        database_path: str,
        principal: str,
        function: Callable[..., dict[str, Any]],
        runtime_arguments: dict[str, Any],
    ) -> None:
        with self._lock:
            current_future = self._futures.get(job_id)
            if current_future is not None and not current_future.done():
                return

        now = datetime.now(timezone.utc)
        lease_owner = uuid.uuid4().hex
        lease_until = (now + timedelta(seconds=self._lease_seconds)).isoformat()
        with closing(self._connect(database_path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT status, lease_until, payload_json
                   FROM ai_background_jobs WHERE id = ? AND principal = ?""",
                (job_id, principal),
            ).fetchone()
            claimable = bool(
                row
                and (
                    row[0] == "pending"
                    or (row[0] == "running" and row[1] and row[1] <= now.isoformat())
                )
            )
            if not claimable:
                connection.rollback()
                return
            connection.execute(
                """UPDATE ai_background_jobs
                   SET status = 'running', updated_at = ?, lease_owner = ?, lease_until = ?
                   WHERE id = ? AND principal = ?""",
                (now.isoformat(), lease_owner, lease_until, job_id, principal),
            )
            connection.commit()
            payload = json.loads(row[2])

        future = self._executor.submit(
            self._execute,
            job_id,
            database_path,
            principal,
            lease_owner,
            self._lease_seconds,
            function,
            payload,
            runtime_arguments,
        )
        with self._lock:
            self._futures[job_id] = future

        def forget(completed: Future[None]) -> None:
            with self._lock:
                if self._futures.get(job_id) is completed:
                    self._futures.pop(job_id, None)

        future.add_done_callback(forget)

    @staticmethod
    def _execute(
        job_id: str,
        database_path: str,
        principal: str,
        lease_owner: str,
        lease_seconds: int,
        function: Callable[..., dict[str, Any]],
        payload: dict[str, Any],
        runtime_arguments: dict[str, Any],
    ) -> None:
        stop_heartbeat = threading.Event()

        def renew_lease() -> None:
            interval = max(1, lease_seconds // 3)
            while not stop_heartbeat.wait(interval):
                lease_until = (
                    datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
                ).isoformat()
                with closing(DurableAnalysisJobManager._connect(database_path)) as connection:
                    with connection:
                        updated = connection.execute(
                            """UPDATE ai_background_jobs SET lease_until = ?, updated_at = ?
                               WHERE id = ? AND principal = ? AND lease_owner = ?
                                     AND status = 'running'""",
                            (
                                lease_until,
                                datetime.now(timezone.utc).isoformat(),
                                job_id,
                                principal,
                                lease_owner,
                            ),
                        ).rowcount
                if not updated:
                    return

        heartbeat = threading.Thread(
            target=renew_lease, name=f"connx-ai-lease-{job_id[:8]}", daemon=True
        )
        heartbeat.start()
        try:
            analysis = function(**payload["arguments"], **runtime_arguments)
            result_json = json.dumps(
                {**payload["metadata"], "analysis": analysis},
                separators=(",", ":"),
                default=str,
            )
            status = "complete"
            error = ""
        except Exception as exc:
            result_json = ""
            status = "failed"
            error = str(exc)[:2000]
        finally:
            stop_heartbeat.set()
            heartbeat.join(timeout=1)
        now = datetime.now(timezone.utc).isoformat()
        with closing(DurableAnalysisJobManager._connect(database_path)) as connection:
            with connection:
                connection.execute(
                    """UPDATE ai_background_jobs
                       SET status = ?, updated_at = ?, lease_owner = '', lease_until = '',
                           payload_json = '{}', result_json = ?, error = ?
                       WHERE id = ? AND principal = ? AND lease_owner = ?""",
                    (
                        status,
                        now,
                        result_json,
                        error,
                        job_id,
                        principal,
                        lease_owner,
                    ),
                )

    def take(
        self,
        job_id: str,
        *,
        database_path: str,
        principal: str,
        function: Callable[..., dict[str, Any]],
        runtime_arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Read a job result or recover an abandoned job after its lease expires."""
        now = datetime.now(timezone.utc)
        with closing(self._connect(database_path)) as connection:
            self._cleanup(connection, now)
            row = connection.execute(
                """SELECT status, result_json, error FROM ai_background_jobs
                   WHERE id = ? AND principal = ?""",
                (job_id, principal),
            ).fetchone()
        if row is None:
            return {"status": "missing"}
        if row[0] == "complete":
            return {"status": "complete", "result": json.loads(row[1])}
        if row[0] == "failed":
            return {"status": "failed", "error": row[2]}
        self._start(
            job_id,
            database_path=database_path,
            principal=principal,
            function=function,
            runtime_arguments=runtime_arguments or {},
        )
        return {"status": "pending"}


analysis_jobs = DurableAnalysisJobManager()
