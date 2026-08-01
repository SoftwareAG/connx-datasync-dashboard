import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import requests

from connx_rest_app import (
    compare_analysis_stats,
    create_app,
    history_trends,
    load_analysis,
    public_server_identity,
    purge_expired_analyses,
    request_ai_analysis,
    safe_http_url,
    save_analysis,
    summarize_history,
)
from connx_ai import redact_history
from connx_platform import (
    AnalysisJobManager,
    DurableAnalysisJobManager,
    consume_analysis_quota,
    consume_login_attempt,
    load_connx_token,
    read_secret,
    store_connx_token,
)


class ConnxRestAppTests(unittest.TestCase):
    def make_app(self):
        handle, database_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(database_path)
        self.addCleanup(lambda: os.path.exists(database_path) and os.unlink(database_path))
        app = create_app()
        app.config.update(
            TESTING=True,
            SECRET_KEY="test",
            CONNX_BASE_URL="https://connx.test:9500",
            ANALYSIS_DB_PATH=database_path,
            CSRF_ENABLED=False,
        )
        return app

    def authenticate(self, client, token="abc"):
        handle = store_connx_token(
            client.application.config["ANALYSIS_DB_PATH"],
            token,
            ttl_seconds=client.application.config["CONNX_SESSION_TTL_SECONDS"],
        )
        with client.session_transaction() as state:
            state["connx_session_handle"] = handle
        return handle

    def test_login_stores_access_token(self):
        response = Mock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.return_value = {"accessToken": "abc"}

        with patch("connx_rest_app.requests.request", return_value=response) as send:
            client = self.make_app().test_client()
            result = client.post("/login", data={"username": "DOMAIN\\user", "password": "secret"})

        self.assertEqual(result.status_code, 302)
        self.assertEqual(result.location, "/jobs")
        self.assertEqual(send.call_args.args[1], "https://connx.test:9500/api/svr/security/login")
        self.assertEqual(send.call_args.kwargs["json"], {"username": "DOMAIN\\user", "password": "secret"})
        self.assertTrue(send.call_args.kwargs["verify"])
        with client.session_transaction() as state:
            self.assertNotIn("access_token", state)
            handle = state["connx_session_handle"]
            self.assertEqual(len(state["analysis_principal"]), 64)
        self.assertEqual(
            load_connx_token(client.application.config["ANALYSIS_DB_PATH"], handle), "abc"
        )
        self.assertNotIn("abc", result.headers["Set-Cookie"])

        replacement = Mock(status_code=200)
        replacement.raise_for_status.return_value = None
        replacement.json.return_value = {"accessToken": "replacement-token"}
        with patch("connx_rest_app.requests.request", return_value=replacement):
            client.post(
                "/login", data={"username": "DOMAIN\\user", "password": "secret"}
            )
        with client.session_transaction() as state:
            replacement_handle = state["connx_session_handle"]
        self.assertNotEqual(handle, replacement_handle)
        self.assertIsNone(
            load_connx_token(client.application.config["ANALYSIS_DB_PATH"], handle)
        )
        self.assertEqual(
            load_connx_token(
                client.application.config["ANALYSIS_DB_PATH"], replacement_handle
            ),
            "replacement-token",
        )
        client.post("/logout")
        self.assertIsNone(
            load_connx_token(
                client.application.config["ANALYSIS_DB_PATH"], replacement_handle
            )
        )

    def test_server_side_token_expiration_and_cookie_security(self):
        app = self.make_app()
        now = datetime(2026, 8, 1, tzinfo=timezone.utc)
        handle = store_connx_token(
            app.config["ANALYSIS_DB_PATH"], "short-lived-token", ttl_seconds=60, now=now
        )
        self.assertEqual(
            load_connx_token(
                app.config["ANALYSIS_DB_PATH"], handle, now=now + timedelta(seconds=59)
            ),
            "short-lived-token",
        )
        self.assertIsNone(
            load_connx_token(
                app.config["ANALYSIS_DB_PATH"], handle, now=now + timedelta(seconds=60)
            )
        )

        app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax")
        response = app.test_client().get("/")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_production_configuration_fails_closed(self):
        handle, database_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(
            lambda: os.path.exists(database_path) and os.unlink(database_path)
        )
        valid = {
            "CONNX_ENVIRONMENT": "production",
            "FLASK_SECRET_KEY": "a-stable-production-signing-key",
            "FLASK_SECRET_KEY_FILE": "",
            "CONNX_BASE_URL": "https://connx-rest.test",
            "CONNX_VERIFY_TLS": "true",
            "CONNX_ALLOW_INSECURE_TLS": "false",
            "SESSION_COOKIE_SECURE": "true",
            "TRUSTED_HOSTS": '["dashboard.test"]',
            "ANALYSIS_DB_PATH": database_path,
        }
        with patch.dict(os.environ, valid):
            self.assertEqual(create_app().config["CONNX_ENVIRONMENT"], "production")

        unsafe_variants = (
            {"FLASK_SECRET_KEY": ""},
            {"CONNX_BASE_URL": "http://connx-rest.test"},
            {"CONNX_VERIFY_TLS": "false", "CONNX_ALLOW_INSECURE_TLS": "true"},
            {"SESSION_COOKIE_SECURE": "false"},
            {"TRUSTED_HOSTS": "[]"},
            {"ANALYSIS_DB_PATH": ""},
        )
        for unsafe in unsafe_variants:
            with self.subTest(unsafe=unsafe), patch.dict(os.environ, {**valid, **unsafe}):
                with self.assertRaisesRegex(ValueError, "Unsafe production configuration"):
                    create_app()

        with patch.dict(
            os.environ,
            {
                **valid,
                "CONNX_ENVIRONMENT": "development",
                "CONNX_VERIFY_TLS": "false",
                "CONNX_ALLOW_INSECURE_TLS": "true",
                "SESSION_COOKIE_SECURE": "false",
                "TRUSTED_HOSTS": "[]",
            },
        ):
            app = create_app()
        self.assertFalse(app.config["CONNX_VERIFY_TLS"])
        self.assertTrue(app.config["CONNX_ALLOW_INSECURE_TLS"])

    def test_login_rate_limit_is_atomic_and_expires(self):
        app = self.make_app()
        now = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)

        def attempt(_index):
            return consume_login_attempt(
                app.config["ANALYSIS_DB_PATH"],
                "principal",
                "source",
                principal_limit=3,
                source_limit=20,
                window_seconds=60,
                now=now,
            )["allowed"]

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(attempt, range(8)))
        self.assertEqual(results.count(True), 3)
        self.assertEqual(results.count(False), 5)

        expired = consume_login_attempt(
            app.config["ANALYSIS_DB_PATH"],
            "principal",
            "source",
            principal_limit=3,
            source_limit=20,
            window_seconds=60,
            now=now + timedelta(seconds=61),
        )
        self.assertTrue(expired["allowed"])

    def test_login_throttle_generic_errors_and_no_store_policy(self):
        app = self.make_app()
        app.config.update(
            LOGIN_ATTEMPTS_PER_PRINCIPAL=1,
            LOGIN_ATTEMPTS_PER_SOURCE=10,
            LOGIN_ATTEMPT_WINDOW_SECONDS=120,
        )
        client = app.test_client()
        failed = Mock(status_code=401)
        failed.raise_for_status.side_effect = requests.HTTPError(
            "credential rejected by https://private.internal.example"
        )
        with patch("connx_rest_app.requests.request", return_value=failed) as send:
            first = client.post(
                "/login",
                data={"username": "DOMAIN\\user", "password": "secret"},
                follow_redirects=True,
            )
            second = client.post(
                "/login", data={"username": "DOMAIN\\user", "password": "secret"}
            )

        self.assertEqual(send.call_count, 1)
        self.assertIn(b"Sign-in failed. Verify the credentials", first.data)
        self.assertNotIn(b"private.internal.example", first.data)
        self.assertEqual(first.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(first.headers["Pragma"], "no-cache")
        self.assertEqual(second.headers["Retry-After"], "120")

    def test_bootstrap_shell_is_local_responsive_and_csp_protected(self):
        client = self.make_app().test_client()
        page = client.get("/")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b'name="viewport"', page.data)
        self.assertIn(b'/static/favicon.svg', page.data)
        self.assertIn(b'name="theme-color"', page.data)
        self.assertIn(b"/static/vendor/bootstrap/bootstrap.min.css", page.data)
        self.assertIn(b"Advanced connection", page.data)
        self.assertIn(b"TLS verification is enforced by the server", page.data)
        self.assertRegex(page.data, rb'id="verify-tls"[^>]*disabled')
        self.assertIn(b"data-password-toggle", page.data)
        self.assertIn(b"data-validate", page.data)
        self.assertNotIn(b"<style", page.data)
        self.assertIn("default-src 'self'", page.headers["Content-Security-Policy"])

        bootstrap = client.get("/static/vendor/bootstrap/bootstrap.min.css")
        self.assertEqual(bootstrap.status_code, 200)
        self.assertGreater(len(bootstrap.data), 200_000)
        bootstrap.close()

        favicon = client.get("/static/favicon.svg")
        self.assertEqual(favicon.status_code, 200)
        self.assertEqual(favicon.mimetype, "image/svg+xml")
        self.assertIn(b"CONNX data synchronization", favicon.data)
        favicon.close()

    def test_connx_rest_origin_is_explicit_and_web_admin_route_is_absent(self):
        app = self.make_app()
        app.config["CONNX_BASE_URL"] = ""
        client = app.test_client()

        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"CONNX REST is not configured", page.data)
        self.assertIn(b"dedicated REST service origin", page.data)
        self.assertIn(b"disabled", page.data)

        with patch("connx_rest_app.requests.request") as send:
            login = client.post(
                "/login", data={"username": "DOMAIN\\user", "password": "secret"}
            )
        self.assertEqual(login.status_code, 302)
        send.assert_not_called()
        self.assertEqual(client.get("/swagger").status_code, 404)

        with patch.dict(os.environ, {"CONNX_BASE_URL": "ftp://invalid.example"}):
            with self.assertRaisesRegex(ValueError, "CONNX_BASE_URL"):
                create_app()

    def test_help_about_renders_only_safe_non_secret_configuration(self):
        responses = []
        for payload in (
            {"RunningThreads": []},
            {"JobList": [{"itemname": "orders", "success": "true"}]},
            {"JobList": [], "TotalNumberOfMatches": 0},
            {"TableList": []},
            {"GroupList": []},
            {"TransformList": []},
        ):
            item = Mock(status_code=200)
            item.raise_for_status.return_value = None
            item.json.return_value = payload
            responses.append(item)

        app = self.make_app()
        app.config.update(
            CONNX_APP_VERSION="2.4.0",
            CONNX_APP_BUILD="2026.08.01",
            CONNX_DOCUMENTATION_URL="https://docs.test/connx",
            CONNX_SUPPORT_URL="javascript:alert('unsafe')",
            CONNX_PRIVACY_URL="https://privacy.test/operations",
            AZURE_OPENAI_API_KEY="must-not-render",
            AZURE_OPENAI_DEPLOYMENT="operations-analysis",
        )
        client = app.test_client()
        self.authenticate(client, "browser-secret-token")
        with patch("connx_rest_app.requests.request", side_effect=responses):
            page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Help &amp; About", page.data)
        self.assertIn(b'id="helpAbout"', page.data)
        self.assertIn(b"2.4.0", page.data)
        self.assertIn(b"2026.08.01", page.data)
        self.assertIn(b"https://connx.test:9500", page.data)
        self.assertIn(b'href="https://docs.test/connx"', page.data)
        self.assertIn(b'target="_blank" rel="noopener noreferrer"', page.data)
        self.assertNotIn(b"javascript:alert", page.data)
        self.assertNotIn(b"must-not-render", page.data)
        self.assertNotIn(b"browser-secret-token", page.data)
        self.assertIn(b'id="analysis-scope-help"', page.data)
        self.assertIn(b'data-help-target="help-ai"', page.data)

        self.assertEqual(safe_http_url("https://support.test/help"), "https://support.test/help")
        self.assertEqual(safe_http_url("javascript:alert(1)"), "")
        self.assertEqual(safe_http_url("https://user:secret@support.test/help"), "")
        self.assertEqual(
            public_server_identity("https://user:password@server.test:9500/private"),
            "https://server.test:9500",
        )

    def test_generic_api_request_route_is_not_exposed(self):
        client = self.make_app().test_client()
        self.authenticate(client)
        with patch("connx_rest_app.requests.request") as send:
            get_result = client.get("/request")
            post_result = client.post(
                "/request",
                data={"method": "DELETE", "path": "/api/svr/syncs/1", "body": "{}"},
            )

        self.assertEqual(get_result.status_code, 404)
        self.assertEqual(post_result.status_code, 404)
        send.assert_not_called()

    def test_jobs_dashboard_requests_documented_status_endpoints(self):
        responses = []
        for payload in (
            {"ActiveSyncs": 1, "QueuedSyncs": 2, "CompletedSyncs": 3, "RecordsPerSecond": 4, "DataVolumeVelocity": 1.5, "RunningThreads": []},
            {"JobList": [{"itemname": "orders", "success": "true"}]},
            {"JobList": [], "TotalNumberOfMatches": 0},
            {"TableList": []},
            {"GroupList": []},
            {"TransformList": []},
        ):
            response = Mock(status_code=200)
            response.raise_for_status.return_value = None
            response.json.return_value = payload
            responses.append(response)

        client = self.make_app().test_client()
        self.authenticate(client)
        with patch("connx_rest_app.requests.request", side_effect=responses) as send:
            result = client.get("/jobs?status=success&period=1%20week&page=2")

        self.assertEqual(result.status_code, 200)
        self.assertIn(b"Data Sync Operations Console", result.data)
        self.assertIn(b'data-bs-target="#primaryNavigation"', result.data)
        self.assertIn(b'class="form-check-input job-select"', result.data)
        self.assertIn(b'data-bs-target="#recordDetails"', result.data)
        self.assertIn(b'data-bs-toggle="tooltip"', result.data)
        self.assertIn(b"data-timezone", result.data)
        self.assertIn(b"Previous", result.data)
        self.assertTrue(
            all(
                call.kwargs["headers"]["Authorization"] == "bearer abc"
                for call in send.call_args_list
            )
        )
        self.assertEqual(send.call_args_list[1].kwargs["params"], {"StatusSearchPattern": "success", "TimePeriod": "1 week", "PageNumber": 2, "PageSize": 100})
        self.assertEqual(send.call_args_list[3].kwargs["params"], {"StatusSearchPattern": "success", "Pagination": "false"})
        self.assertEqual([call.args[1] for call in send.call_args_list], [
            "https://connx.test:9500/api/status/runningjobs",
            "https://connx.test:9500/api/status/completedjobs",
            "https://connx.test:9500/api/status/completedjobs",
            "https://connx.test:9500/api/object/tableswithstatus",
            "https://connx.test:9500/api/object/groupswithstatus",
            "https://connx.test:9500/api/object/transformswithstatus",
        ])

    def test_history_export_returns_csv(self):
        response = Mock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.return_value = {"JobList": [{"success": "false", "itemname": "orders", "error": "Target unavailable"}]}
        client = self.make_app().test_client()
        self.authenticate(client)
        with patch("connx_rest_app.requests.request", return_value=response):
            result = client.get("/jobs/history.csv?status=failure")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/csv")
        self.assertIn(b"Target unavailable", result.data)

    def test_ai_analysis_uses_filtered_history(self):
        responses = []
        for payload in (
            {"RunningThreads": []},
            {"JobList": [{"itemname": "orders", "success": "false", "error": "Timeout"}]},
            {"JobList": [], "TotalNumberOfMatches": 0},
            {"TableList": []},
            {"GroupList": []},
            {"TransformList": []},
        ):
            response = Mock(status_code=200)
            response.raise_for_status.return_value = None
            response.json.return_value = payload
            responses.append(response)

        app = self.make_app()
        app.config.update(
            AZURE_OPENAI_ENDPOINT="https://example.openai.azure.com",
            AZURE_OPENAI_API_KEY="server-secret",
            AZURE_OPENAI_DEPLOYMENT="analysis-model",
        )
        client = app.test_client()
        self.authenticate(client)
        with (
            patch("connx_rest_app.requests.request", side_effect=responses),
            patch(
                "connx_rest_app.request_ai_analysis",
                return_value={
                    "structured": True,
                    "executive_summary": "Prioritize timeout remediation.",
                    "overall_severity": "high",
                    "confidence": "high",
                    "findings": [
                        {
                            "title": "Repeated timeout",
                            "severity": "high",
                            "confidence": "high",
                            "observation": "The orders sync timed out.",
                            "evidence": ["One failed orders job"],
                            "impact": "The destination is stale.",
                            "recommendations": ["Check destination connectivity."],
                        }
                    ],
                    "limitations": ["Only one record was analyzed."],
                },
            ) as analyze,
        ):
            result = client.post(
                "/jobs",
                data={
                    "action": "analyze",
                    "status": "failure",
                    "period": "1 week",
                    "item_type": "All",
                    "analysis_scope": "selected",
                    "selected_jobs": "0",
                },
            )

        self.assertEqual(result.status_code, 200)
        self.assertIn(b"Prioritize timeout remediation.", result.data)
        self.assertIn(b"Jobs analyzed", result.data)
        self.assertIn(b"Repeated timeout", result.data)
        self.assertIn(b"Severity: high", result.data)
        self.assertIn(b"Confidence: high", result.data)
        self.assertNotIn(b"server-secret", result.data)
        self.assertEqual(analyze.call_args.kwargs["deployment"], "analysis-model")
        self.assertEqual(analyze.call_args.kwargs["history"][0]["itemname"], "orders")

        with client.session_transaction() as state:
            analysis_id = state["last_ai_analysis_id"]
        selected = client.get(f"/jobs/analyses/{analysis_id}/select")
        self.assertEqual(selected.status_code, 302)
        self.assertIn("status=failure", selected.location)
        self.assertIn("period=1+week", selected.location)
        exported = client.get(f"/jobs/analysis/{analysis_id}.md")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.mimetype, "text/markdown")
        self.assertIn(b"# CONNX Data Sync AI analysis", exported.data)
        self.assertIn(b"**Severity:** high", exported.data)
        self.assertIn(b"Check destination connectivity.", exported.data)

        pdf = client.get(f"/jobs/analysis/{analysis_id}.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.mimetype, "application/pdf")
        self.assertTrue(pdf.data.startswith(b"%PDF-1.4"))

        updated = client.post(
            f"/jobs/analysis/{analysis_id}/findings/0",
            data={
                "status": "acknowledged",
                "owner": "Data operations",
                "notes": "Checking the destination listener.",
                "runbook_url": "https://runbooks.test/destination",
            },
        )
        self.assertEqual(updated.status_code, 302)
        record = load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id)
        self.assertEqual(record["filters"]["analysis_scope"], "selected")
        self.assertEqual(record["finding_workflow"][0]["status"], "acknowledged")
        self.assertEqual(record["finding_workflow"][0]["owner"], "Data operations")
        exported_with_workflow = client.get(f"/jobs/analysis/{analysis_id}.md")
        self.assertIn(b"https://runbooks.test/destination", exported_with_workflow.data)

        refresh_responses = []
        for payload in (
            {"RunningThreads": []},
            {"JobList": [{"itemname": "orders", "success": "false"}]},
            {"JobList": []},
            {"TableList": []},
            {"GroupList": []},
            {"TransformList": []},
        ):
            response = Mock(status_code=200)
            response.raise_for_status.return_value = None
            response.json.return_value = payload
            refresh_responses.append(response)
        with patch("connx_rest_app.requests.request", side_effect=refresh_responses):
            refreshed = client.get("/jobs")
        self.assertIn(b"Prioritize timeout remediation.", refreshed.data)
        self.assertIn(b"Export Markdown", refreshed.data)
        history_page = client.get("/jobs/analyses")
        self.assertEqual(history_page.status_code, 200)
        self.assertIn(b"AI analysis history", history_page.data)
        self.assertIn(b"Help &amp; About", history_page.data)
        self.assertIn(b"Prioritize timeout remediation.", history_page.data)

        deleted = client.post(f"/jobs/analyses/{analysis_id}/delete")
        self.assertEqual(deleted.status_code, 302)
        self.assertIsNone(load_analysis(app.config["ANALYSIS_DB_PATH"], analysis_id))

    def test_analysis_history_search_severity_and_pagination(self):
        app = self.make_app()
        analysis_ids = []
        for index in range(12):
            saved = save_analysis(
                app.config["ANALYSIS_DB_PATH"],
                deployment="history-model",
                filters={"period": "1 week"},
                stats={"total": index + 1, "successes": 0, "failures": index + 1, "affected_objects": 1},
                analysis={
                    "structured": True,
                    "executive_summary": f"Batch reliability finding {index}",
                    "overall_severity": "high",
                    "confidence": "high",
                    "findings": [],
                    "limitations": [],
                },
            )
            analysis_ids.append(saved["id"])

        client = app.test_client()
        self.authenticate(client)
        with client.session_transaction() as state:
            state["analysis_ids"] = analysis_ids
            state["dashboard_filters"] = {
                "search": "orders",
                "status": "failure",
                "item_type": "All",
                "period": "1 week",
                "page": "2",
            }
        page = client.get("/jobs/analyses?search=Batch&severity=high&page=2")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"12 matching analyses", page.data)
        self.assertIn(b"Page 2 of 2", page.data)
        self.assertIn(b'data-timestamp=', page.data)
        self.assertIn(b"status=failure", page.data)
        self.assertNotIn(b"Batch reliability finding 11", page.data)

        empty = client.get("/jobs/analyses?search=does-not-exist")
        self.assertIn(b"No matching analyses", empty.data)

    def test_ai_client_uses_azure_v1_endpoint_and_selected_fields(self):
        response = Mock(
            output_text=json.dumps(
                {
                    "executive_summary": "Recommendation",
                    "overall_severity": "low",
                    "confidence": "low",
                    "findings": [],
                    "limitations": ["Small sample"],
                }
            )
        )
        client = Mock()
        client.responses.create.return_value = response

        with patch("openai.OpenAI", return_value=client) as openai_client:
            result = request_ai_analysis(
                endpoint="https://example.openai.azure.com",
                api_key="secret",
                deployment="analysis-model",
                history=[{"itemname": "orders", "success": "false", "internal": "do-not-send"}],
            )

        self.assertTrue(result["structured"])
        self.assertEqual(result["executive_summary"], "Recommendation")
        openai_client.assert_called_once_with(
            api_key="secret", base_url="https://example.openai.azure.com/openai/v1/"
        )
        request_args = client.responses.create.call_args.kwargs
        self.assertEqual(request_args["model"], "analysis-model")
        self.assertIn('"itemname":"orders"', request_args["input"])
        self.assertNotIn("internal", request_args["input"])
        self.assertEqual(request_args["text"]["format"]["type"], "json_schema")
        self.assertTrue(request_args["text"]["format"]["strict"])

    def test_required_destination_preflight_blocks_analysis(self):
        responses = []
        for payload in (
            {"RunningThreads": []},
            {"JobList": [{"itemname": "orders", "success": "false"}]},
            {"JobList": [], "TotalNumberOfMatches": 0},
            {"TableList": []},
            {"GroupList": []},
            {"TransformList": []},
        ):
            response = Mock(status_code=200)
            response.raise_for_status.return_value = None
            response.json.return_value = payload
            responses.append(response)
        unavailable = Mock(status_code=503)
        unavailable.raise_for_status.side_effect = requests.HTTPError("503 unavailable")
        responses.append(unavailable)

        app = self.make_app()
        app.config.update(
            AZURE_OPENAI_ENDPOINT="https://example.openai.azure.com",
            AZURE_OPENAI_API_KEY="server-secret",
            AZURE_OPENAI_DEPLOYMENT="analysis-model",
            CONNX_HEALTH_PATH="/api/status/destination-health",
            CONNX_HEALTH_REQUIRED=True,
        )
        client = app.test_client()
        self.authenticate(client)
        with (
            patch("connx_rest_app.requests.request", side_effect=responses) as send,
            patch("connx_rest_app.request_ai_analysis") as analyze,
        ):
            result = client.post("/jobs", data={"action": "analyze"})

        self.assertEqual(result.status_code, 200)
        self.assertIn(b"Destination pre-flight failed", result.data)
        analyze.assert_not_called()
        self.assertEqual(
            send.call_args_list[-1].args[1],
            "https://connx.test:9500/api/status/destination-health",
        )

    def test_ai_plain_text_fallback_and_deterministic_stats(self):
        response = Mock(output_text="Plain text recommendation")
        client = Mock()
        client.responses.create.return_value = response
        history = [
            {"itemname": "orders", "success": "true"},
            {"itemname": "orders", "success": "false"},
            {"itemname": "customers", "success": False},
        ]

        with patch("openai.OpenAI", return_value=client):
            result = request_ai_analysis(
                endpoint="https://example.openai.azure.com",
                api_key="secret",
                deployment="analysis-model",
                history=history,
            )

        self.assertEqual(result, {"structured": False, "raw_text": "Plain text recommendation"})
        self.assertEqual(
            summarize_history(history),
            {"total": 3, "successes": 1, "failures": 2, "affected_objects": 2},
        )

    def test_ai_client_supports_entra_token_provider(self):
        response = Mock(output_text="plain response")
        client = Mock()
        client.responses.create.return_value = response
        token_provider = Mock()
        identity = types.ModuleType("azure.identity")
        identity.DefaultAzureCredential = Mock(return_value="credential")
        identity.get_bearer_token_provider = Mock(return_value=token_provider)
        azure = types.ModuleType("azure")
        azure.__path__ = []
        azure.identity = identity

        with (
            patch.dict(sys.modules, {"azure": azure, "azure.identity": identity}),
            patch("openai.OpenAI", return_value=client) as openai_client,
        ):
            result = request_ai_analysis(
                endpoint="https://example.openai.azure.com",
                deployment="analysis-model",
                history=[],
                auth_mode="entra",
            )

        self.assertEqual(result["raw_text"], "plain response")
        identity.get_bearer_token_provider.assert_called_once_with(
            "credential", "https://ai.azure.com/.default"
        )
        openai_client.assert_called_once_with(
            api_key=token_provider,
            base_url="https://example.openai.azure.com/openai/v1/",
        )

    def test_server_side_analysis_quota_is_atomic(self):
        app = self.make_app()
        now = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
        first = consume_analysis_quota(
            app.config["ANALYSIS_DB_PATH"],
            "session-one",
            hourly_limit=1,
            daily_limit=2,
            now=now,
        )
        second = consume_analysis_quota(
            app.config["ANALYSIS_DB_PATH"],
            "session-one",
            hourly_limit=1,
            daily_limit=2,
            now=now,
        )
        other_session = consume_analysis_quota(
            app.config["ANALYSIS_DB_PATH"],
            "session-two",
            hourly_limit=1,
            daily_limit=2,
            now=now,
        )

        self.assertTrue(first["allowed"])
        self.assertFalse(second["allowed"])
        self.assertEqual(second["reason"], "hourly")
        self.assertTrue(other_session["allowed"])

    def test_trends_baseline_and_csrf_protection(self):
        trends = history_trends(
            [
                {"starttime": "2026-07-28 01:00", "success": "false", "duration": "4 sec", "processedrows": 0},
                {"starttime": "2026-07-28 02:00", "success": "true", "duration": "2 sec", "processedrows": 20},
            ]
        )
        self.assertEqual(trends[0]["failure_rate"], 50)
        self.assertEqual(trends[0]["average_duration"], 3.0)
        self.assertEqual(trends[0]["processed_rows"], 20)

        app = self.make_app()
        filters = {"search": "", "status": "", "item_type": "All", "period": "1 week"}
        analysis = {"structured": False, "raw_text": "baseline"}
        first = save_analysis(
            app.config["ANALYSIS_DB_PATH"],
            deployment="model",
            filters=filters,
            stats={"total": 10, "successes": 8, "failures": 2, "affected_objects": 2},
            analysis=analysis,
        )
        baseline = load_analysis(app.config["ANALYSIS_DB_PATH"], first["id"])
        comparison = compare_analysis_stats(
            {"total": 10, "successes": 5, "failures": 5, "affected_objects": 3}, baseline
        )
        self.assertEqual(comparison["failure_rate_direction"], "up")
        self.assertEqual(comparison["failure_rate_delta"], 30.0)

        app.config["CSRF_ENABLED"] = True
        client = app.test_client()
        self.authenticate(client)
        self.assertEqual(client.post("/logout").status_code, 400)
        with client.session_transaction() as state:
            state["csrf_token"] = "valid-token"
        self.assertEqual(
            client.post("/logout", data={"csrf_token": "valid-token"}).status_code,
            302,
        )

    def test_background_job_and_mounted_secret_helpers(self):
        manager = AnalysisJobManager(max_workers=1)
        job_id = manager.submit(
            lambda value: {"value": value},
            metadata={"deployment": "model"},
            arguments={"value": 42},
        )
        outcome = manager.take(job_id)
        for _ in range(100):
            if outcome["status"] != "pending":
                break
            outcome = manager.take(job_id)
        self.assertEqual(outcome["status"], "complete")
        self.assertEqual(outcome["result"]["analysis"], {"value": 42})

        handle, secret_path = tempfile.mkstemp()
        os.write(handle, b"mounted-secret\n")
        os.close(handle)
        self.addCleanup(lambda: os.path.exists(secret_path) and os.unlink(secret_path))
        with patch.dict(os.environ, {"TEST_SECRET_FILE": secret_path, "TEST_SECRET": "env-secret"}):
            self.assertEqual(read_secret("TEST_SECRET"), "mounted-secret")

    def test_durable_background_jobs_are_secret_free_and_owner_scoped(self):
        app = self.make_app()
        manager = DurableAnalysisJobManager(max_workers=1, lease_seconds=3)
        started = threading.Event()
        release = threading.Event()

        def analyze(value, api_key):
            started.set()
            release.wait(timeout=5)
            return {"value": value, "authenticated": api_key == "runtime-secret"}

        job_id = manager.submit(
            analyze,
            database_path=app.config["ANALYSIS_DB_PATH"],
            principal="operator-one",
            metadata={"deployment": "model"},
            arguments={"value": 42},
            runtime_arguments={"api_key": "runtime-secret"},
        )
        self.assertTrue(started.wait(timeout=2))
        with closing(sqlite3.connect(app.config["ANALYSIS_DB_PATH"])) as connection:
            payload = connection.execute(
                "SELECT payload_json FROM ai_background_jobs WHERE id = ?", (job_id,)
            ).fetchone()[0]
        self.assertNotIn("runtime-secret", payload)
        self.assertEqual(
            manager.take(
                job_id,
                database_path=app.config["ANALYSIS_DB_PATH"],
                principal="operator-two",
                function=analyze,
                runtime_arguments={"api_key": "runtime-secret"},
            ),
            {"status": "missing"},
        )

        release.set()
        outcome = {"status": "pending"}
        for _ in range(200):
            outcome = manager.take(
                job_id,
                database_path=app.config["ANALYSIS_DB_PATH"],
                principal="operator-one",
                function=analyze,
                runtime_arguments={"api_key": "runtime-secret"},
            )
            if outcome["status"] != "pending":
                break
            time.sleep(0.01)
        self.assertEqual(outcome["status"], "complete")
        self.assertEqual(outcome["result"]["analysis"]["value"], 42)
        self.assertTrue(outcome["result"]["analysis"]["authenticated"])
        with closing(sqlite3.connect(app.config["ANALYSIS_DB_PATH"])) as connection:
            payload = connection.execute(
                "SELECT payload_json FROM ai_background_jobs WHERE id = ?", (job_id,)
            ).fetchone()[0]
        self.assertEqual(payload, "{}")

    def test_durable_background_job_recovers_an_expired_worker_lease(self):
        app = self.make_app()
        abandoned_manager = DurableAnalysisJobManager(max_workers=1, lease_seconds=60)
        started = threading.Event()
        release = threading.Event()

        def abandoned(value):
            started.set()
            release.wait(timeout=5)
            return {"source": "abandoned", "value": value}

        job_id = abandoned_manager.submit(
            abandoned,
            database_path=app.config["ANALYSIS_DB_PATH"],
            principal="operator",
            metadata={"deployment": "model"},
            arguments={"value": 7},
        )
        self.assertTrue(started.wait(timeout=2))
        with closing(sqlite3.connect(app.config["ANALYSIS_DB_PATH"])) as connection:
            with connection:
                connection.execute(
                    "UPDATE ai_background_jobs SET lease_until = ? WHERE id = ?",
                    ("2000-01-01T00:00:00+00:00", job_id),
                )

        recovery_manager = DurableAnalysisJobManager(max_workers=1, lease_seconds=3)
        outcome = recovery_manager.take(
            job_id,
            database_path=app.config["ANALYSIS_DB_PATH"],
            principal="operator",
            function=lambda value: {"source": "recovered", "value": value},
        )
        for _ in range(200):
            if outcome["status"] != "pending":
                break
            time.sleep(0.01)
            outcome = recovery_manager.take(
                job_id,
                database_path=app.config["ANALYSIS_DB_PATH"],
                principal="operator",
                function=lambda value: {"source": "recovered", "value": value},
            )
        release.set()
        self.assertEqual(outcome["status"], "complete")
        self.assertEqual(outcome["result"]["analysis"], {"source": "recovered", "value": 7})

    def test_durable_background_job_failure_and_retention(self):
        app = self.make_app()
        manager = DurableAnalysisJobManager(max_workers=1, retention_seconds=1)

        def fail_analysis():
            raise RuntimeError("model unavailable")

        job_id = manager.submit(
            fail_analysis,
            database_path=app.config["ANALYSIS_DB_PATH"],
            principal="operator",
            metadata={"deployment": "model"},
            arguments={},
        )
        outcome = {"status": "pending"}
        for _ in range(200):
            outcome = manager.take(
                job_id,
                database_path=app.config["ANALYSIS_DB_PATH"],
                principal="operator",
                function=fail_analysis,
            )
            if outcome["status"] != "pending":
                break
            time.sleep(0.01)
        self.assertEqual(outcome, {"status": "failed", "error": "model unavailable"})

        with closing(sqlite3.connect(app.config["ANALYSIS_DB_PATH"])) as connection:
            with connection:
                connection.execute(
                    "UPDATE ai_background_jobs SET updated_at = ? WHERE id = ?",
                    ("2000-01-01T00:00:00+00:00", job_id),
                )
        self.assertEqual(
            manager.take(
                job_id,
                database_path=app.config["ANALYSIS_DB_PATH"],
                principal="operator",
                function=fail_analysis,
            ),
            {"status": "missing"},
        )

    def test_production_http_boundary_and_health_check(self):
        with patch.dict(
            os.environ,
            {
                "TRUSTED_HOSTS": '["dashboard.test"]',
                "TRUST_PROXY_HEADERS": "true",
                "SESSION_COOKIE_SECURE": "true",
            },
        ):
            app = self.make_app()
        client = app.test_client()
        healthy = client.get(
            "/healthz",
            base_url="http://internal:8000",
            headers={
                "X-Forwarded-For": "192.0.2.10",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "dashboard.test",
            },
        )
        self.assertEqual(healthy.status_code, 200)
        self.assertEqual(healthy.json, {"status": "ok"})
        self.assertIn("max-age=", healthy.headers["Strict-Transport-Security"])

        untrusted = client.get("/healthz", base_url="https://untrusted.test")
        self.assertEqual(untrusted.status_code, 400)

        app.config["MAX_CONTENT_LENGTH"] = 32
        oversized = client.post(
            "/login",
            base_url="https://dashboard.test",
            data={"username": "x" * 100, "password": "secret"},
        )
        self.assertEqual(oversized.status_code, 413)

    def test_redaction_and_retention(self):
        redacted = redact_history(
            [
                {
                    "itemname": "CUSTOMERS_PRIVATE",
                    "success": "false",
                    "error_summary": "password=hunter2 host=internal.example",
                },
                {"itemname": "CUSTOMERS_PRIVATE", "success": "true"},
            ],
            redact_object_names=True,
            redaction_patterns=(r"password=\S+", r"internal\.example"),
        )
        self.assertEqual(redacted[0]["itemname"], "object_1")
        self.assertEqual(redacted[1]["itemname"], "object_1")
        self.assertNotIn("hunter2", redacted[0]["error_summary"])
        self.assertNotIn("internal.example", redacted[0]["error_summary"])

        app = self.make_app()
        saved = save_analysis(
            app.config["ANALYSIS_DB_PATH"],
            deployment="model",
            filters={"period": "1 week"},
            stats={"total": 1, "successes": 1, "failures": 0, "affected_objects": 1},
            analysis={"structured": False, "raw_text": "old"},
        )
        with closing(sqlite3.connect(app.config["ANALYSIS_DB_PATH"])) as connection:
            with connection:
                connection.execute(
                    "UPDATE ai_analyses SET created_at = ? WHERE id = ?",
                    ("2000-01-01T00:00:00+00:00", saved["id"]),
                )
        self.assertEqual(purge_expired_analyses(app.config["ANALYSIS_DB_PATH"], 30), 1)
        self.assertIsNone(load_analysis(app.config["ANALYSIS_DB_PATH"], saved["id"]))
