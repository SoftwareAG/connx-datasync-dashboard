"""Deterministic browser, accessibility, and visual checks for the Flask UI."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlparse
from unittest.mock import patch

import requests
from PIL import Image, ImageChops
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import WSGIRequestHandler, make_server

from connx_rest_app import create_app


ROOT = Path(__file__).resolve().parents[1]
AXE_PATH = ROOT / "tests" / "vendor" / "axe.min.js"
BASELINE_ROOT = ROOT / "tests" / "visual_baselines"
BASELINE_FLAVOR = os.environ.get(
    "VISUAL_BASELINE_FLAVOR", "linux" if sys.platform.startswith("linux") else "macos"
)
BASELINE_DIR = BASELINE_ROOT / BASELINE_FLAVOR
ACTUAL_DIR = ROOT / "tests" / "visual_actual"
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")

BREAKPOINTS = {
    "mobile": {"width": 390, "height": 844},
    "tablet": {"width": 768, "height": 1024},
    "desktop": {"width": 1440, "height": 900},
}

STRUCTURED_ANALYSIS = {
    "structured": True,
    "executive_summary": "Stabilize destination connectivity before the full-sync window.",
    "overall_severity": "high",
    "confidence": "high",
    "findings": [
        {
            "title": "Destination availability is interrupting full syncs",
            "severity": "high",
            "confidence": "high",
            "observation": "Several tables failed while opening the destination database.",
            "evidence": ["CUSTOMERS_DB2 and ORDERS_DB2 report the same connection failure."],
            "impact": "Dependent reporting data can remain stale.",
            "recommendations": ["Add a destination pre-flight check before table recreation."],
        }
    ],
    "limitations": ["The fixture contains a short operational window."],
}

FAILURE_JOB = {
    "success": "false",
    "itemname": "CUSTOMERS_DB2",
    "itemtype": "Table",
    "synctype": "Full",
    "starttime": "2026-07-28T05:20:50Z",
    "duration": 5,
    "processedrows": 0,
    "insertedrows": 0,
    "updatedrows": 0,
    "deletedrows": 0,
    "error": "Unable to open destination database.",
}
SUCCESS_JOB = {
    "success": "true",
    "itemname": "ORDERS_DB2",
    "itemtype": "Table",
    "synctype": "Full",
    "starttime": "2026-07-28T06:29:55Z",
    "duration": 2,
    "processedrows": 64000,
    "insertedrows": 64000,
    "updatedrows": 0,
    "deletedrows": 0,
    "error": "",
}


class QuietRequestHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        pass


def response(payload, status=200):
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = json.dumps(payload).encode("utf-8")
    return result


class ConnxBrowserUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tempdir.cleanup)
        cls.state = {"mode": "failures", "slow_ai": False}
        cls.release_ai = threading.Event()
        cls.request_patch = patch(
            "connx_rest_app.requests.request", side_effect=cls.fake_request
        )
        cls.ai_patch = patch(
            "connx_rest_app.request_ai_analysis", side_effect=cls.fake_ai_analysis
        )
        cls.request_patch.start()
        cls.addClassCleanup(cls.request_patch.stop)
        cls.ai_patch.start()
        cls.addClassCleanup(cls.ai_patch.stop)

        cls.app = create_app()
        cls.app.config.update(
            TESTING=True,
            SECRET_KEY="browser-test-secret",
            CONNX_BASE_URL="https://connx.fixture:9500",
            ANALYSIS_DB_PATH=str(Path(cls.tempdir.name) / "browser-tests.db"),
            AZURE_OPENAI_ENDPOINT="https://azure.fixture.openai.azure.com",
            AZURE_OPENAI_API_KEY="server-only-test-key",
            AZURE_OPENAI_DEPLOYMENT="operations-analysis",
            AI_HISTORY_LIMIT=100,
            AI_BACKGROUND_THRESHOLD=100,
            AI_REQUESTS_PER_HOUR=100,
            AI_REQUESTS_PER_DAY=100,
            CONNX_HEALTH_PATH="",
            CONNX_HEALTH_REQUIRED=False,
            AI_REDACT_OBJECT_NAMES=False,
            AI_REDACT_ERROR_TEXT=False,
            AI_REDACTION_PATTERNS=[],
            CONNX_APP_VERSION="2.4.0",
            CONNX_APP_BUILD="2026.08.01-test",
            CONNX_DOCUMENTATION_URL="https://docs.fixture.test/connx",
            CONNX_SUPPORT_URL="https://support.fixture.test/operations",
            CONNX_PRIVACY_URL="https://privacy.fixture.test/ai",
            CSRF_ENABLED=True,
        )
        cls.server = make_server(
            "127.0.0.1", 0, cls.app, threaded=True, request_handler=QuietRequestHandler
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.addClassCleanup(cls.server_thread.join, timeout=5)
        cls.addClassCleanup(cls.server.shutdown)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch(headless=True)
        cls.addClassCleanup(cls.browser.close)
        cls.addClassCleanup(cls.release_ai.set)

    def setUp(self):
        self.state.update(mode="failures", slow_ai=False)
        self.release_ai.set()
        self.release_ai.clear()
        database_name = self.id().rsplit(".", 1)[-1] + ".db"
        database_path = Path(self.tempdir.name) / database_name
        database_path.unlink(missing_ok=True)
        self.app.config.update(
            ANALYSIS_DB_PATH=str(database_path),
            AI_BACKGROUND_THRESHOLD=100,
            AI_REQUESTS_PER_HOUR=100,
            AI_REQUESTS_PER_DAY=100,
        )

    @classmethod
    def fake_request(cls, method, url, **kwargs):
        path = urlparse(url).path
        if path.endswith("/api/svr/security/login"):
            return response({"accessToken": "browser-access-token"})

        mode = cls.state["mode"]
        if mode == "partial" and path.endswith("/api/object/groupswithstatus"):
            return response({"error": "Fixture group endpoint unavailable"}, 503)
        if path.endswith("/api/ds/env"):
            return response(
                {
                    "isconnected": True,
                    "CDDName": "BrowserFixtureCDD",
                    "dataSyncAvailable": True,
                    "transformsAvailable": True,
                    "transformLicenseMessages": [],
                }
            )
        if path.endswith("/api/status/runningjobs"):
            return response(
                {
                    "ActiveSyncs": 0,
                    "QueuedSyncs": 0,
                    "CompletedSyncs": 2,
                    "RecordsPerSecond": 32000,
                    "DataVolumeVelocity": 4.8,
                    "RunningThreads": [],
                }
            )
        if path.endswith("/api/status/completedjobs"):
            rows = [] if mode == "empty" else [copy.deepcopy(SUCCESS_JOB)]
            if mode in {"failures", "partial"}:
                rows.insert(0, copy.deepcopy(FAILURE_JOB))
            params = kwargs.get("params") or {}
            status = str(params.get("StatusSearchPattern", "")).lower()
            search = str(params.get("SearchPattern", "")).casefold()
            if status == "failure":
                rows = [row for row in rows if row["success"] == "false"]
            elif status == "success":
                rows = [row for row in rows if row["success"] == "true"]
            if search:
                rows = [row for row in rows if search in row["itemname"].casefold()]
            return response({"JobList": rows, "TotalNumberOfMatches": len(rows)})
        if path.endswith("/api/object/tableswithstatus"):
            rows = [] if mode == "empty" else [
                {
                    "catalog": "DEMO",
                    "schema": "PUBLIC",
                    "table": "ORDERS_DB2",
                    "laststatus": "Success",
                    "lastsynctype": "Full",
                    "laststarttime": "2026-07-28T06:29:55Z",
                    "lastduration": 2,
                    "lastprocessedrows": 64000,
                    "error": "",
                }
            ]
            return response({"TableList": rows, "TotalNumberOfMatches": len(rows)})
        if path.endswith("/api/object/groupswithstatus"):
            return response({"GroupList": [], "TotalNumberOfMatches": 0})
        if path.endswith("/api/object/transformswithstatus"):
            return response({"TransformList": [], "TotalNumberOfMatches": 0})
        if path.endswith("/api/object/schedules"):
            return response(
                {
                    "ScheduleItems": [
                        {
                            "Name": "Nightly orders",
                            "ItemType": "Table",
                            "ItemName": "ORDERS_DB2",
                            "SyncType": "Incremental",
                            "DateFrequency": "Daily",
                            "TimeFrequency": "Once",
                            "Enabled": True,
                            "UseTriggerFile": True,
                            "BeforeSyncTask": "/private/scripts/before.cmd",
                        }
                    ],
                    "TotalNumberOfMatches": 1,
                }
            )
        if path.endswith("/api/object/allobjects"):
            return response(
                {
                    "ItemList": [
                        {"ItemType": "Table", "ItemName": "ORDERS_DB2"},
                        {"ItemType": "Group", "ItemName": "MONTHLY_LOAD"},
                        {"ItemType": "Transform", "ItemName": "ORDER_SUMMARY"},
                    ],
                    "TotalNumberOfMatches": 3,
                }
            )
        if path.endswith("/api/config/settings"):
            return response(
                {
                    "maxworkerthreads": 8,
                    "historydays": 30,
                    "batchsize": 5000,
                    "retryfailedsyncs": True,
                    "smtpserver": "smtp.fixture.internal",
                    "ondemandscriptdirectory": "/private/scripts",
                }
            )
        if path.endswith("/api/svr/env"):
            return response(
                {
                    "version": "14.8.0",
                    "currentTime": "2026-08-01T18:00:00Z",
                    "timezone": "UTC",
                    "serverHomeDirectory": "/private/connx",
                    "licenseServerName": "license.fixture.internal",
                }
            )
        return response({"status": "ok"})

    @classmethod
    def fake_ai_analysis(cls, **_kwargs):
        if cls.state["slow_ai"]:
            cls.release_ai.wait(timeout=10)
        return copy.deepcopy(STRUCTURED_ANALYSIS)

    def new_page(self, breakpoint="desktop", *, axe=False):
        context = self.browser.new_context(
            viewport=BREAKPOINTS[breakpoint], accept_downloads=True, locale="en-US"
        )
        if axe:
            context.add_init_script(path=AXE_PATH)
        page = context.new_page()
        page.set_default_timeout(10_000)
        self.addCleanup(context.close)
        return page

    def login(self, page, username):
        page.goto(self.base_url)
        page.get_by_label("Windows AD username").fill(username)
        page.get_by_label("Password", exact=True).fill("fixture-password")
        page.get_by_role("button", name="Sign in securely").click()
        expect(page.get_by_role("heading", name="Operations overview")).to_be_visible()

    def run_analysis(self, page):
        page.locator("#analysis-scope").select_option("failures")
        page.locator("#ai-analysis-form").get_by_role(
            "button", name="Analyze job history"
        ).click()
        expect(page.get_by_text(STRUCTURED_ANALYSIS["executive_summary"])).to_be_visible()

    def freeze_visual_time(self, page):
        page.evaluate(
            """
            () => {
              const updated = document.querySelector('[data-last-updated]');
              if (updated) updated.textContent = '9:30:00 AM';
              document.querySelectorAll('time[data-timestamp]').forEach((item) => {
                item.textContent = 'Jul 28, 2026, 6:30 AM';
              });
              document.querySelectorAll('[role="alert"]').forEach((item) => {
                item.textContent = item.textContent.replace(
                  /Reference [0-9a-f]{12}[.]/,
                  'Reference fixture-reference.'
                );
              });
            }
            """
        )

    def settle_visual_state(self, page):
        page.mouse.move(0, 0)
        page.evaluate(
            """
            async () => {
              if (document.activeElement instanceof HTMLElement) {
                document.activeElement.blur();
              }
              await document.fonts.ready;
              await new Promise((resolve) => requestAnimationFrame(() =>
                requestAnimationFrame(resolve)));
            }
            """
        )

    def assert_visual(self, page, name, locator=None):
        self.freeze_visual_time(page)
        self.settle_visual_state(page)
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        ACTUAL_DIR.mkdir(parents=True, exist_ok=True)
        baseline = BASELINE_DIR / f"{name}.png"
        actual = ACTUAL_DIR / f"{name}-actual.png"
        diff = ACTUAL_DIR / f"{name}-diff.png"
        target = locator or page
        target.screenshot(path=actual, animations="disabled", caret="hide")
        if os.environ.get("UPDATE_VISUAL_BASELINES") == "1" or not baseline.exists():
            if not baseline.exists() and os.environ.get("UPDATE_VISUAL_BASELINES") != "1":
                self.fail(
                    f"Missing visual baseline {baseline}. Run with UPDATE_VISUAL_BASELINES=1."
                )
            baseline.write_bytes(actual.read_bytes())
            return

        with Image.open(baseline).convert("RGB") as expected_image, Image.open(actual).convert(
            "RGB"
        ) as actual_image:
            self.assertEqual(expected_image.size, actual_image.size, name)
            difference = ImageChops.difference(expected_image, actual_image).convert("L")
            changed = difference.point(lambda value: 255 if value > 20 else 0).histogram()[255]
            ratio = changed / (expected_image.width * expected_image.height)
            if ratio > 0.01:
                ImageChops.difference(expected_image, actual_image).save(diff)
            else:
                diff.unlink(missing_ok=True)
                actual.unlink(missing_ok=True)
            self.assertLessEqual(
                ratio,
                0.01,
                f"Visual regression in {name}: {ratio:.2%} of pixels changed; "
                f"actual and diff saved under {ACTUAL_DIR}",
            )

    def test_responsive_end_to_end_workflows(self):
        for breakpoint in BREAKPOINTS:
            with self.subTest(breakpoint=breakpoint):
                page = self.new_page(breakpoint)
                self.login(page, f"DOMAIN\\{breakpoint}-operator")

                filters = page.locator(".filter-card").first
                filters.get_by_label("Search item").fill("CUSTOMERS")
                filters.get_by_label("Status").select_option("failure")
                filters.get_by_label("History period").select_option("1 week")
                filters.get_by_role("button", name="Apply").click()
                expect(page.get_by_text("Search: CUSTOMERS")).to_be_visible()

                with page.expect_download() as csv_download:
                    page.get_by_role("link", name="Export CSV").click()
                self.assertEqual(csv_download.value.suggested_filename, "connx-job-history.csv")

                self.run_analysis(page)
                page.get_by_label("Status", exact=True).last.select_option("acknowledged")
                page.get_by_label("Owner").fill("Data operations")
                page.get_by_role("button", name="Save follow-up").click()
                expect(page.get_by_text("Finding follow-up saved.")).to_be_visible()
                expect(page.get_by_text("Follow-up acknowledged")).to_be_visible()

                with page.expect_download() as markdown_download:
                    page.get_by_role("link", name="Export Markdown").click()
                self.assertRegex(markdown_download.value.suggested_filename, r"analysis-\d+\.md")
                with page.expect_download() as pdf_download:
                    page.get_by_role("link", name="Export PDF").click()
                self.assertRegex(pdf_download.value.suggested_filename, r"analysis-\d+\.pdf")

                page.get_by_role("group", name="Analysis actions").get_by_role(
                    "link", name="History", exact=True
                ).click()
                expect(page.get_by_role("heading", name="Analysis history")).to_be_visible()
                delete_trigger = page.get_by_role("button", name="Delete").first
                delete_trigger.click()
                modal = page.get_by_role("dialog")
                expect(modal.get_by_role("heading", name="Delete this analysis?")).to_be_visible()
                modal.get_by_role("button", name="Cancel").click()
                expect(modal).to_be_hidden()
                delete_trigger.click()
                modal.get_by_role("button", name="Delete analysis").click()
                expect(page.get_by_role("heading", name="No saved analyses yet")).to_be_visible()

    def test_accessibility_keyboard_focus_contrast_and_zoom(self):
        page = self.new_page("mobile", axe=True)
        page.goto(self.base_url)

        page.keyboard.press("Tab")
        self.assertEqual(page.locator(":focus").get_attribute("href"), "#main-content")
        page.keyboard.press("Enter")
        self.assertEqual(page.evaluate("document.activeElement.id"), "main-content")
        page.keyboard.press("Tab")
        self.assertEqual(page.evaluate("document.activeElement.id"), "username")

        page.get_by_label("Windows AD username").fill("DOMAIN\\accessibility-operator")
        page.get_by_label("Password", exact=True).fill("fixture-password")
        page.get_by_role("button", name="Sign in securely").press("Enter")
        expect(page.get_by_role("heading", name="Operations overview")).to_be_visible()

        snapshot = page.aria_snapshot()
        self.assertIn('navigation "Primary navigation"', snapshot)
        self.assertIn('main', snapshot)
        self.assertIn('heading "Operations overview" [level=1]', snapshot)
        self.assertIn('table "Completed Data Sync job history"', snapshot)

        violations = page.evaluate(
            """
            async () => {
              const result = await axe.run(document, {
                runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'] }
              });
              return result.violations.map((violation) => ({
                id: violation.id,
                impact: violation.impact,
                targets: violation.nodes.map((node) => node.target.join(' '))
              }));
            }
            """
        )
        self.assertEqual(violations, [], json.dumps(violations, indent=2))

        captions_missing = page.locator("table:not(:has(caption))").count()
        labels_missing = page.locator(
            "input:not([type=hidden]):not([aria-label]):not([aria-labelledby]):not(:has(+ label))"
        ).evaluate_all(
            "els => els.filter(el => !document.querySelector(`label[for='${el.id}']`)).length"
        )
        self.assertEqual(captions_missing, 0)
        self.assertEqual(labels_missing, 0)

        navigation_button = page.get_by_role("button", name="Open navigation")
        navigation_button.click()
        navigation = page.locator("#primaryNavigation")
        expect(navigation).to_be_visible()
        expect(navigation).to_be_focused()
        page.keyboard.press("Escape")
        expect(navigation).to_be_hidden()
        expect(navigation_button).to_be_focused()

        details_button = page.get_by_role("button", name="View details").first
        details_button.click()
        details = page.locator("#recordDetails")
        expect(details).to_be_visible()
        expect(details).to_be_focused()
        page.keyboard.press("Escape")
        expect(details).to_be_hidden()
        expect(details_button).to_be_focused()

        # A 640 CSS-pixel viewport is the reflow equivalent of a 1280px-wide
        # browser at 200% zoom, without relying on Chromium-only CSS zoom.
        page.set_viewport_size({"width": 640, "height": 450})
        self.assertLessEqual(
            page.evaluate("document.documentElement.scrollWidth"),
            page.evaluate("window.innerWidth") + 2,
        )
        expect(page.get_by_role("button", name="Open navigation")).to_be_visible()

        self.run_analysis(page)
        page.get_by_role("group", name="Analysis actions").get_by_role(
            "link", name="History", exact=True
        ).click()
        delete_trigger = page.get_by_role("button", name="Delete").first
        delete_trigger.click()
        modal = page.get_by_role("dialog")
        expect(modal).to_be_visible()
        expect(modal).to_be_focused()
        page.keyboard.press("Escape")
        expect(modal).to_be_hidden()
        expect(delete_trigger).to_be_focused()

    def test_help_about_responsive_content_links_and_focus(self):
        for breakpoint in BREAKPOINTS:
            with self.subTest(breakpoint=breakpoint):
                page = self.new_page(breakpoint, axe=True)
                self.login(page, f"DOMAIN\\help-{breakpoint}")
                page.get_by_role("button", name="Dismiss").click()
                page.get_by_label("Search item").fill("UNAPPLIED FILTER")

                navigation_button = page.get_by_role("button", name="Open navigation")
                if breakpoint != "desktop":
                    navigation_button.click()
                    expect(page.locator("#primaryNavigation")).to_be_visible()
                help_trigger = page.get_by_role("button", name="Help & About")
                help_trigger.click()

                panel = page.locator("#helpAbout")
                expect(panel).to_be_visible()
                expect(panel.get_by_role("heading", name="Help & About")).to_be_visible()
                expect(panel.get_by_role("heading", name="Quick start")).to_be_visible()
                expect(panel.get_by_text("Operator review is required.")).to_be_attached()
                expect(panel.get_by_text("2.4.0")).to_be_attached()
                expect(page.get_by_label("Search item")).to_have_value("UNAPPLIED FILTER")
                self.assertNotIn("server-only-test-key", page.content())
                self.assertNotIn("browser-access-token", page.content())

                panel.get_by_role("button", name="About this application").click()
                expect(panel.get_by_text("2026.08.01-test")).to_be_visible()
                documentation = panel.get_by_role("link", name="Documentation (opens in a new tab)")
                self.assertEqual(documentation.get_attribute("target"), "_blank")
                self.assertEqual(documentation.get_attribute("rel"), "noopener noreferrer")
                self.assertEqual(
                    documentation.get_attribute("href"),
                    "https://docs.fixture.test/connx",
                )

                violations = page.evaluate(
                    """
                    async () => {
                      const result = await axe.run(document, {
                        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'] }
                      });
                      return result.violations.map((violation) => ({
                        id: violation.id,
                        targets: violation.nodes.map((node) => node.target.join(' '))
                      }));
                    }
                    """
                )
                self.assertEqual(violations, [], json.dumps(violations, indent=2))

                page.keyboard.press("Escape")
                expect(panel).to_be_hidden()
                expected_focus = navigation_button if breakpoint != "desktop" else help_trigger
                expect(expected_focus).to_be_focused()
                expect(page.get_by_label("Search item")).to_have_value("UNAPPLIED FILTER")

        page = self.new_page("desktop")
        self.login(page, "DOMAIN\\help-context")
        context_trigger = page.get_by_role("button", name="Open AI analysis help")
        context_trigger.click()
        expect(page.locator("#helpAbout")).to_be_visible()
        expect(page.locator("#helpAi")).to_be_visible()
        expect(page.locator("#help-ai")).to_be_focused()

    def test_visual_regression_states(self):
        page = self.new_page("desktop")
        self.state["mode"] = "healthy"
        self.login(page, "DOMAIN\\visual-healthy")
        self.assert_visual(page, "dashboard-healthy")

        self.state["mode"] = "failures"
        page.reload()
        self.assert_visual(page, "dashboard-failures")

        self.state["mode"] = "empty"
        page.reload()
        self.assert_visual(page, "dashboard-empty")

        self.state["mode"] = "partial"
        page.reload()
        groups_card = page.get_by_role(
            "heading", name="Groups — last sync"
        ).locator("xpath=ancestor::article[1]")
        expect(groups_card.get_by_role("alert")).to_contain_text(
            "Data is temporarily unavailable."
        )
        self.assert_visual(page, "dashboard-partial-outage", groups_card)

        self.state["mode"] = "failures"
        page.reload()
        self.run_analysis(page)
        self.assert_visual(page, "dashboard-structured-ai", page.locator("#ai"))

        quota_page = self.new_page("desktop")
        self.login(quota_page, "DOMAIN\\visual-quota")
        self.app.config["AI_REQUESTS_PER_HOUR"] = 1
        self.app.config["AI_REQUESTS_PER_DAY"] = 1
        self.run_analysis(quota_page)
        quota_page.locator("#ai-analysis-form").get_by_role(
            "button", name="Analyze job history"
        ).click()
        expect(quota_page.get_by_text("quota has been reached")).to_be_visible()
        self.assert_visual(quota_page, "dashboard-quota", quota_page.locator("#ai"))

        loading_page = self.new_page("desktop")
        self.login(loading_page, "DOMAIN\\visual-loading")
        self.app.config.update(
            AI_BACKGROUND_THRESHOLD=1,
            AI_REQUESTS_PER_HOUR=100,
            AI_REQUESTS_PER_DAY=100,
        )
        self.state["slow_ai"] = True
        loading_page.locator("#ai-analysis-form").get_by_role(
            "button", name="Analyze job history"
        ).click()
        expect(loading_page.get_by_text("A large-history analysis is running")).to_be_visible()
        self.assert_visual(loading_page, "dashboard-ai-loading", loading_page.locator("#ai"))
        self.release_ai.set()

        mobile_page = self.new_page("mobile")
        self.login(mobile_page, "DOMAIN\\visual-mobile")
        mobile_page.get_by_role("button", name="Open navigation").click()
        expect(mobile_page.locator("#primaryNavigation")).to_be_visible()
        self.assert_visual(mobile_page, "mobile-navigation")

        help_page = self.new_page("desktop")
        self.login(help_page, "DOMAIN\\visual-help")
        help_page.get_by_role("button", name="Help & About").click()
        expect(help_page.locator("#helpAbout")).to_be_visible()
        self.assert_visual(help_page, "help-about")


if __name__ == "__main__":
    unittest.main()
