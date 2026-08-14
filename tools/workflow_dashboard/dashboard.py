from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import webbrowser
from collections.abc import Callable
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


WORKSPACE_DEFAULT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_DEFAULT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DEFAULT))

from tools.workflow_dashboard.snapshot import (  # noqa: E402
    HostHealthSampler,
    read_target_lifecycle_snapshot,
    read_workflow_snapshot,
)


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'none'"
)
STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
}
SUBMISSION_ROUTE = "/api/mark-submitted"
SUBMISSION_HEADER = "confirm-submitted"
DIMINISHING_RETURNS_ROUTE = "/api/ack-diminishing-returns"
DIMINISHING_RETURNS_HEADER = "confirm-diminishing-returns"
PACKAGE_OUTCOME_ROUTE = "/api/ack-package-outcome"
PACKAGE_OUTCOME_HEADER = "confirm-package-outcome"
WEEKLY_PATCH_WATCH_ROUTE = "/api/ack-weekly-patch-watch"
WEEKLY_PATCH_WATCH_HEADER = "confirm-weekly-patch-watch"
REPORT_ISSUES_ROUTE = "/api/ack-report-issues"
REPORT_ISSUES_HEADER = "confirm-report-issues-acknowledgement"
REPORT_ISSUE_GREENLIGHT_ROUTE = "/api/greenlight-report-issue"
REPORT_ISSUE_GREENLIGHT_HEADER = "confirm-report-issue-greenlight"
HUNT_PROFILE_ROUTE = "/api/hunt-profile"
HUNT_PROFILE_HEADER = "confirm-hunt-profile"
HUNT_PROFILE_PRESETS = {"A_TIER_ONLY", "BALANCED", "INCLUDE_B_TIER"}
COORDINATION_REPLY_ROUTE = "/api/coordination/reply"
COORDINATION_REPLY_HEADER = "confirm-coordination-reply"
COORDINATION_DECISION_ROUTE = "/api/coordination/decide"
COORDINATION_DECISION_HEADER = "confirm-coordination-decision"
COORDINATION_DISMISS_ROUTE = "/api/coordination/dismiss"
COORDINATION_DISMISS_HEADER = "dismiss-coordination-message"
COORDINATION_CHAT_ROUTE = "/api/coordination/chat/send"
COORDINATION_CHAT_HEADER = "send-coordination-chat"
COORDINATION_DECISIONS = {"APPROVED", "DECLINED"}
MAX_REQUEST_BODY = 1024
MAX_COORDINATION_REQUEST_BODY = 4096
MAX_COORDINATION_TEXT = 2000


def acknowledge_report_issues(
    workspace: Path,
    issues: list[dict[str, str]],
) -> dict[str, object]:
    from tools.review_mailbox.report_issues import acknowledge_issues

    return acknowledge_issues(
        workspace=workspace,
        issue_snapshots=issues,
        actor="operator",
    )


def greenlight_report_issue(workspace: Path, issue_key: str) -> dict[str, object]:
    from tools.review_mailbox.report_issues import greenlight_issue

    return greenlight_issue(
        workspace=workspace,
        issue_key=issue_key,
        actor="operator",
    )


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def validate_bind(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("bind must be one exact IP address") from error
    if address.version != 4:
        raise ValueError("version one requires an IPv4 bind address")
    return str(address)


def validate_port(value: int) -> int:
    value = int(value)
    if not 0 <= value <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return value


def validate_remote_access(bind: str, allow_remote: bool) -> str:
    address = validate_bind(bind)
    if not ipaddress.ip_address(address).is_loopback and not allow_remote:
        raise ValueError(
            "non-loopback dashboard binding requires explicit --allow-remote"
        )
    return address


def acknowledge_diminishing_returns(
    workspace: Path,
    slug: str,
    marker_sha256: str,
) -> dict[str, object]:
    workspace = Path(workspace).resolve()
    active_target, marker = read_target_lifecycle_snapshot(workspace)
    if (
        active_target.get("status") != "active"
        or active_target.get("slug") != slug
    ):
        raise ValueError("active target does not match acknowledgement")
    if marker is None or str(marker.get("marker_sha256", "")) != marker_sha256:
        raise ValueError("diminishing-return marker changed")

    from tools.target_lifecycle import target_lifecycle

    database = workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
    event = target_lifecycle.add_event(
        database,
        slug,
        "DIMINISHING_RETURNS_ACKNOWLEDGED",
        "Operator acknowledged current diminishing-return marker",
        {"marker_sha256": marker_sha256},
    )
    return {
        "slug": slug,
        "marker_sha256": marker_sha256,
        "event_type": event["event_type"],
    }


def make_handler(
    static_dir: Path,
    snapshot_provider: Callable[[], dict[str, object]],
    submission_handler: Callable[[int], dict[str, object]] | None = None,
    diminishing_returns_handler: Callable[[str, str], dict[str, object]] | None = None,
    package_outcome_handler: Callable[[int], dict[str, object]] | None = None,
    hunt_profile_handler: Callable[[str], dict[str, object]] | None = None,
    coordination_reply_handler: Callable[[int, int, str], dict[str, object]]
    | None = None,
    coordination_decision_handler: Callable[[int, int, str, str], dict[str, object]]
    | None = None,
    coordination_dismiss_handler: Callable[[int, int], dict[str, object]] | None = None,
    coordination_chat_handler: Callable[[str], dict[str, object]] | None = None,
    weekly_patch_watch_handler: Callable[[str, str], dict[str, object]] | None = None,
    report_issues_handler: Callable[[list[dict[str, str]]], dict[str, object]]
    | None = None,
    report_issue_greenlight_handler: Callable[[str], dict[str, object]] | None = None,
) -> type[BaseHTTPRequestHandler]:
    static_dir = Path(static_dir).resolve()

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "JENNYDashboard/1"
        sys_version = ""

        def log_message(self, format: str, *args: object) -> None:
            return

        def _common_headers(self, content_type: str, length: int) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str = "application/json; charset=utf-8",
            *,
            allow: str = "",
        ) -> None:
            self.send_response(status)
            if allow:
                self.send_header("Allow", allow)
            self._common_headers(content_type, len(body))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, value: object) -> None:
            body = (
                json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n"
            ).encode("utf-8")
            self._send(status, body)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/api/status":
                try:
                    snapshot = snapshot_provider()
                except Exception:
                    self._send_json(503, {"error": "status unavailable"})
                    return
                self._send_json(200, snapshot)
                return
            if path == "/healthz":
                self._send_json(200, {"ok": True})
                return
            route = STATIC_ROUTES.get(path)
            if route is None:
                self._send_json(404, {"error": "not found"})
                return
            filename, content_type = route
            try:
                body = (static_dir / filename).read_bytes()
            except OSError:
                self._send_json(404, {"error": "not found"})
                return
            self._send(200, body, content_type)

        def _read_submission_request(self) -> int | None:
            if self.headers.get("X-JENNY-Operator") != SUBMISSION_HEADER:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if not isinstance(value, dict) or set(value) != {"item_id", "confirmed"}:
                self._send_json(400, {"error": "invalid request"})
                return None
            item_id = value.get("item_id")
            if (
                isinstance(item_id, bool)
                or not isinstance(item_id, int)
                or item_id < 1
                or value.get("confirmed") is not True
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return item_id

        def _read_coordination_json(
            self,
            expected_header: str,
            expected_keys: set[str],
        ) -> dict[str, object] | None:
            if self.headers.get("X-JENNY-Operator") != expected_header:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_COORDINATION_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if not isinstance(value, dict) or set(value) != expected_keys:
                self._send_json(400, {"error": "invalid request"})
                return None
            return value

        @staticmethod
        def _coordination_id(value: object) -> int | None:
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                return None
            return value

        @staticmethod
        def _coordination_text(value: object, *, required: bool) -> str | None:
            if not isinstance(value, str):
                return None
            text = value.strip()
            if required and not text:
                return None
            if len(text) > MAX_COORDINATION_TEXT:
                return None
            if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
                return None
            return text

        def _read_coordination_reply_request(
            self,
        ) -> tuple[int, int, str] | None:
            value = self._read_coordination_json(
                COORDINATION_REPLY_HEADER,
                {"message_id", "expected_revision", "text"},
            )
            if value is None:
                return None
            message_id = self._coordination_id(value.get("message_id"))
            revision = self._coordination_id(value.get("expected_revision"))
            text = self._coordination_text(value.get("text"), required=True)
            if message_id is None or revision is None or text is None:
                self._send_json(400, {"error": "invalid request"})
                return None
            return message_id, revision, text

        def _read_coordination_chat_request(self) -> str | None:
            value = self._read_coordination_json(
                COORDINATION_CHAT_HEADER,
                {"body"},
            )
            if value is None:
                return None
            body = self._coordination_text(value.get("body"), required=True)
            if body is None:
                self._send_json(400, {"error": "invalid request"})
                return None
            return body

        def _read_coordination_decision_request(
            self,
        ) -> tuple[int, int, str, str] | None:
            value = self._read_coordination_json(
                COORDINATION_DECISION_HEADER,
                {
                    "message_id",
                    "expected_revision",
                    "decision",
                    "reason",
                    "confirmed",
                },
            )
            if value is None:
                return None
            message_id = self._coordination_id(value.get("message_id"))
            revision = self._coordination_id(value.get("expected_revision"))
            decision = value.get("decision")
            reason = self._coordination_text(value.get("reason"), required=False)
            if (
                message_id is None
                or revision is None
                or not isinstance(decision, str)
                or decision not in COORDINATION_DECISIONS
                or reason is None
                or value.get("confirmed") is not True
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return message_id, revision, str(decision), reason

        def _read_coordination_dismiss_request(self) -> tuple[int, int] | None:
            value = self._read_coordination_json(
                COORDINATION_DISMISS_HEADER,
                {"message_id", "expected_revision"},
            )
            if value is None:
                return None
            message_id = self._coordination_id(value.get("message_id"))
            revision = self._coordination_id(value.get("expected_revision"))
            if message_id is None or revision is None:
                self._send_json(400, {"error": "invalid request"})
                return None
            return message_id, revision

        def _read_diminishing_returns_request(self) -> tuple[str, str] | None:
            if self.headers.get("X-JENNY-Operator") != DIMINISHING_RETURNS_HEADER:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if not isinstance(value, dict) or set(value) != {
                "slug",
                "marker_sha256",
                "confirmed",
            }:
                self._send_json(400, {"error": "invalid request"})
                return None
            slug = value.get("slug")
            digest = value.get("marker_sha256")
            if (
                not isinstance(slug, str)
                or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", slug) is None
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or value.get("confirmed") is not True
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return slug, digest

        def _read_package_outcome_request(self) -> int | None:
            if self.headers.get("X-JENNY-Operator") != PACKAGE_OUTCOME_HEADER:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if (
                not isinstance(value, dict)
                or set(value) != {"notification_id", "confirmed"}
            ):
                self._send_json(400, {"error": "invalid request"})
                return None
            notification_id = value.get("notification_id")
            if (
                isinstance(notification_id, bool)
                or not isinstance(notification_id, int)
                or notification_id < 1
                or value.get("confirmed") is not True
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return notification_id

        def _read_weekly_patch_watch_request(self) -> tuple[str, str] | None:
            if self.headers.get("X-JENNY-Operator") != WEEKLY_PATCH_WATCH_HEADER:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if not isinstance(value, dict) or set(value) != {
                "monday_date",
                "manifest_digest",
                "confirmed",
            }:
                self._send_json(400, {"error": "invalid request"})
                return None
            monday_date = value.get("monday_date")
            digest = value.get("manifest_digest")
            try:
                parsed_date = date.fromisoformat(monday_date)
            except (TypeError, ValueError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if (
                str(parsed_date) != monday_date
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or value.get("confirmed") is not True
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return monday_date, digest

        def _read_report_issues_request(self) -> list[dict[str, str]] | None:
            if self.headers.get("X-JENNY-Operator") != REPORT_ISSUES_HEADER:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_COORDINATION_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if (
                not isinstance(value, dict)
                or set(value) != {"confirmed", "issues"}
                or value.get("confirmed") is not True
                or not isinstance(value.get("issues"), list)
                or not 1 <= len(value["issues"]) <= 100
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            issues: list[dict[str, str]] = []
            for item in value["issues"]:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"issue_key", "updated_at"}
                    or not isinstance(item.get("issue_key"), str)
                    or not item["issue_key"].strip()
                    or len(item["issue_key"]) > 200
                    or not isinstance(item.get("updated_at"), str)
                    or not item["updated_at"].strip()
                    or len(item["updated_at"]) > 64
                ):
                    self._send_json(400, {"error": "invalid request"})
                    return None
                issues.append(
                    {
                        "issue_key": item["issue_key"].strip(),
                        "updated_at": item["updated_at"].strip(),
                    }
                )
            return issues

        def _read_report_issue_greenlight_request(self) -> str | None:
            if (
                self.headers.get("X-JENNY-Operator")
                != REPORT_ISSUE_GREENLIGHT_HEADER
            ):
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            issue_key = value.get("issue_key") if isinstance(value, dict) else None
            if (
                not isinstance(value, dict)
                or set(value) != {"confirmed", "issue_key"}
                or value.get("confirmed") is not True
                or not isinstance(issue_key, str)
                or not issue_key.strip()
                or len(issue_key) > 200
                or any(ord(character) < 32 for character in issue_key)
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return issue_key.strip()

        def _read_hunt_profile_request(self) -> str | None:
            if self.headers.get("X-JENNY-Operator") != HUNT_PROFILE_HEADER:
                self._send_json(403, {"error": "operator confirmation required"})
                return None
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                self._send_json(415, {"error": "application/json required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length < 1:
                self._send_json(400, {"error": "invalid request"})
                return None
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request too large"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
                return None
            if not isinstance(value, dict) or set(value) != {"preset", "confirmed"}:
                self._send_json(400, {"error": "invalid request"})
                return None
            preset = value.get("preset")
            if (
                not isinstance(preset, str)
                or preset not in HUNT_PROFILE_PRESETS
                or value.get("confirmed") is not True
            ):
                self._send_json(400, {"error": "explicit confirmation required"})
                return None
            return str(preset)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            if path == COORDINATION_CHAT_ROUTE:
                body = self._read_coordination_chat_request()
                if body is None:
                    return
                if coordination_chat_handler is None:
                    self._send_json(503, {"error": "coordination unavailable"})
                    return
                try:
                    result = coordination_chat_handler(body)
                    result_id = int(result["id"])
                    sender = str(result["sender"])
                    recipient = str(result["recipient"])
                    status = str(result["status"])
                    if (
                        result_id < 1
                        or sender != "operator"
                        or recipient != "midlane"
                        or status != "OPEN"
                    ):
                        raise ValueError("unexpected coordination chat result")
                except Exception:
                    self._send_json(409, {"error": "coordination chat failed"})
                    return
                self._send_json(
                    200,
                    {"ok": True, "message_id": result_id, "status": status},
                )
                return
            if path == COORDINATION_REPLY_ROUTE:
                request = self._read_coordination_reply_request()
                if request is None:
                    return
                if coordination_reply_handler is None:
                    self._send_json(503, {"error": "coordination unavailable"})
                    return
                message_id, revision, text = request
                try:
                    result = coordination_reply_handler(message_id, revision, text)
                    result_id = int(result["id"])
                    result_revision = int(result["revision"])
                    status = str(result["status"])
                    if (
                        result_id != message_id
                        or result_revision != revision + 1
                        or status != "OPEN"
                    ):
                        raise ValueError("unexpected coordination result")
                except Exception:
                    self._send_json(409, {"error": "coordination reply failed"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "message_id": message_id,
                        "revision": result_revision,
                        "status": status,
                    },
                )
                return
            if path == COORDINATION_DECISION_ROUTE:
                request = self._read_coordination_decision_request()
                if request is None:
                    return
                if coordination_decision_handler is None:
                    self._send_json(503, {"error": "coordination unavailable"})
                    return
                message_id, revision, decision, reason = request
                try:
                    result = coordination_decision_handler(
                        message_id, revision, decision, reason
                    )
                    result_id = int(result["id"])
                    result_revision = int(result["revision"])
                    status = str(result["status"])
                    if (
                        result_id != message_id
                        or result_revision != revision + 1
                        or status != decision
                    ):
                        raise ValueError("unexpected coordination result")
                except Exception:
                    self._send_json(409, {"error": "coordination decision failed"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "message_id": message_id,
                        "revision": result_revision,
                        "status": status,
                    },
                )
                return
            if path == COORDINATION_DISMISS_ROUTE:
                request = self._read_coordination_dismiss_request()
                if request is None:
                    return
                if coordination_dismiss_handler is None:
                    self._send_json(503, {"error": "coordination unavailable"})
                    return
                message_id, revision = request
                try:
                    result = coordination_dismiss_handler(message_id, revision)
                    if (
                        int(result["id"]) != message_id
                        or int(result["revision"]) != revision + 1
                        or not result.get("operator_dismissed_at")
                    ):
                        raise ValueError("unexpected coordination result")
                except Exception:
                    self._send_json(409, {"error": "coordination dismissal failed"})
                    return
                self._send_json(200, {"ok": True, "message_id": message_id})
                return
            if path == WEEKLY_PATCH_WATCH_ROUTE:
                request = self._read_weekly_patch_watch_request()
                if request is None:
                    return
                if weekly_patch_watch_handler is None:
                    self._send_json(503, {"error": "acknowledgement unavailable"})
                    return
                monday_date, digest = request
                try:
                    result = weekly_patch_watch_handler(monday_date, digest)
                    acknowledged_at = str(result["acknowledged_at"])
                    if (
                        str(result["state"]) != "ACKNOWLEDGED"
                        or str(result["monday_date"]) != monday_date
                        or str(result["manifest_digest"]) != digest
                        or not acknowledged_at
                    ):
                        raise ValueError("acknowledgement returned unexpected state")
                except Exception:
                    self._send_json(409, {"error": "acknowledgement failed"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "state": "ACKNOWLEDGED",
                        "monday_date": monday_date,
                        "manifest_digest": digest,
                        "acknowledged_at": acknowledged_at,
                    },
                )
                return
            if path == REPORT_ISSUES_ROUTE:
                issues = self._read_report_issues_request()
                if issues is None:
                    return
                if report_issues_handler is None:
                    self._send_json(503, {"error": "acknowledgement unavailable"})
                    return
                try:
                    result = report_issues_handler(issues)
                    acknowledged = int(result["acknowledged"])
                    requested = int(result.get("requested", len(issues)))
                    if requested != len(issues) or acknowledged != requested:
                        raise ValueError("acknowledgement returned unexpected state")
                except Exception:
                    self._send_json(409, {"error": "acknowledgement failed"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "state": "ACKNOWLEDGED",
                        "acknowledged": acknowledged,
                    },
                )
                return
            if path == REPORT_ISSUE_GREENLIGHT_ROUTE:
                issue_key = self._read_report_issue_greenlight_request()
                if issue_key is None:
                    return
                if report_issue_greenlight_handler is None:
                    self._send_json(503, {"error": "greenlight unavailable"})
                    return
                try:
                    result = report_issue_greenlight_handler(issue_key)
                    if (
                        str(result["issue_key"]) != issue_key
                        or str(result["status"]) != "CLOSED"
                    ):
                        raise ValueError("greenlight returned unexpected state")
                except Exception:
                    self._send_json(409, {"error": "greenlight failed"})
                    return
                self._send_json(
                    200,
                    {"ok": True, "issue_key": issue_key, "status": "CLOSED"},
                )
                return
            if path == HUNT_PROFILE_ROUTE:
                preset = self._read_hunt_profile_request()
                if preset is None:
                    return
                if hunt_profile_handler is None:
                    self._send_json(503, {"error": "hunt profile unavailable"})
                    return
                try:
                    result = hunt_profile_handler(preset)
                    active = result["active"]
                    pending = result.get("pending")
                    if not isinstance(active, dict) or (
                        pending is not None and not isinstance(pending, dict)
                    ):
                        raise ValueError("hunt profile returned unexpected state")
                except Exception:
                    self._send_json(409, {"error": "hunt profile change failed"})
                    return
                self._send_json(
                    200,
                    {"ok": True, "active": active, "pending": pending},
                )
                return
            if path == PACKAGE_OUTCOME_ROUTE:
                notification_id = self._read_package_outcome_request()
                if notification_id is None:
                    return
                if package_outcome_handler is None:
                    self._send_json(503, {"error": "acknowledgement unavailable"})
                    return
                try:
                    result = package_outcome_handler(notification_id)
                    if (
                        int(result["notification_id"]) != notification_id
                        or str(result["state"]) != "ACKNOWLEDGED"
                    ):
                        raise ValueError("acknowledgement returned unexpected state")
                except Exception:
                    self._send_json(409, {"error": "acknowledgement failed"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "notification_id": notification_id,
                        "state": "ACKNOWLEDGED",
                    },
                )
                return
            if path == DIMINISHING_RETURNS_ROUTE:
                request = self._read_diminishing_returns_request()
                if request is None:
                    return
                if diminishing_returns_handler is None:
                    self._send_json(503, {"error": "acknowledgement unavailable"})
                    return
                slug, digest = request
                try:
                    result = diminishing_returns_handler(slug, digest)
                    if (
                        str(result["slug"]) != slug
                        or str(result["marker_sha256"]) != digest
                        or str(result["event_type"])
                        != "DIMINISHING_RETURNS_ACKNOWLEDGED"
                    ):
                        raise ValueError("acknowledgement returned unexpected state")
                except Exception:
                    self._send_json(409, {"error": "acknowledgement failed"})
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "slug": slug,
                        "marker_sha256": digest,
                        "state": "ACKNOWLEDGED",
                    },
                )
                return
            if path != SUBMISSION_ROUTE:
                self._method_not_allowed()
                return
            item_id = self._read_submission_request()
            if item_id is None:
                return
            if submission_handler is None:
                self._send_json(503, {"error": "submission action unavailable"})
                return
            try:
                result = submission_handler(item_id)
                result_id = int(result["id"])
                state = str(result["state"])
                if result_id != item_id or state != "SUBMITTED":
                    raise ValueError("submission transition returned unexpected state")
            except Exception:
                self._send_json(
                    409,
                    {
                        "error": "submission reconciliation failed",
                        "code": "PACKAGE_RECONCILIATION_FAILED",
                        "detail": (
                            "Package state could not be reconciled safely. "
                            "Refresh and inspect Package details before retrying."
                        ),
                    },
                )
                return
            self._send_json(
                200,
                {"ok": True, "item_id": result_id, "state": state},
            )

        def _method_not_allowed(self) -> None:
            body = b'{"error":"method not allowed"}\n'
            allow = (
                "POST"
                if urlsplit(self.path).path
                in {
                    SUBMISSION_ROUTE,
                    DIMINISHING_RETURNS_ROUTE,
                    PACKAGE_OUTCOME_ROUTE,
                    WEEKLY_PATCH_WATCH_ROUTE,
                    REPORT_ISSUES_ROUTE,
                    REPORT_ISSUE_GREENLIGHT_ROUTE,
                    HUNT_PROFILE_ROUTE,
                    COORDINATION_CHAT_ROUTE,
                    COORDINATION_REPLY_ROUTE,
                    COORDINATION_DECISION_ROUTE,
                    COORDINATION_DISMISS_ROUTE,
                }
                else "GET"
            )
            self._send(405, body, allow=allow)

        do_PUT = _method_not_allowed
        do_PATCH = _method_not_allowed
        do_DELETE = _method_not_allowed

    return DashboardHandler


def create_server(
    bind: str,
    port: int,
    handler: type[BaseHTTPRequestHandler],
) -> DashboardServer:
    return DashboardServer((validate_bind(bind), validate_port(port)), handler)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Status dashboard for the JENNY review workflow."
    )
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_DEFAULT)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help=(
            "allow a non-loopback bind; use only behind a trusted local or "
            "Tailscale access boundary"
        ),
    )
    parser.add_argument("--no-open", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        bind = validate_remote_access(args.bind, args.allow_remote)
        port = validate_port(args.port)
    except ValueError as error:
        _parser().error(str(error))
    workspace = args.workspace.resolve()
    static_dir = Path(__file__).resolve().parent / "static"
    sampler = HostHealthSampler()

    def snapshot_provider() -> dict[str, object]:
        host_health = sampler.sample(workspace)
        return read_workflow_snapshot(workspace, host_health=host_health)

    def submission_handler(item_id: int) -> dict[str, object]:
        review_mailbox_dir = workspace / "tools" / "review_mailbox"
        if str(review_mailbox_dir) not in sys.path:
            sys.path.insert(0, str(review_mailbox_dir))
        from review_mailbox import Mailbox

        database = workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
        return Mailbox(database, workspace).mark_submitted(item_id)

    def diminishing_returns_handler(slug: str, marker_sha256: str) -> dict[str, object]:
        return acknowledge_diminishing_returns(workspace, slug, marker_sha256)

    def package_outcome_handler(notification_id: int) -> dict[str, object]:
        review_mailbox_dir = workspace / "tools" / "review_mailbox"
        if str(review_mailbox_dir) not in sys.path:
            sys.path.insert(0, str(review_mailbox_dir))
        from review_mailbox import Mailbox

        database = workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
        return Mailbox(database, workspace).acknowledge_package_outcome(
            notification_id
        )

    def hunt_profile_handler(preset: str) -> dict[str, object]:
        from tools.hunt_policy.hunt_policy import HuntPolicyStore

        active_target, _ = read_target_lifecycle_snapshot(workspace)
        target = (
            str(active_target.get("slug", ""))
            if active_target.get("status") == "active"
            else None
        )
        database = workspace / "notes" / "hunt_policy" / "hunt_policy.sqlite3"
        return HuntPolicyStore(database, workspace).select(preset, target)

    def coordination_reply_handler(
        message_id: int, revision: int, text: str
    ) -> dict[str, object]:
        from tools.coordination_inbox.coordination_inbox import CoordinationInbox

        database = workspace / "notes" / "coordination_inbox" / "coordination.sqlite3"
        return CoordinationInbox(database).reply(message_id, revision, text)

    def coordination_decision_handler(
        message_id: int,
        revision: int,
        decision: str,
        reason: str,
    ) -> dict[str, object]:
        from tools.coordination_inbox.coordination_inbox import CoordinationInbox

        database = workspace / "notes" / "coordination_inbox" / "coordination.sqlite3"
        return CoordinationInbox(database).decide(
            message_id, revision, decision, reason
        )

    def coordination_dismiss_handler(
        message_id: int, revision: int
    ) -> dict[str, object]:
        from tools.coordination_inbox.coordination_inbox import CoordinationInbox

        database = workspace / "notes" / "coordination_inbox" / "coordination.sqlite3"
        return CoordinationInbox(database).dismiss(message_id, revision)

    def coordination_chat_handler(body: str) -> dict[str, object]:
        from tools.coordination_inbox.coordination_inbox import CoordinationInbox

        active_target, _ = read_target_lifecycle_snapshot(workspace)
        slug = str(active_target.get("slug", "")).strip()
        context_ref = (
            f"TARGET:{slug}"
            if active_target.get("status") == "active" and slug
            else "WORKFLOW"
        )
        database = workspace / "notes" / "coordination_inbox" / "coordination.sqlite3"
        return CoordinationInbox(database).chat_send(
            sender="operator",
            recipient="midlane",
            context_ref=context_ref,
            body=body,
        )

    def weekly_patch_watch_handler(
        monday_date: str,
        manifest_digest: str,
    ) -> dict[str, object]:
        from tools.submitted_patch_watch.patch_watch import acknowledge_run

        return acknowledge_run(
            workspace,
            date.fromisoformat(monday_date),
            manifest_digest,
        )

    def report_issues_handler(
        issues: list[dict[str, str]],
    ) -> dict[str, object]:
        return acknowledge_report_issues(workspace, issues)

    def report_issue_greenlight_handler(issue_key: str) -> dict[str, object]:
        return greenlight_report_issue(workspace, issue_key)

    handler = make_handler(
        static_dir,
        snapshot_provider,
        submission_handler,
        diminishing_returns_handler,
        package_outcome_handler,
        hunt_profile_handler,
        coordination_reply_handler,
        coordination_decision_handler,
        coordination_dismiss_handler,
        coordination_chat_handler,
        weekly_patch_watch_handler=weekly_patch_watch_handler,
        report_issues_handler=report_issues_handler,
        report_issue_greenlight_handler=report_issue_greenlight_handler,
    )
    try:
        server = create_server(bind, port, handler)
    except OSError as exc:
        print(
            f"Dashboard could not bind to {bind}:{port} ({type(exc).__name__}). "
            "Another process may already be using that address.",
            file=sys.stderr,
            flush=True,
        )
        return 2
    actual_port = int(server.server_address[1])
    url = f"http://{bind}:{actual_port}/"
    print(f"JENNY dashboard: {url}", flush=True)
    if not ipaddress.ip_address(bind).is_loopback:
        print(
            "Remote mode: no application authentication; trusted network "
            "and Tailscale ACLs are the access boundary.",
            flush=True,
        )
    print("Press Ctrl+C to stop.", flush=True)
    if not args.no_open:
        webbrowser.open(url, new=2)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("Stopping dashboard.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
