from __future__ import annotations

import ctypes
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import time
from collections import Counter
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

from tools.hunt_policy.hunt_policy import HuntPolicyStore
from tools.review_mailbox.human_time import format_duration, format_local_time
from tools.review_mailbox.report_issues import list_issues as list_report_issues
from tools.submitted_patch_watch.patch_watch import ELIGIBLE_TIME, load_dashboard_status


ACTIVE_REFRESH_SECONDS = 1
PARKED_REFRESH_SECONDS = 60
STALE_AFTER_SECONDS = 30 * 60
ASSUMED_SHUTDOWN_AFTER_SECONDS = 4 * 60 * 60
MAX_EVENTS = 25
PROJECT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
FINAL_DETERMINATION_SCHEMA = "jenny.final-review-determination.v1"
FINAL_DETERMINATION_FIELDS = (
    "technical_readiness",
    "portfolio_recommendation",
    "same_product_rank",
    "actual_vulnerability",
    "exploit_path",
    "threat_actor_impact",
    "decisive_proof",
    "cvss",
    "duplicate_posture",
    "estimated_payout",
    "discovery_difficulty",
)

READY_RE = re.compile(r"^_READY_TO_SUBMIT_(\d+)_")
SUBMITTED_RE = re.compile(r"^_SUBMITTED_(\d+)_")
ACCEPTED_RE = re.compile(r"^_ACCEPTED_(\d+)_")
PLAIN_RE = re.compile(r"^(\d+)_")

TERMINAL_STATES = {
    "ACCEPTED",
    "DEAD",
    "HOLD",
    "REJECTED",
    "SUBMITTED",
    "WRITE_OFF",
}
STAGING_STATES = {
    "FINAL_REWORK",
    "FINAL_REWORK_QUEUED",
    "HUNTER_REFINED",
    "MIDLANE_PASS",
    "MIDLANE_REVIEWING",
    "QUESTIONS_OPEN",
    "READY_FOR_MIDLANE",
}
DIRECT_ZDI_STATES = {"AWAITING_FINAL_REVIEW", "READY"}
NEXT_ACTOR = {
    "AWAITING_FINAL_REVIEW": "Operator",
    "FINAL_REWORK": "Hunter",
    "FINAL_REWORK_QUEUED": "Hunter",
    "HUNTER_REFINED": "Midlane",
    "MIDLANE_PASS": "Midlane",
    "MIDLANE_REVIEWING": "Midlane",
    "QUESTIONS_OPEN": "Hunter",
    "READY": "Operator",
    "READY_FOR_MIDLANE": "Midlane",
}
NEXT_ACTION = {
    "AWAITING_FINAL_REVIEW": "Run independent Final Review",
    "FINAL_REWORK": "Address claimed Final Rework",
    "FINAL_REWORK_QUEUED": "Claim Final Rework",
    "HUNTER_REFINED": "Re-review refined package",
    "MIDLANE_PASS": "Complete package promotion",
    "MIDLANE_REVIEWING": "Record independent verdict",
    "QUESTIONS_OPEN": "Answer review questions",
    "READY": "Confirm portal submission after submitting",
    "READY_FOR_MIDLANE": "Claim Midlane review",
}


def read_project_identity(workspace: Path) -> dict[str, str]:
    workspace = Path(workspace)
    version_path = workspace / "VERSION"
    try:
        version = version_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        version = "0.0.0"
    if not PROJECT_VERSION_RE.fullmatch(version):
        version = "0.0.0"
    try:
        channel = (workspace / "CHANNEL").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        channel = ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", channel):
        channel = ""
    return {
        "channel": channel or "release",
        "display_name": f"JENNY-{channel}" if channel else f"JENNY v{version}",
        "name": "JENNY",
        "version": version,
    }
ACTIVE_PHASES = {
    "AWAITING_FINAL_REVIEW": (
        "final-reviewer",
        "Final Reviewer",
        "FINAL REVIEW IN PROGRESS",
    ),
    "FINAL_REWORK": ("hunter", "Hunter", "FINAL REWORK IN PROGRESS"),
    "MIDLANE_REVIEWING": (
        "midlane",
        "Midlane",
        "MIDLANE REVIEW IN PROGRESS",
    ),
    "QUESTIONS_OPEN": (
        "hunter",
        "Hunter",
        "HUNTER REFINEMENT IN PROGRESS",
    ),
}


class _FileTime(ctypes.Structure):
    _fields_ = [
        ("low", ctypes.c_ulong),
        ("high", ctypes.c_ulong),
    ]


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("memory_load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


def _file_time_value(value: _FileTime) -> int:
    return (int(value.high) << 32) | int(value.low)


def _read_cpu_counters() -> tuple[int, int, int]:
    if not hasattr(ctypes, "windll"):
        raise OSError("unavailable")
    idle = _FileTime()
    kernel = _FileTime()
    user = _FileTime()
    if not ctypes.windll.kernel32.GetSystemTimes(  # type: ignore[attr-defined]
        ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
    ):
        raise OSError("unavailable")
    return (
        _file_time_value(idle),
        _file_time_value(kernel),
        _file_time_value(user),
    )


def _read_memory() -> tuple[int, int]:
    if not hasattr(ctypes, "windll"):
        raise OSError("unavailable")
    status = _MemoryStatusEx()
    status.length = ctypes.sizeof(_MemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(  # type: ignore[attr-defined]
        ctypes.byref(status)
    ):
        raise OSError("unavailable")
    return int(status.total_physical), int(status.available_physical)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_seconds(now: datetime, value: str | None) -> int:
    parsed = _parse_time(value)
    if parsed is None:
        return 0
    return max(0, int((now - parsed).total_seconds()))


def _display_time(now: datetime) -> str:
    return format_local_time(now.astimezone())


def _package_number(name: str) -> int | None:
    for pattern in (READY_RE, SUBMITTED_RE, ACCEPTED_RE, PLAIN_RE):
        match = pattern.match(name)
        if match:
            return int(match.group(1))
    return None


def _package_title(name: str, product: object) -> str:
    normalized = re.sub(r"^_(?:READY_TO_SUBMIT|SUBMITTED|ACCEPTED)_", "", name)
    normalized = re.sub(r"^\d+_", "", normalized)
    normalized = re.sub(r"_20\d{6}$", "", normalized)
    tokens = [token for token in normalized.split("_") if token]
    product_tokens = re.findall(r"[A-Za-z0-9]+", str(product))
    while (
        tokens
        and product_tokens
        and tokens[0].casefold() == product_tokens[0].casefold()
    ):
        tokens.pop(0)
        product_tokens.pop(0)
    return " ".join(tokens) or normalized.replace("_", " ")


def _worker_mentions_package(worker: dict[str, object], package_number: int) -> bool:
    text = f"{worker.get('task', '')} {worker.get('detail', '')}"
    pattern = rf"(?:\bpackage\s*#?\s*|#){package_number}\b"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def _worker_mentions_any_package(worker: dict[str, object]) -> bool:
    text = f"{worker.get('task', '')} {worker.get('detail', '')}"
    return re.search(r"(?:\bpackage\s*#?\s*|#)\d+\b", text, re.IGNORECASE) is not None


def _decorate_active_work(
    items: list[dict[str, object]], workers: list[dict[str, object]]
) -> set[int]:
    workers_by_name = {str(worker["worker"]): worker for worker in workers}
    candidates_by_worker: dict[str, list[dict[str, object]]] = {}
    for item in items:
        phase = ACTIVE_PHASES.get(str(item["state"]))
        if (
            phase is None
            or not isinstance(item.get("package_number"), int)
            or item.get("display_state") == "READY TO SUBMIT"
        ):
            continue
        candidates_by_worker.setdefault(phase[0], []).append(item)

    active_final_reviews: set[int] = set()
    for item in items:
        item["active_worker"] = ""
        if str(item["state"]) == "BUILDING_PACKAGE":
            item["active_worker"] = "Hunter"
            continue
        phase = ACTIVE_PHASES.get(str(item["state"]))
        package_number = item.get("package_number")
        if phase is None or not isinstance(package_number, int):
            continue
        worker_name, worker_label, display_state = phase
        worker = workers_by_name.get(worker_name)
        if (
            worker is None
            or str(worker["state"]) != "WORKING"
            or bool(worker["stale"])
        ):
            continue
        exact_match = _worker_mentions_package(worker, package_number)
        candidates = candidates_by_worker.get(worker_name, [])
        unique_match = (
            not _worker_mentions_any_package(worker)
            and len(candidates) == 1
            and candidates[0]["id"] == item["id"]
        )
        if not exact_match and not unique_match:
            continue
        item["active_worker"] = worker_label
        item["display_state"] = display_state
        if str(item["state"]) == "AWAITING_FINAL_REVIEW":
            active_final_reviews.add(package_number)
    return active_final_reviews


def _resolved_package_path(workspace: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = workspace / path
    return path.resolve()


def _relative_location(workspace: Path, path: Path) -> tuple[str, bool]:
    try:
        return path.relative_to(workspace).as_posix(), True
    except ValueError:
        return "outside-workspace", False


def _safe_text(value: object, workspace: Path) -> str:
    text = str(value or "")
    variants = {str(workspace), workspace.as_posix()}
    for variant in variants:
        text = text.replace(variant, ".")
    return text


def _safe_final_determination(raw: str, workspace: Path) -> dict[str, str]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    if (
        not isinstance(value, dict)
        or value.get("schema") != FINAL_DETERMINATION_SCHEMA
    ):
        return {}
    determination = {"schema": FINAL_DETERMINATION_SCHEMA}
    for field in FINAL_DETERMINATION_FIELDS:
        field_value = value.get(field)
        if not isinstance(field_value, str) or not field_value.strip():
            return {}
        determination[field] = _safe_text(field_value.strip(), workspace)
    return determination


def _worker_display_detail(worker_name: str, detail: str) -> str:
    if worker_name != "midlane":
        return detail
    match = re.match(r"^Package\s+(?:_[A-Z_]+_)?(\d+)_", detail)
    if match is None:
        return detail
    return f"Package #{match.group(1)}"


def _event_detail(
    raw_detail: object,
    event_type: str,
    workspace: Path,
) -> str:
    try:
        detail = json.loads(str(raw_detail))
    except (json.JSONDecodeError, TypeError):
        return ""
    if not isinstance(detail, dict):
        return ""

    def short_hash(*keys: str) -> str:
        for key in keys:
            value = str(detail.get(key, "")).strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", value):
                return value[:12]
        return ""

    parts: list[str] = []
    if event_type == "WORKER_CHECKIN":
        parts = [
            str(detail[key]).strip()
            for key in ("task", "detail")
            if str(detail.get(key, "")).strip()
        ]
    elif event_type == "FINAL_REWORK_QUEUED":
        if detail.get("request_id") is not None:
            parts.append(f"Request {detail['request_id']}")
        if detail.get("reviewed_revision") is not None:
            parts.append(f"reviewed revision {detail['reviewed_revision']}")
        issues = detail.get("issue_ids")
        if isinstance(issues, list):
            issue_values = [str(value).strip() for value in issues if str(value).strip()]
            if issue_values:
                parts.append(f"issues: {', '.join(issue_values)}")
        digest = short_hash("reviewed_hash", "package_hash")
        if digest:
            parts.append(f"hash {digest}")
    elif event_type in {
        "FINAL_REWORK_ADDRESSED",
        "FINAL_REWORK_CLAIMED",
        "FINAL_REWORK_VERIFIED",
    }:
        if detail.get("request_id") is not None:
            parts.append(f"Request {detail['request_id']}")
        if detail.get("revision") is not None:
            parts.append(f"revision {detail['revision']}")
        if event_type == "FINAL_REWORK_CLAIMED":
            parts.append("unchanged bytes moved to staging")
        digest = short_hash("package_hash")
        if digest:
            parts.append(f"hash {digest}")
    elif event_type == "PROMOTED_TO_FINAL":
        parts.append("Unchanged bytes moved to final review")
        digest = short_hash("package_hash")
        if digest:
            parts.append(f"hash {digest}")
    elif event_type == "MARKED_READY_FOR_SUBMISSION":
        parts.append("Unchanged bytes marked ready")
        digest = short_hash("package_hash")
        if digest:
            parts.append(f"hash {digest}")
    elif event_type == "SUBMISSION_RECONCILED":
        parts.append("Archived submitted bytes")
        parts.append(
            "accepted drift" if detail.get("accepted_drift") else "no byte drift"
        )
        digest = short_hash("archived_hash", "frozen_hash")
        if digest:
            parts.append(f"hash {digest}")
    elif event_type == "OPERATOR_ACCEPTED":
        amount_cents = detail.get("amount_cents")
        currency = str(detail.get("currency", ""))
        if isinstance(amount_cents, int) and currency == "USD":
            parts.append(f"Accepted for ${amount_cents / 100:,.2f}")
        digest = short_hash("accepted_hash")
        if digest:
            parts.append(f"hash {digest}")
    elif str(detail.get("summary", "")).strip():
        parts = [str(detail["summary"]).strip()]
    elif isinstance(detail.get("issue_ids"), list):
        issues = [str(value).strip() for value in detail["issue_ids"] if str(value).strip()]
        if issues:
            parts = [f"Issues: {', '.join(issues)}"]
    elif str(detail.get("note", "")).strip():
        parts = [str(detail["note"]).strip()]
    else:
        action = {
            "CLAIMED": "Frozen revision claimed by Midlane",
            "REGISTERED": "Frozen package registered",
            "REREGISTERED": "Revised package registered",
            "QUESTIONS_ANSWERED": "Hunter answer batch recorded",
            "RESTAGED_FROM_FINAL_ROOT": "Unchanged bytes returned to staging",
            "RESTORED_READY_AFTER_STALE_REWORK": "Prior ready bytes restored",
            "HOLD_RELOCATED": "Unchanged HOLD bytes parked",
            "DEAD_RELOCATED": "Unchanged DEAD bytes archived",
        }.get(event_type, "")
        if action:
            parts.append(action)
        for key, label in (
            ("question_count", "questions"),
            ("answer_count", "answers"),
            ("closure_count", "closures"),
            ("revision", "revision"),
        ):
            if detail.get(key) is not None:
                parts.append(f"{label} {detail[key]}")
        digest = short_hash("package_hash", "expected_hash", "observed_hash")
        if digest:
            parts.append(f"hash {digest}")

    text = " - ".join(dict.fromkeys(parts))
    return _safe_text(text, workspace)[:400]


def _alert(
    code: str,
    text: str,
    *,
    severity: str = "warning",
    package_number: int | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "severity": severity,
        "package_number": package_number,
        "text": text,
    }


def _next_weekly_patch_watch_run(local_now: datetime) -> datetime:
    if local_now.tzinfo is None:
        local_now = local_now.astimezone()
    days_until_monday = (7 - local_now.weekday()) % 7
    candidate = (
        local_now.replace(
            hour=ELIGIBLE_TIME.hour,
            minute=ELIGIBLE_TIME.minute,
            second=0,
            microsecond=0,
        )
        + timedelta(days=days_until_monday)
    )
    if candidate <= local_now:
        candidate += timedelta(days=7)
    return candidate


def _empty_snapshot(
    now: datetime,
    error: str,
    *,
    weekly_patch_watch_next_run_at: str,
) -> dict[str, object]:
    return {
        "available": False,
        "error": error,
        "generated_at": now.isoformat(),
        "display_time": _display_time(now),
        "fully_parked": False,
        "assumed_shutdown": False,
        "refresh_seconds": ACTIVE_REFRESH_SECONDS,
        "counts": {},
        "alerts": [
            _alert("MAILBOX_UNAVAILABLE", error, severity="error")
        ],
        "workers": [],
        "operator_requests": [],
        "approval_requests": [],
        "package_outcome_notifications": [],
        "candidate_reviews": [],
        "hunt_state": None,
        "hunt_profile": {
            "available": False,
            "active": {
                "revision": 0,
                "preset": "A_TIER_ONLY",
                "state": "ACKNOWLEDGED",
                "target": None,
                "selected_at": "",
                "acknowledged_at": "",
            },
            "pending": None,
            "warning": "hunt profile unavailable",
        },
        "coordination_inbox": {
            "available": False,
            "open": [],
            "chat": [],
            "warning": "coordination inbox unavailable",
        },
        "final_reviewer": None,
        "midlane": {"status": "not observed"},
        "host": {},
        "active_items": [],
        "terminal_counts": {},
        "terminal_items": [],
        "recent_events": [],
        "report_issues": None,
        "weekly_patch_watch": None,
        "weekly_patch_watch_next_run_at": weekly_patch_watch_next_run_at,
    }


def read_hunt_profile_snapshot(workspace: Path) -> dict[str, object]:
    database = Path(workspace) / "notes" / "hunt_policy" / "hunt_policy.sqlite3"
    if not database.is_file():
        return {
            "available": False,
            "active": {
                "revision": 0,
                "preset": "A_TIER_ONLY",
                "state": "ACKNOWLEDGED",
                "target": None,
                "selected_at": "",
                "acknowledged_at": "",
            },
            "pending": None,
            "warning": "hunt profile unavailable",
        }
    try:
        return HuntPolicyStore(
            database,
            Path(workspace),
        ).snapshot()
    except (OSError, sqlite3.Error, ValueError):
        return {
            "available": False,
            "active": {
                "revision": 0,
                "preset": "A_TIER_ONLY",
                "state": "ACKNOWLEDGED",
                "target": None,
                "selected_at": "",
                "acknowledged_at": "",
            },
            "pending": None,
            "warning": "hunt profile unavailable",
        }


def _coordination_target_labels(workspace: Path) -> dict[str, str]:
    database = (
        Path(workspace)
        / "notes"
        / "target_lifecycle"
        / "target_lifecycle.sqlite3"
    )
    if not database.is_file():
        return {}
    try:
        with closing(_open_read_only(database)) as connection:
            rows = connection.execute("SELECT slug, product FROM targets").fetchall()
        return {str(row["slug"]): str(row["product"]) for row in rows}
    except (OSError, sqlite3.DatabaseError):
        return {}


def _coordination_target_label(labels: dict[str, str], slug: str) -> str:
    product = str(labels.get(slug, "")).strip()
    if not product:
        return slug
    normalize = lambda value: "".join(  # noqa: E731 - compact display helper
        character for character in value.casefold() if character.isalnum()
    )
    if normalize(product) == normalize(slug):
        return product
    return f"{product} ({slug})"


def read_coordination_snapshot(
    workspace: Path,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    database = (
        Path(workspace)
        / "notes"
        / "coordination_inbox"
        / "coordination.sqlite3"
    )
    if not database.is_file():
        return {"available": True, "open": [], "chat": [], "warning": ""}
    try:
        from tools.coordination_inbox.coordination_inbox import CoordinationInbox

        current = now if now is not None else datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        target_labels = _coordination_target_labels(workspace)
        decision_cutoff = (current.astimezone(UTC) - timedelta(minutes=30)).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        messages = CoordinationInbox(database).list_for_dashboard(
            decision_cutoff=decision_cutoff,
            limit=20,
        )
        active_target, _ = read_target_lifecycle_snapshot(Path(workspace))
        active_slug = (
            str(active_target.get("slug", ""))
            if active_target.get("status") == "active"
            else ""
        )
        lifecycle_known = active_target.get("status") != "unavailable"
        if lifecycle_known:
            messages = [
                message
                for message in messages
                if (
                    not active_slug
                    or str(message.get("scope_kind", "")) == "PACKAGE"
                    or str(message.get("scope_ref", "")) == active_slug
                )
            ]
        for message in messages:
            display_timestamp = (
                message.get("decided_at")
                if message.get("operator_decision")
                else message.get("created_at")
            )
            age_seconds = _age_seconds(current.astimezone(UTC), str(display_timestamp))
            message["age_seconds"] = age_seconds
            message["age"] = format_duration(age_seconds)
            if str(message.get("scope_kind", "")) == "TARGET":
                slug = str(message.get("scope_ref", ""))
                message["scope_label"] = _coordination_target_label(
                    target_labels,
                    slug,
                )
        chat = []
        for message in CoordinationInbox(database).chat_history(limit=20):
            age_seconds = _age_seconds(current.astimezone(UTC), str(message["created_at"]))
            if age_seconds > 24 * 60 * 60:
                continue
            message["age_seconds"] = age_seconds
            message["age"] = format_duration(age_seconds)
            context_ref = str(message.get("context_ref", ""))
            if (
                lifecycle_known
                and active_slug
                and context_ref.startswith("TARGET:")
                and context_ref.partition(":")[2] != active_slug
            ):
                continue
            if context_ref.startswith("TARGET:"):
                slug = context_ref.partition(":")[2]
                message["context_label"] = _coordination_target_label(
                    target_labels,
                    slug,
                )
            else:
                message["context_label"] = context_ref
            chat.append(message)
        return {"available": True, "open": messages, "chat": chat, "warning": ""}
    except (OSError, sqlite3.Error, ValueError, RuntimeError):
        return {
            "available": False,
            "open": [],
            "chat": [],
            "warning": "coordination inbox unavailable",
        }


def _read_rows(
    connection: sqlite3.Connection,
) -> dict[str, list[sqlite3.Row]]:
    work_item_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(work_items)")
    }
    final_determination_projection = (
        "final_determination_json"
        if "final_determination_json" in work_item_columns
        else "'{}' AS final_determination_json"
    )
    items = connection.execute(
        f"""
        SELECT id, package_path, product, version, package_hash, reviewed_hash,
               review_summary, {final_determination_projection},
               state, revision, updated_at, hold_reason,
               submitted_at, dead_at
        FROM work_items ORDER BY id
        """
    ).fetchall()
    workers = connection.execute(
        """
        SELECT worker, state, task, detail, updated_at
        FROM worker_status
        ORDER BY lower(worker), updated_at DESC,
                 CASE WHEN worker = lower(worker) THEN 0 ELSE 1 END,
                 worker
        """
    ).fetchall()
    has_worker_activity = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_activity'"
    ).fetchone()
    worker_activity = (
        connection.execute(
            """
            SELECT worker, category, detail, source, session_hash, target, updated_at
            FROM worker_activity
            ORDER BY lower(worker), updated_at DESC
            """
        ).fetchall()
        if has_worker_activity is not None
        else []
    )
    has_operator_requests = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'operator_requests'"
    ).fetchone()
    operator_requests = (
        connection.execute(
            """
            SELECT worker, target, summary, detail, state, created_at, updated_at
            FROM operator_requests
            WHERE state = 'OPEN'
            ORDER BY updated_at DESC, lower(worker)
            """
        ).fetchall()
        if has_operator_requests is not None
        else []
    )
    has_approval_requests = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'operator_approval_requests'
        """
    ).fetchone()
    approval_requests = (
        connection.execute(
            """
            SELECT worker, target, summary, detail, state, created_at, updated_at
            FROM operator_approval_requests
            WHERE state = 'OPEN'
            ORDER BY updated_at DESC, lower(worker)
            """
        ).fetchall()
        if has_approval_requests is not None
        else []
    )
    has_package_builds = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'package_builds'"
    ).fetchone()
    package_builds = (
        connection.execute(
            """
            SELECT package_number, package_path, product, version, detail,
                   created_at, updated_at
            FROM package_builds
            ORDER BY updated_at DESC, package_number DESC
            """
        ).fetchall()
        if has_package_builds is not None
        else []
    )
    has_candidate_challenges = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'candidate_challenges'
        """
    ).fetchone()
    candidate_challenges = (
        connection.execute(
            """
            SELECT id, candidate_key, candidate_title, product, version,
                   target_slug, state, reviewer, disposition, package_number,
                   created_at, decided_at, updated_at
            FROM candidate_challenges
            WHERE package_number IS NOT NULL
            ORDER BY updated_at DESC, id DESC
            """
        ).fetchall()
        if has_candidate_challenges is not None
        else []
    )
    candidate_reviews = (
        connection.execute(
            """
            SELECT id, candidate_title, product, version, target_slug, state,
                   reviewer, disposition, updated_at
            FROM candidate_challenges
            WHERE package_number IS NULL
              AND state IN ('PENDING', 'CLAIMED')
            ORDER BY
              CASE state
                WHEN 'CLAIMED' THEN 0
                WHEN 'PENDING' THEN 1
                ELSE 2
              END,
              updated_at ASC,
              id ASC
            LIMIT 50
            """
        ).fetchall()
        if has_candidate_challenges is not None
        else []
    )
    has_outcome_notifications = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'package_outcome_notifications'
        """
    ).fetchone()
    outcome_notifications = (
        connection.execute(
            """
            SELECT id, work_item_id, outcome, package_path, product,
                   package_hash, revision, reason, state, created_at
            FROM package_outcome_notifications
            WHERE state = 'OPEN'
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        if has_outcome_notifications is not None
        else []
    )
    has_acquisitions = connection.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'accepted_acquisitions'"
    ).fetchone()
    acquisitions = (
        connection.execute(
            """
            SELECT id, work_item_id, package_number, product, title,
                   package_path, accepted_hash, accepted_revision,
                   amount_cents, currency, accepted_at
            FROM accepted_acquisitions
            WHERE status = 'ACTIVE'
            ORDER BY accepted_at DESC, id DESC
            """
        ).fetchall()
        if has_acquisitions is not None
        else []
    )
    has_rejections = connection.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'rejections'"
    ).fetchone()
    rejections = (
        connection.execute(
            """
            SELECT id, work_item_id, package_number, product, title,
                   package_path, rejected_hash, rejected_revision,
                   reason_code, reason, case_id, public_reference, rejected_at
            FROM rejections
            ORDER BY rejected_at DESC, id DESC
            """
        ).fetchall()
        if has_rejections is not None
        else []
    )
    reworks = connection.execute(
        """
        SELECT id, work_item_id, state, reviewed_revision, addressed_revision,
               summary, created_at, claimed_at, addressed_at, verified_at, closed_at
        FROM final_rework_requests ORDER BY id DESC
        """
    ).fetchall()
    questions = connection.execute(
        """
        SELECT work_item_id, COUNT(*) AS count
        FROM questions WHERE status = 'OPEN' GROUP BY work_item_id
        """
    ).fetchall()
    events = connection.execute(
        """
        SELECT id, work_item_id, actor, event_type, detail_json, created_at
        FROM events
        WHERE event_type != 'WORKER_ACTIVITY_HEARTBEAT'
        ORDER BY id DESC LIMIT ?
        """,
        (MAX_EVENTS,),
    ).fetchall()
    midlane = connection.execute(
        """
        SELECT id, work_item_id, actor, event_type, created_at
        FROM events WHERE lower(actor) LIKE '%midlane%'
          AND event_type != 'WORKER_CHECKIN'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchall()
    return {
        "items": items,
        "workers": workers,
        "worker_activity": worker_activity,
        "operator_requests": operator_requests,
        "approval_requests": approval_requests,
        "outcome_notifications": outcome_notifications,
        "package_builds": package_builds,
        "candidate_challenges": candidate_challenges,
        "candidate_reviews": candidate_reviews,
        "acquisitions": acquisitions,
        "rejections": rejections,
        "reworks": reworks,
        "questions": questions,
        "events": events,
        "midlane": midlane,
    }


def _open_read_only(db_path: Path) -> sqlite3.Connection:
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=1)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 1000")
    return connection


def _workspace_path(workspace: Path, value: str) -> Path | None:
    path = Path(value)
    if not path.is_absolute():
        path = workspace / path
    try:
        resolved = path.resolve()
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return None
    return resolved


def _diminishing_returns_path(
    workspace: Path,
    slug: str,
    goal_value: object,
) -> Path:
    goal = _workspace_path(workspace, str(goal_value or ""))
    if goal is not None and goal.is_file():
        try:
            text = goal.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            text = ""
        for match in re.finditer(
            r"`([^`\r\n]*DIMINISHING_RETURNS\.md)`",
            text,
            flags=re.IGNORECASE,
        ):
            marker_value = match.group(1).strip()
            if Path(marker_value).name == marker_value:
                candidate = (
                    workspace / "targets" / slug / "DIMINISHING_RETURNS.md"
                ).resolve()
            else:
                candidate = _workspace_path(workspace, marker_value)
            if candidate is not None:
                return candidate
    return (workspace / "targets" / slug / "DIMINISHING_RETURNS.md").resolve()


def _marker_field(text: str, label: str) -> str:
    match = re.search(
        rf"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?{re.escape(label)}"
        r"(?:\*\*)?\s*:\s*(.+?)\s*$",
        text,
    )
    if match is None:
        return ""
    return re.sub(r"\*\*$", "", match.group(1).strip()).strip()


def read_target_lifecycle_snapshot(
    workspace: Path,
) -> tuple[dict[str, object], dict[str, object] | None]:
    workspace = Path(workspace).resolve()
    database = workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
    if not database.is_file():
        return {"status": "unavailable", "slug": "", "product": "Unavailable"}, None
    try:
        with closing(_open_read_only(database)) as connection:
            active = connection.execute(
                "SELECT slug, product, goal_path FROM targets "
                "WHERE status = 'ACTIVE' ORDER BY slug"
            ).fetchall()
            if not active:
                return {
                    "status": "none",
                    "slug": "",
                    "product": "No active target",
                }, None
            if len(active) != 1:
                return {
                    "status": "fault",
                    "slug": "",
                    "product": "Multiple active targets",
                    "slugs": [str(row["slug"]) for row in active],
                }, None

            row = active[0]
            slug = str(row["slug"])
            product = str(row["product"])
            target = {"status": "active", "slug": slug, "product": product}
            marker = _diminishing_returns_path(workspace, slug, row["goal_path"])
            if not marker.is_file():
                return target, None
            raw = marker.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            acknowledgements = connection.execute(
                "SELECT metadata_json FROM events "
                "WHERE slug = ? AND event_type = 'DIMINISHING_RETURNS_ACKNOWLEDGED' "
                "ORDER BY id DESC",
                (slug,),
            ).fetchall()
            for acknowledgement in acknowledgements:
                try:
                    metadata = json.loads(str(acknowledgement["metadata_json"] or ""))
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(metadata, dict)
                    and str(metadata.get("marker_sha256", "")).lower() == digest
                ):
                    return target, None

            text = raw.decode("utf-8", errors="replace")
            return target, {
                "slug": slug,
                "product": product,
                "marker_sha256": digest,
                "message": text.strip(),
                "revision": _marker_field(text, "Revision"),
                "updated": _marker_field(text, "Updated"),
                "recommendation": _marker_field(text, "Recommendation"),
                "strongest_survivor": _marker_field(text, "Strongest survivor"),
                "largest_exhausted_area": _marker_field(
                    text, "Largest exhausted area"
                ),
                "top_blocker": _marker_field(text, "Top blocker"),
                "operator_decision": _marker_field(text, "Operator decision"),
                "hunter_next_action": _marker_field(text, "Hunter next action"),
            }
    except (OSError, sqlite3.DatabaseError):
        return {"status": "unavailable", "slug": "", "product": "Unavailable"}, None


def read_hunt_state_summary(
    workspace: Path, slug: str
) -> dict[str, int] | None:
    slug = str(slug or "").strip()
    database = Path(workspace).resolve() / "notes" / "hunt_state" / "hunt_state.sqlite3"
    if not slug or not database.is_file():
        return None
    try:
        with closing(_open_read_only(database)) as connection:
            checkpoint_rows = connection.execute(
                "SELECT c.state FROM checkpoint_revisions c JOIN ("
                "SELECT stage_key, MAX(revision) AS revision "
                "FROM checkpoint_revisions WHERE slug = ? GROUP BY stage_key"
                ") latest ON latest.stage_key = c.stage_key "
                "AND latest.revision = c.revision WHERE c.slug = ?",
                (slug, slug),
            ).fetchall()
            hypothesis_rows = connection.execute(
                "SELECT h.state FROM hypothesis_revisions h JOIN ("
                "SELECT hypothesis_id, MAX(revision) AS revision "
                "FROM hypothesis_revisions WHERE slug = ? GROUP BY hypothesis_id"
                ") latest ON latest.hypothesis_id = h.hypothesis_id "
                "AND latest.revision = h.revision WHERE h.slug = ?",
                (slug, slug),
            ).fetchall()
    except (OSError, sqlite3.DatabaseError):
        return None
    if not checkpoint_rows and not hypothesis_rows:
        return None
    return {
        "complete": sum(row["state"] == "COMPLETE" for row in checkpoint_rows),
        "active": sum(row["state"] == "ACTIVE" for row in checkpoint_rows),
        "blocked": sum(row["state"] == "BLOCKED" for row in checkpoint_rows),
        "open_hypotheses": sum(
            row["state"] in {"OPEN", "TESTING", "SUPPORTED", "BLOCKED"}
            for row in hypothesis_rows
        ),
    }


def read_report_issues_snapshot(
    workspace: Path, *, now: datetime
) -> dict[str, object]:
    database = workspace / "notes" / "report_issues" / "report_issues.sqlite3"
    empty = {
        "available": False,
        "active_count": 0,
        "open_count": 0,
        "awaiting_greenlight_count": 0,
        "unacknowledged_count": 0,
        "issues": [],
        "acknowledgement_items": [],
    }
    if not database.is_file():
        return empty
    try:
        rows = list_report_issues(workspace=workspace, include_closed=False)
    except (OSError, sqlite3.Error):
        return empty
    issues: list[dict[str, object]] = []
    acknowledgement_items: list[dict[str, str]] = []
    for row in rows:
        issue = {
            "issue_key": str(row["issue_key"]),
            "title": str(row["title"]),
            "priority": str(row["priority"]),
            "category": str(row["category"]),
            "reported_by": str(row.get("reported_by") or "system"),
            "status": str(row["status"]),
            "owner": str(row["owner"]),
            "next_action": str(row["next_action"]),
            "updated_at": str(row["updated_at"]),
            "age_seconds": _age_seconds(now, str(row["updated_at"])),
            "acknowledged": bool(row.get("operator_acknowledged_at")),
        }
        issues.append(issue)
        if issue["status"] == "OPEN" and not issue["acknowledged"]:
            acknowledgement_items.append(
                {
                    "issue_key": str(issue["issue_key"]),
                    "updated_at": str(issue["updated_at"]),
                }
            )
    return {
        "available": True,
        "active_count": len(issues),
        "open_count": sum(issue["status"] == "OPEN" for issue in issues),
        "awaiting_greenlight_count": sum(
            issue["status"] == "RESOLVED_AWAITING_OPERATOR_GREENLIGHT"
            for issue in issues
        ),
        "unacknowledged_count": len(acknowledgement_items),
        "issues": issues,
        "acknowledgement_items": acknowledgement_items,
    }


def read_workflow_snapshot(
    workspace: Path,
    *,
    now: datetime | None = None,
    host_health: dict[str, object] | None = None,
) -> dict[str, object]:
    workspace = Path(workspace).resolve()
    local_now = now if now is not None else datetime.now().astimezone()
    if local_now.tzinfo is None:
        local_now = local_now.astimezone()
    next_weekly_run_at = _next_weekly_patch_watch_run(local_now).isoformat()
    now = local_now.astimezone(UTC)
    project = read_project_identity(workspace)
    hunt_profile = read_hunt_profile_snapshot(workspace)
    coordination_inbox = read_coordination_snapshot(workspace, now=now)
    active_target, diminishing_returns = read_target_lifecycle_snapshot(workspace)
    hunt_state_summary = (
        read_hunt_state_summary(workspace, str(active_target.get("slug", "")))
        if active_target.get("status") == "active"
        else None
    )
    db_path = workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
    if not db_path.is_file():
        snapshot = _empty_snapshot(
            now,
            "mailbox database is unavailable",
            weekly_patch_watch_next_run_at=next_weekly_run_at,
        )
        snapshot["project"] = project
        snapshot["host"] = host_health or {}
        snapshot["active_target"] = active_target
        snapshot["diminishing_returns"] = diminishing_returns
        snapshot["hunt_state"] = hunt_state_summary
        snapshot["hunt_profile"] = hunt_profile
        snapshot["coordination_inbox"] = coordination_inbox
        return snapshot

    try:
        with closing(_open_read_only(db_path)) as connection:
            rows = _read_rows(connection)
    except sqlite3.OperationalError:
        snapshot = _empty_snapshot(
            now,
            "mailbox database could not be read",
            weekly_patch_watch_next_run_at=next_weekly_run_at,
        )
        snapshot["project"] = project
        snapshot["host"] = host_health or {}
        snapshot["active_target"] = active_target
        snapshot["diminishing_returns"] = diminishing_returns
        snapshot["hunt_state"] = hunt_state_summary
        snapshot["hunt_profile"] = hunt_profile
        snapshot["coordination_inbox"] = coordination_inbox
        return snapshot
    except sqlite3.DatabaseError:
        snapshot = _empty_snapshot(
            now,
            "mailbox schema is incompatible",
            weekly_patch_watch_next_run_at=next_weekly_run_at,
        )
        snapshot["project"] = project
        snapshot["host"] = host_health or {}
        snapshot["active_target"] = active_target
        snapshot["diminishing_returns"] = diminishing_returns
        snapshot["hunt_state"] = hunt_state_summary
        snapshot["hunt_profile"] = hunt_profile
        snapshot["coordination_inbox"] = coordination_inbox
        return snapshot

    zdi_root = (workspace / "ZDI").resolve()
    staging_root = (workspace / "ZDI_STAGING").resolve()
    item_number_by_id: dict[int, int | None] = {}
    latest_rework: dict[int, sqlite3.Row] = {}
    for row in rows["reworks"]:
        latest_rework.setdefault(int(row["work_item_id"]), row)
    open_questions = {
        int(row["work_item_id"]): int(row["count"])
        for row in rows["questions"]
    }
    active_acquisitions = {
        int(row["work_item_id"]): row
        for row in rows["acquisitions"]
        if row["work_item_id"] is not None
    }
    latest_candidate_by_number: dict[int, sqlite3.Row] = {}
    for row in rows["candidate_challenges"]:
        package_number = row["package_number"]
        if package_number is not None:
            latest_candidate_by_number.setdefault(int(package_number), row)
    candidate_reviews: list[dict[str, object]] = []
    for row in rows["candidate_reviews"]:
        state = str(row["state"])
        reviewer = _safe_text(row["reviewer"], workspace).strip()
        if state == "CLAIMED":
            next_actor = "Midlane" if reviewer.casefold() == "midlane" else reviewer
            next_actor = next_actor or "Midlane"
            next_action = "Record independent disposition"
        else:
            next_actor = "Midlane"
            next_action = "Claim Candidate Challenge"
        age_seconds = _age_seconds(now, str(row["updated_at"]))
        candidate_reviews.append(
            {
                "id": int(row["id"]),
                "title": _safe_text(row["candidate_title"], workspace),
                "product": _safe_text(row["product"], workspace),
                "version": _safe_text(row["version"], workspace),
                "target_slug": _safe_text(row["target_slug"], workspace),
                "state": state,
                "reviewer": reviewer,
                "disposition": _safe_text(row["disposition"], workspace),
                "next_actor": next_actor,
                "next_action": next_action,
                "updated_at": str(row["updated_at"]),
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
            }
        )
    alerts: list[dict[str, object]] = []
    active_items: list[dict[str, object]] = []
    terminal_items: list[dict[str, object]] = []
    tracked_paths: set[Path] = set()

    package_outcome_notifications: list[dict[str, object]] = []
    for row in rows["outcome_notifications"]:
        package_path = Path(str(row["package_path"]))
        age_seconds = _age_seconds(now, str(row["created_at"]))
        package_outcome_notifications.append(
            {
                "notification_id": int(row["id"]),
                "item_id": int(row["work_item_id"]),
                "package_number": _package_number(package_path.name),
                "product": _safe_text(row["product"], workspace),
                "title": _package_title(package_path.name, row["product"]),
                "outcome": str(row["outcome"]),
                "reason": _safe_text(row["reason"], workspace),
                "revision": int(row["revision"]),
                "created_at": str(row["created_at"]),
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
            }
        )

    operator_requests: list[dict[str, object]] = []
    for row in rows["operator_requests"]:
        age_seconds = _age_seconds(now, str(row["updated_at"]))
        request = {
            "worker": str(row["worker"]).casefold(),
            "target": _safe_text(row["target"], workspace),
            "summary": _safe_text(row["summary"], workspace),
            "detail": _safe_text(row["detail"], workspace),
            "state": str(row["state"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "age_seconds": age_seconds,
            "age": format_duration(age_seconds),
        }
        operator_requests.append(request)
        worker_label = str(request["worker"]).upper()
        target_label = str(request["target"])
        text = (
            f"{worker_label} NEEDS OPERATOR - {request['summary']} "
            f"[{target_label}]"
        )
        if request["detail"]:
            text += f" - {request['detail']}"
        text += f" - {request['age']}"
        alerts.append(
            _alert(
                "OPERATOR_HELP_REQUEST",
                text,
                severity="operator",
            )
        )

    approval_requests: list[dict[str, object]] = []
    for row in rows["approval_requests"]:
        age_seconds = _age_seconds(now, str(row["updated_at"]))
        request = {
            "worker": str(row["worker"]).casefold(),
            "target": _safe_text(row["target"], workspace),
            "summary": _safe_text(row["summary"], workspace),
            "detail": _safe_text(row["detail"], workspace),
            "state": str(row["state"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "age_seconds": age_seconds,
            "age": format_duration(age_seconds),
        }
        approval_requests.append(request)

    for row in rows["items"]:
        item_id = int(row["id"])
        state = str(row["state"])
        path = _resolved_package_path(workspace, str(row["package_path"]))
        tracked_paths.add(path)
        location, inside_workspace = _relative_location(workspace, path)
        package_number = _package_number(path.name)
        item_number_by_id[item_id] = package_number
        path_exists = path.is_dir()
        is_direct_zdi = path.parent == zdi_root
        is_staging = path.parent == staging_root
        is_ready = bool(READY_RE.match(path.name)) and is_direct_zdi
        is_plain = bool(PLAIN_RE.match(path.name)) and is_direct_zdi

        rework = latest_rework.get(item_id)
        if (
            state == "READY_FOR_MIDLANE"
            and rework is not None
            and str(rework["state"]) == "ADDRESSED"
        ):
            display_state = "FINAL REWORK ADDRESSED"
        elif is_ready and state == "READY":
            display_state = "READY TO SUBMIT"
        elif is_plain and state == "AWAITING_FINAL_REVIEW":
            display_state = "FINAL REVIEW NEEDED"
        else:
            display_state = state.replace("_", " ")

        attention: list[str] = []
        if not inside_workspace:
            attention.append("PATH_OUTSIDE_WORKSPACE")
            alerts.append(
                _alert(
                    "PATH_OUTSIDE_WORKSPACE",
                    f"Package {package_number or item_id} is tracked outside the workspace",
                    severity="error",
                    package_number=package_number,
                )
            )
        if not path_exists:
            attention.append("TRACKED_PATH_MISSING")
            alerts.append(
                _alert(
                    "TRACKED_PATH_MISSING",
                    f"Package {package_number or item_id} tracked path is missing",
                    severity="error",
                    package_number=package_number,
                )
            )
        expected_location = True
        if state == "READY":
            expected_location = is_ready
        elif state == "AWAITING_FINAL_REVIEW":
            expected_location = is_plain
        elif state in STAGING_STATES:
            expected_location = is_staging
        elif state in DIRECT_ZDI_STATES:
            expected_location = is_direct_zdi
        if path_exists and inside_workspace and not expected_location:
            attention.append("STATE_LOCATION_MISMATCH")
            alerts.append(
                _alert(
                    "STATE_LOCATION_MISMATCH",
                    f"Package {package_number or item_id} state and location disagree",
                    severity="error",
                    package_number=package_number,
                )
            )

        if display_state == "READY TO SUBMIT":
            alerts.append(
                _alert(
                    "READY_TO_SUBMIT",
                    f"Package {package_number} is ready to submit",
                    package_number=package_number,
                )
            )
        elif display_state == "FINAL REVIEW NEEDED":
            alerts.append(
                _alert(
                    "FINAL_REVIEW_NEEDED",
                    f"Package {package_number} needs Final Review",
                    package_number=package_number,
                )
            )

        age_seconds = _age_seconds(now, str(row["updated_at"]))
        normalized = {
            "id": item_id,
            "package_number": package_number,
            "name": path.name,
            "title": _package_title(path.name, row["product"]),
            "product": _safe_text(row["product"], workspace),
            "version": _safe_text(row["version"], workspace),
            "revision": int(row["revision"]),
            "state": state,
            "display_state": display_state,
            "submission_available": (
                display_state == "READY TO SUBMIT"
                and path_exists
                and inside_workspace
                and not attention
            ),
            "final_verdict": "READY" if display_state == "READY TO SUBMIT" else "",
            "reviewed_revision": (
                int(row["revision"])
                if display_state == "READY TO SUBMIT" and row["reviewed_hash"]
                else None
            ),
            "reviewed_hash": (
                str(row["reviewed_hash"] or "")
                if display_state == "READY TO SUBMIT"
                else ""
            ),
            "package_hash": (
                str(row["package_hash"] or "")
                if display_state == "READY TO SUBMIT"
                else ""
            ),
            "review_summary": (
                _safe_text(row["review_summary"], workspace)
                if display_state == "READY TO SUBMIT"
                else ""
            ),
            "final_determination": (
                _safe_final_determination(
                    str(row["final_determination_json"] or "{}"),
                    workspace,
                )
                if display_state == "READY TO SUBMIT"
                else {}
            ),
            "location": location,
            "path_exists": path_exists,
            "next_actor": NEXT_ACTOR.get(state, "None" if state in TERMINAL_STATES else "Unknown"),
            "next_action": NEXT_ACTION.get(
                state,
                "No action" if state in TERMINAL_STATES else "Inspect workflow state",
            ),
            "rework_state": str(rework["state"]) if rework else "",
            "open_questions": open_questions.get(item_id, 0),
            "updated_at": str(row["updated_at"]),
            "age_seconds": age_seconds,
            "age": format_duration(age_seconds),
            "attention": attention,
        }
        candidate = (
            latest_candidate_by_number.get(package_number)
            if package_number is not None
            else None
        )
        if candidate is not None:
            normalized.update(
                {
                    "candidate_challenge_id": int(candidate["id"]),
                    "candidate_state": str(candidate["state"]),
                    "candidate_disposition": str(candidate["disposition"]),
                    "candidate_title": _safe_text(
                        candidate["candidate_title"], workspace
                    ),
                }
            )
        acquisition = active_acquisitions.get(item_id)
        if acquisition is not None:
            amount_cents = int(acquisition["amount_cents"])
            currency = str(acquisition["currency"])
            normalized["accepted_order"] = int(acquisition["id"])
            normalized["accepted_amount"] = (
                f"${amount_cents // 100:,}"
                if currency == "USD" and amount_cents % 100 == 0
                else f"{currency} {amount_cents / 100:,.2f}"
            )
            normalized["accepted_at"] = str(acquisition["accepted_at"])
        if state in TERMINAL_STATES:
            terminal_items.append(normalized)
        else:
            active_items.append(normalized)

    for row in rows["acquisitions"]:
        if row["work_item_id"] is not None:
            continue
        path = _resolved_package_path(workspace, str(row["package_path"]))
        tracked_paths.add(path)
        location, inside_workspace = _relative_location(workspace, path)
        age_seconds = _age_seconds(now, str(row["accepted_at"]))
        amount_cents = int(row["amount_cents"])
        currency = str(row["currency"])
        attention: list[str] = []
        if not inside_workspace:
            attention.append("PATH_OUTSIDE_WORKSPACE")
        if not path.is_dir():
            attention.append("TRACKED_PATH_MISSING")
        terminal_items.append(
            {
                "id": int(row["id"]),
                "package_number": int(row["package_number"]),
                "name": path.name,
                "title": _safe_text(row["title"], workspace),
                "product": _safe_text(row["product"], workspace),
                "version": "",
                "revision": int(row["accepted_revision"] or 0),
                "state": "ACCEPTED",
                "display_state": "ACCEPTED",
                "location": location,
                "path_exists": path.is_dir(),
                "next_actor": "None",
                "rework_state": "",
                "open_questions": 0,
                "updated_at": str(row["accepted_at"]),
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
                "attention": attention,
                "accepted_amount": (
                    f"${amount_cents // 100:,}"
                    if currency == "USD" and amount_cents % 100 == 0
                    else f"{currency} {amount_cents / 100:,.2f}"
                ),
                "accepted_order": int(row["id"]),
                "accepted_at": str(row["accepted_at"]),
            }
        )

    for row in rows["rejections"]:
        if row["work_item_id"] is not None:
            continue
        path = _resolved_package_path(workspace, str(row["package_path"]))
        tracked_paths.add(path)
        location, inside_workspace = _relative_location(workspace, path)
        age_seconds = _age_seconds(now, str(row["rejected_at"]))
        attention: list[str] = []
        if not inside_workspace:
            attention.append("PATH_OUTSIDE_WORKSPACE")
        if not path.is_dir():
            attention.append("TRACKED_PATH_MISSING")
        terminal_items.append(
            {
                "id": int(row["id"]),
                "package_number": int(row["package_number"]),
                "name": path.name,
                "title": _safe_text(row["title"], workspace),
                "product": _safe_text(row["product"], workspace),
                "version": "",
                "revision": int(row["rejected_revision"] or 0),
                "state": "REJECTED",
                "display_state": "REJECTED",
                "location": location,
                "path_exists": path.is_dir(),
                "next_actor": "None",
                "rework_state": "",
                "open_questions": 0,
                "updated_at": str(row["rejected_at"]),
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
                "attention": attention,
                "reason_code": str(row["reason_code"]),
                "rejection_reason": _safe_text(row["reason"], workspace),
                "rejected_at": str(row["rejected_at"]),
            }
        )

    for row in rows["package_builds"]:
        package_number = int(row["package_number"])
        path = _resolved_package_path(workspace, str(row["package_path"]))
        tracked_paths.add(path)
        location, inside_workspace = _relative_location(workspace, path)
        path_exists = path.is_dir()
        is_staging = path.parent == staging_root
        attention: list[str] = []
        if not inside_workspace:
            attention.append("PATH_OUTSIDE_WORKSPACE")
            alerts.append(
                _alert(
                    "PATH_OUTSIDE_WORKSPACE",
                    f"Package {package_number} build is outside the workspace",
                    severity="error",
                    package_number=package_number,
                )
            )
        if not path_exists:
            attention.append("TRACKED_PATH_MISSING")
            alerts.append(
                _alert(
                    "TRACKED_PATH_MISSING",
                    f"Package {package_number} build path is missing",
                    severity="error",
                    package_number=package_number,
                )
            )
        if path_exists and inside_workspace and not is_staging:
            attention.append("STATE_LOCATION_MISMATCH")
            alerts.append(
                _alert(
                    "STATE_LOCATION_MISMATCH",
                    f"Package {package_number} build is not directly under ZDI_STAGING",
                    severity="error",
                    package_number=package_number,
                )
            )
        age_seconds = _age_seconds(now, str(row["updated_at"]))
        active_items.append(
            {
                "id": f"build-{package_number}",
                "package_number": package_number,
                "name": path.name,
                "title": _package_title(path.name, row["product"]),
                "product": _safe_text(row["product"], workspace),
                "version": _safe_text(row["version"], workspace),
                "revision": "\u2014",
                "state": "BUILDING_PACKAGE",
                "display_state": "BUILDING PACKAGE",
                "location": location,
                "path_exists": path_exists,
                "next_actor": "Hunter",
                "active_worker": "Hunter",
                "build_detail": _safe_text(row["detail"], workspace),
                "rework_state": "",
                "open_questions": 0,
                "updated_at": str(row["updated_at"]),
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
                "attention": attention,
                **(
                    {
                        "candidate_challenge_id": int(
                            latest_candidate_by_number[package_number]["id"]
                        ),
                        "candidate_state": str(
                            latest_candidate_by_number[package_number]["state"]
                        ),
                        "candidate_disposition": str(
                            latest_candidate_by_number[package_number]["disposition"]
                        ),
                        "candidate_title": _safe_text(
                            latest_candidate_by_number[package_number][
                                "candidate_title"
                            ],
                            workspace,
                        ),
                    }
                    if package_number in latest_candidate_by_number
                    else {}
                ),
            }
        )

    active_by_number: dict[int, list[dict[str, object]]] = {}
    for item in active_items:
        package_number = item.get("package_number")
        if isinstance(package_number, int):
            active_by_number.setdefault(package_number, []).append(item)
    for package_number, duplicates in active_by_number.items():
        if len(duplicates) < 2:
            continue
        item_ids = ", ".join(str(item["id"]) for item in duplicates)
        alerts.append(
            _alert(
                "DUPLICATE_PACKAGE_NUMBER",
                f"Package {package_number} has multiple active mailbox items: {item_ids}",
                severity="error",
                package_number=package_number,
            )
        )
        for item in duplicates:
            attention = item.get("attention")
            if isinstance(attention, list):
                attention.append("DUPLICATE_PACKAGE_NUMBER")

    if zdi_root.is_dir():
        for path in sorted(zdi_root.iterdir(), key=lambda candidate: candidate.name.lower()):
            if not path.is_dir() or path.resolve() in tracked_paths:
                continue
            package_number = _package_number(path.name)
            if PLAIN_RE.match(path.name):
                alerts.append(
                    _alert(
                        "UNTRACKED_FINAL_REVIEW_FOLDER",
                        f"Package {package_number} is in ZDI but absent from SQLite",
                        severity="error",
                        package_number=package_number,
                    )
                )
            elif READY_RE.match(path.name):
                alerts.append(
                    _alert(
                        "UNTRACKED_READY_FOLDER",
                        f"Ready package {package_number} is absent from SQLite",
                        severity="error",
                        package_number=package_number,
                    )
                )

    workers: list[dict[str, object]] = []
    seen_workers: set[str] = set()
    activity_by_worker = {
        str(row["worker"]).casefold(): row for row in rows["worker_activity"]
    }
    for row in rows["workers"]:
        worker_name = str(row["worker"]).casefold()
        if worker_name in seen_workers:
            continue
        seen_workers.add(worker_name)
        state = str(row["state"]).upper()
        semantic_updated_at = str(row["updated_at"])
        semantic_age_seconds = _age_seconds(now, semantic_updated_at)
        activity = activity_by_worker.get(worker_name)
        activity_age_seconds = (
            _age_seconds(now, str(activity["updated_at"]))
            if activity is not None
            else None
        )
        # A semantic check-in supersedes older transient activity. Keeping an
        # older heartbeat attached makes the card render stale "Live activity"
        # even while the worker's authoritative task/detail are current.
        if (
            activity_age_seconds is not None
            and activity_age_seconds > semantic_age_seconds
        ):
            activity = None
            activity_age_seconds = None
        age_seconds = min(
            semantic_age_seconds,
            activity_age_seconds
            if activity_age_seconds is not None
            else semantic_age_seconds,
        )
        assumed_shutdown = (
            worker_name == "hunter"
            and state in {"WORKING", "BLOCKED"}
            and age_seconds >= ASSUMED_SHUTDOWN_AFTER_SECONDS
        )
        stale = (
            state == "WORKING"
            and not assumed_shutdown
            and age_seconds > STALE_AFTER_SECONDS
        )
        # Semantic check-ins are event-driven. Only total observed inactivity
        # can produce dashboard attention; elapsed time alone never makes a
        # Hunter check-in "due".
        checkin_due = False
        task = _safe_text(row["task"], workspace)
        if assumed_shutdown:
            display_state = "DEAD"
        elif task.startswith("STANDING DOWN - "):
            display_state = "STANDING DOWN"
        elif task.startswith("PARKED - "):
            display_state = "PARKED"
        else:
            display_state = state
        workers.append(
            {
                "worker": worker_name,
                "state": state,
                "display_state": display_state,
                "availability_state": (
                    "STATUS UNKNOWN" if assumed_shutdown else "OBSERVED"
                ),
                "task": task,
                "detail": _worker_display_detail(
                    worker_name,
                    _safe_text(row["detail"], workspace),
                ),
                "updated_at": str(row["updated_at"]),
                "semantic_updated_at": semantic_updated_at,
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
                "semantic_age_seconds": semantic_age_seconds,
                "semantic_age": format_duration(semantic_age_seconds),
                "activity_category": (
                    _safe_text(activity["category"], workspace)
                    if activity is not None
                    else ""
                ),
                "activity_detail": (
                    _safe_text(activity["detail"], workspace)
                    if activity is not None
                    else ""
                ),
                "activity_source": (
                    _safe_text(activity["source"], workspace)
                    if activity is not None
                    else ""
                ),
                "activity_target": (
                    _safe_text(activity["target"], workspace)
                    if activity is not None
                    else ""
                ),
                "activity_updated_at": (
                    str(activity["updated_at"]) if activity is not None else None
                ),
                "activity_age_seconds": activity_age_seconds,
                "activity_age": (
                    format_duration(activity_age_seconds)
                    if activity_age_seconds is not None
                    else None
                ),
                "checkin_due": checkin_due,
                "checkin_due_after_seconds": None,
                "assumed_shutdown": assumed_shutdown,
                "assumed_shutdown_after_seconds": ASSUMED_SHUTDOWN_AFTER_SECONDS,
                "stale": stale,
                "stale_after_seconds": STALE_AFTER_SECONDS,
            }
        )
        code_prefix = re.sub(r"[^A-Z0-9]+", "_", worker_name.upper()).strip("_")
        if stale:
            alerts.append(
                _alert(
                    f"{code_prefix}_STALE",
                    f"{worker_name} has no observed activity for "
                    f"{STALE_AFTER_SECONDS // 60} minutes",
                    severity="error",
                )
            )
        elif state == "BLOCKED":
            alerts.append(
                _alert(
                    f"{code_prefix}_BLOCKED",
                    f"{worker_name} reports BLOCKED",
                    severity="error",
                )
            )
    active_final_reviews = _decorate_active_work(active_items, workers)
    if active_final_reviews:
        alerts = [
            alert
            for alert in alerts
            if not (
                alert["code"] == "FINAL_REVIEW_NEEDED"
                and alert.get("package_number") in active_final_reviews
            )
        ]

    final_reviewer = next(
        (
            dict(worker)
            for worker in workers
            if str(worker["worker"]).lower() == "final-reviewer"
        ),
        None,
    )
    if final_reviewer is not None:
        final_reviewer["mode"] = "activity"
        final_reviewer["stale"] = (
            str(final_reviewer["state"]) in {"WORKING", "BLOCKED"}
            and int(final_reviewer["age_seconds"]) > STALE_AFTER_SECONDS
        )
    reviewer_is_active = final_reviewer is not None and str(
        final_reviewer["state"]
    ) in {"WORKING", "BLOCKED"}
    if not reviewer_is_active:
        final_reviewer = None

    recent_events: list[dict[str, object]] = []
    for row in rows["events"]:
        age_seconds = _age_seconds(now, str(row["created_at"]))
        event_type = str(row["event_type"])
        package_number = item_number_by_id.get(row["work_item_id"])
        if package_number is None:
            try:
                event_detail = json.loads(str(row["detail_json"]))
            except (json.JSONDecodeError, TypeError):
                event_detail = {}
            detail_number = (
                event_detail.get("package_number")
                if isinstance(event_detail, dict)
                else None
            )
            if isinstance(detail_number, int) and detail_number > 0:
                package_number = detail_number
        recent_events.append(
            {
                "id": int(row["id"]),
                "package_number": package_number,
                "actor": _safe_text(row["actor"], workspace),
                "event_type": event_type,
                "detail": _event_detail(row["detail_json"], event_type, workspace),
                "created_at": str(row["created_at"]),
                "age_seconds": age_seconds,
                "age": format_duration(age_seconds),
            }
        )

    if rows["midlane"]:
        row = rows["midlane"][0]
        age_seconds = _age_seconds(now, str(row["created_at"]))
        midlane: dict[str, object] = {
            "status": "last observed",
            "event_type": str(row["event_type"]),
            "package_number": item_number_by_id.get(row["work_item_id"]),
            "created_at": str(row["created_at"]),
            "age_seconds": age_seconds,
            "age": format_duration(age_seconds),
        }
    else:
        midlane = {"status": "not observed"}

    hunter_worker = next(
        (worker for worker in workers if worker["worker"] == "hunter"), None
    )
    midlane_worker = next(
        (worker for worker in workers if worker["worker"] == "midlane"), None
    )
    diagnostic_prefix = "Hunter stale diagnostic:"
    if (
        hunter_worker is not None
        and bool(hunter_worker["stale"])
        and midlane_worker is not None
        and str(midlane_worker["task"]).startswith(diagnostic_prefix)
        and int(midlane_worker["age_seconds"])
        <= int(hunter_worker["age_seconds"])
    ):
        classification = str(midlane_worker["task"])[len(diagnostic_prefix) :].strip()
        midlane["investigation"] = {
            "classification": classification or "UNKNOWN",
            "detail": midlane_worker["detail"],
            "updated_at": midlane_worker["updated_at"],
            "age_seconds": midlane_worker["age_seconds"],
            "age": midlane_worker["age"],
        }

    def active_priority(item: dict[str, object]) -> tuple[int, int]:
        label = item["display_state"]
        priority = (
            0
            if label in {"READY TO SUBMIT", "FINAL REVIEW NEEDED"}
            or "IN PROGRESS" in str(label)
            else 1
        )
        return priority, int(item["age_seconds"])

    active_items.sort(key=active_priority)
    active_product = (
        " ".join(str(active_target.get("product", "")).split()).casefold()
        if active_target.get("status") == "active"
        else ""
    )

    def terminal_priority(item: dict[str, object]) -> tuple[object, ...]:
        item_product = " ".join(str(item.get("product", "")).split()).casefold()
        if active_product and item_product == active_product:
            return (0, -int(item["package_number"]))
        state = str(item["state"])
        state_order = {
            "SUBMITTED": 0,
            "HOLD": 1,
            "ACCEPTED": 2,
            "REJECTED": 3,
            "DEAD": 4,
        }
        rank = state_order.get(state, len(state_order))
        if state == "ACCEPTED":
            return (
                1,
                rank,
                str(item.get("accepted_at", "")),
                int(item.get("accepted_order", 0)),
            )
        return (1, rank, -int(item["id"]))

    terminal_items.sort(key=terminal_priority)
    counts = Counter(str(row["state"]) for row in rows["items"])
    terminal_counts = Counter(item["state"] for item in terminal_items)
    report_issues = read_report_issues_snapshot(workspace, now=now)
    weekly_patch_watch = load_dashboard_status(workspace)
    coordination_open = coordination_inbox.get("open", [])
    weekly_needs_ack = bool(
        weekly_patch_watch
        and str(weekly_patch_watch.get("state", "")) == "COMPLETED"
        and not str(weekly_patch_watch.get("acknowledged_at", ""))
    )
    actionable = bool(
        any(str(worker["state"]) in {"WORKING", "BLOCKED"} for worker in workers)
        or active_items
        or operator_requests
        or approval_requests
        or package_outcome_notifications
        or candidate_reviews
        or coordination_open
        or int(report_issues.get("unacknowledged_count", 0)) > 0
        or int(report_issues.get("awaiting_greenlight_count", 0)) > 0
        or weekly_needs_ack
        or alerts
    )
    fully_parked = not actionable
    assumed_shutdown = any(
        bool(worker.get("assumed_shutdown")) for worker in workers
    )
    refresh_seconds = PARKED_REFRESH_SECONDS if fully_parked else ACTIVE_REFRESH_SECONDS

    return {
        "available": True,
        "error": "",
        "project": project,
        "generated_at": now.isoformat(),
        "display_time": _display_time(now),
        "fully_parked": fully_parked,
        "assumed_shutdown": assumed_shutdown,
        "refresh_seconds": refresh_seconds,
        "counts": dict(sorted(counts.items())),
        "alerts": alerts,
        "workers": workers,
        "operator_requests": operator_requests,
        "approval_requests": approval_requests,
        "package_outcome_notifications": package_outcome_notifications,
        "candidate_reviews": candidate_reviews,
        "active_target": active_target,
        "diminishing_returns": diminishing_returns,
        "hunt_state": hunt_state_summary,
        "hunt_profile": hunt_profile,
        "coordination_inbox": coordination_inbox,
        "final_reviewer": final_reviewer,
        "midlane": midlane,
        "host": host_health or {},
        "active_items": active_items,
        "terminal_counts": dict(sorted(terminal_counts.items())),
        "terminal_items": terminal_items,
        "recent_events": recent_events,
        "report_issues": report_issues,
        "weekly_patch_watch": weekly_patch_watch,
        "weekly_patch_watch_next_run_at": next_weekly_run_at,
    }


class HostHealthSampler:
    def __init__(
        self,
        docker_ttl_seconds: int = 15,
        docker_timeout_seconds: int = 2,
        cpu_reader: Callable | None = None,
        memory_reader: Callable | None = None,
        disk_reader: Callable | None = None,
        docker_runner: Callable | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.docker_ttl_seconds = docker_ttl_seconds
        self.docker_timeout_seconds = docker_timeout_seconds
        self.cpu_reader = cpu_reader or _read_cpu_counters
        self.memory_reader = memory_reader or _read_memory
        self.disk_reader = disk_reader or shutil.disk_usage
        self.docker_runner = docker_runner or subprocess.run
        self.clock = clock or time.monotonic
        self._previous_cpu: tuple[int, int, int] | None = None
        self._docker_cached_at: float | None = None
        self._docker_cached_result: dict[str, object] | None = None

    def _sample_cpu(self) -> dict[str, object]:
        try:
            current = tuple(int(value) for value in self.cpu_reader())
        except (OSError, TypeError, ValueError):
            return {"status": "unknown", "error": "unavailable"}
        if len(current) != 3:
            return {"status": "unknown", "error": "unavailable"}
        previous = self._previous_cpu
        self._previous_cpu = current
        if previous is None:
            return {"status": "warming", "percent": None}
        idle_delta = current[0] - previous[0]
        kernel_delta = current[1] - previous[1]
        user_delta = current[2] - previous[2]
        total_delta = kernel_delta + user_delta
        if total_delta <= 0:
            return {"status": "unknown", "error": "unavailable"}
        busy_delta = total_delta - idle_delta
        percent = max(0.0, min(100.0, busy_delta * 100.0 / total_delta))
        return {"status": "ok", "percent": round(percent, 1)}

    def _sample_memory(self) -> dict[str, object]:
        try:
            total, available = (int(value) for value in self.memory_reader())
            if total <= 0 or available < 0:
                raise ValueError
        except (OSError, TypeError, ValueError):
            return {"status": "unknown", "error": "unavailable"}
        used = max(0, total - available)
        return {
            "status": "ok",
            "total_bytes": total,
            "available_bytes": available,
            "percent_used": round(used * 100.0 / total, 1),
        }

    def _sample_disk(self, workspace: Path) -> dict[str, object]:
        try:
            usage = self.disk_reader(workspace)
            total = int(usage.total)
            used = int(usage.used)
            free = int(usage.free)
        except (OSError, TypeError, ValueError, AttributeError):
            return {"status": "unknown", "error": "unavailable"}
        return {
            "status": "ok",
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "free_gib": round(free / (1024**3), 1),
        }

    def _sample_docker(self, now_monotonic: float) -> dict[str, object]:
        if (
            self._docker_cached_at is not None
            and self._docker_cached_result is not None
            and now_monotonic - self._docker_cached_at < self.docker_ttl_seconds
        ):
            return dict(self._docker_cached_result)
        try:
            result = self.docker_runner(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=self.docker_timeout_seconds,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            version = str(result.stdout or "").strip()
            if int(result.returncode) == 0 and version:
                normalized = {
                    "status": "ok",
                    "available": True,
                    "version": version,
                }
            else:
                normalized = {
                    "status": "unavailable",
                    "available": False,
                    "version": "",
                }
        except subprocess.TimeoutExpired:
            normalized = {
                "status": "timeout",
                "available": False,
                "version": "",
            }
        except (FileNotFoundError, OSError, TypeError, ValueError):
            normalized = {
                "status": "unavailable",
                "available": False,
                "version": "",
            }
        self._docker_cached_at = now_monotonic
        self._docker_cached_result = normalized
        return dict(normalized)

    def sample(
        self,
        workspace: Path,
        *,
        now_monotonic: float | None = None,
    ) -> dict[str, object]:
        sampled_at = self.clock() if now_monotonic is None else now_monotonic
        return {
            "cpu": self._sample_cpu(),
            "memory": self._sample_memory(),
            "disk": self._sample_disk(Path(workspace)),
            "docker": self._sample_docker(float(sampled_at)),
        }


def collect_host_health(
    workspace: Path,
    sampler: HostHealthSampler | None = None,
) -> dict[str, object]:
    return (sampler or HostHealthSampler()).sample(Path(workspace))
