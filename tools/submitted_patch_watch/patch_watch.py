#!/usr/bin/env python3
"""Resumable weekly public-patch watch for submitted vulnerability packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import Counter
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


WORKSPACE_DEFAULT = Path(__file__).resolve().parents[2]
WATCH_ROOT = Path("notes/submitted_patch_watch")
DATABASE_NAME = "patch_watch.sqlite3"
LATEST_REPORT_NAME = "LATEST_WEEKLY_PATCH_WATCH_REPORT.json"
ELIGIBLE_TIME = time(6, 45)
RESULT_SCHEMA = "jenny.weekly-patch-watch-results.v2"
REPORT_SCHEMA = "jenny.weekly-patch-watch-report.v2"
REPORT_SCHEMA_RE = re.compile(
    r"^[a-z][a-z0-9_-]*\.weekly-patch-watch-report\.v2$"
)
TERMINAL_SUBMISSION_ROOTS = (
    ("_SUBMITTED", "SUBMITTED", 1),
    ("_REJECTED", "REJECTED", 2),
    ("_ACCEPTED", "ACCEPTED", 3),
)
TERMINAL_STATES = {
    "NO_PUBLIC_CHANGE",
    "POSSIBLE_FIX",
    "LIKELY_EXACT_FIX",
    "FIX_RELEASED_AFTER_SUBMISSION",
    "PUBLIC_AFTER_SUBMISSION",
    "PUBLIC_BEFORE_SUBMISSION",
    "SOURCE_UNAVAILABLE",
    "RECORD_INCOMPLETE",
}
PATCH_MATCH_STATES = {
    "POSSIBLE_FIX",
    "LIKELY_EXACT_FIX",
    "FIX_RELEASED_AFTER_SUBMISSION",
    "PUBLIC_AFTER_SUBMISSION",
    "PUBLIC_BEFORE_SUBMISSION",
}
DURABLE_PATCH_STATES = {
    "LIKELY_EXACT_FIX",
    "FIX_RELEASED_AFTER_SUBMISSION",
    "PUBLIC_AFTER_SUBMISSION",
    "PUBLIC_BEFORE_SUBMISSION",
}
CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
RELATIONSHIPS = {
    "NO_MATCH",
    "UNKNOWN",
    "PREDATES_SUBMISSION",
    "POSTDATES_SUBMISSION",
    "SAME_DAY",
}
REPOSITORY_KINDS = {"PUBLIC", "CLOSED"}
SOURCE_CLASSES = {
    "RELEASES",
    "ADVISORIES",
    "ISSUES",
    "PULL_REQUESTS",
    "COMMITS",
    "PUBLIC_WEB",
}
SOURCE_CHECK_STATES = {"CHECKED", "NOT_APPLICABLE", "UNAVAILABLE"}


class PatchWatchError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _watch_root(workspace: Path) -> Path:
    return Path(workspace).resolve() / WATCH_ROOT


def _database_path(workspace: Path) -> Path:
    return _watch_root(workspace) / DATABASE_NAME


def _run_root(workspace: Path, monday_date: date) -> Path:
    return _watch_root(workspace) / monday_date.isoformat()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, value: object) -> None:
    _atomic_write(
        path,
        (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )


def _connect(workspace: Path) -> sqlite3.Connection:
    path = _database_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
            monday_date TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            started_at TEXT NOT NULL,
            started_early INTEGER NOT NULL,
            completed_at TEXT NOT NULL DEFAULT '',
            manifest_digest TEXT NOT NULL,
            total INTEGER NOT NULL,
            acknowledged_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS entries (
            monday_date TEXT NOT NULL REFERENCES runs(monday_date),
            entry_id TEXT NOT NULL,
            package_number INTEGER,
            relative_path TEXT NOT NULL,
            title TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            mailbox_item_id INTEGER,
            submitted_at TEXT NOT NULL,
            legacy_filesystem_only INTEGER NOT NULL,
            identity_conflict INTEGER NOT NULL,
            group_key TEXT NOT NULL,
            buyer_disposition TEXT NOT NULL DEFAULT 'SUBMITTED',
            duplicate_terminal_locations_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL,
            result_json TEXT NOT NULL DEFAULT '',
            carried_from_monday TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (monday_date, entry_id)
        );
        CREATE INDEX IF NOT EXISTS idx_patch_watch_entries_status
        ON entries(monday_date, status, group_key, package_number);
        """
    )
    entry_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(entries)").fetchall()
    }
    if "carried_from_monday" not in entry_columns:
        connection.execute(
            """
            ALTER TABLE entries
            ADD COLUMN carried_from_monday TEXT NOT NULL DEFAULT ''
            """
        )
    if "buyer_disposition" not in entry_columns:
        connection.execute(
            "ALTER TABLE entries ADD COLUMN buyer_disposition TEXT NOT NULL "
            "DEFAULT 'SUBMITTED'"
        )
    if "duplicate_terminal_locations_json" not in entry_columns:
        connection.execute(
            "ALTER TABLE entries ADD COLUMN duplicate_terminal_locations_json "
            "TEXT NOT NULL DEFAULT '[]'"
        )
    connection.commit()
    return connection


def _localize(current: datetime, local_timezone: tzinfo | None) -> datetime:
    if current.tzinfo is None:
        raise PatchWatchError("current time must include a timezone")
    if local_timezone is None:
        return current.astimezone()
    return current.astimezone(local_timezone)


def _eligible_monday(local: datetime) -> date | None:
    monday = local.date() - timedelta(days=local.weekday())
    if local.weekday() == 0 and local.timetz().replace(tzinfo=None) < ELIGIBLE_TIME:
        return None
    return monday


def _calendar_window(monday_date: date) -> tuple[date, date]:
    """Return the complete Sunday-through-Saturday period preceding a run."""

    return monday_date - timedelta(days=8), monday_date - timedelta(days=2)


def _dashboard_window(monday_date: date) -> tuple[str, str]:
    start, end = _calendar_window(monday_date)
    # Local noon avoids browser timezone conversion shifting a calendar date.
    return f"{start.isoformat()}T12:00:00", f"{end.isoformat()}T12:00:00"


def _early_run_freshness(
    run: dict[str, Any], target_monday: date, local: datetime
) -> str:
    """Classify an early run without letting a far-early run satisfy Monday."""

    # Finalization synchronizes the live terminal inventory before committing
    # COMPLETED.  A far-early scan that reaches that checkpoint on Sunday or
    # Monday is therefore current even when its original start timestamp is
    # older.  Ignore a completion timestamp that is in the caller's future so
    # deterministic historical checks cannot be satisfied retroactively.
    try:
        completed_text = str(run.get("completed_at") or "")
        if completed_text:
            completed = datetime.fromisoformat(completed_text)
            completed_local = _localize(completed, local.tzinfo)
            if (
                completed_local <= local
                and completed_local.date() >= target_monday - timedelta(days=1)
            ):
                return "FRESH"
    except (TypeError, ValueError):
        pass
    try:
        started = datetime.fromisoformat(str(run["started_at"]))
        started_local = _localize(started, local.tzinfo)
    except (KeyError, TypeError, ValueError):
        return "STALE"
    if started_local.date() >= target_monday - timedelta(days=1):
        return "FRESH"
    eligible = datetime.combine(target_monday, ELIGIBLE_TIME, tzinfo=local.tzinfo)
    return "OVERDUE" if local >= eligible else "STALE"


def weekly_due(
    workspace: Path,
    *,
    now: datetime | None = None,
    local_timezone: tzinfo | None = None,
) -> dict[str, Any]:
    current = now or _utc_now()
    local = _localize(current, local_timezone)
    monday = _eligible_monday(local)
    if monday is None:
        return {
            "due": False,
            "eligible_after": ELIGIBLE_TIME.strftime("%H:%M"),
            "local_now": local.isoformat(),
            "monday_date": "",
            "run_state": "NOT_ELIGIBLE",
        }
    next_monday = monday + timedelta(days=7)
    next_run = load_run(workspace, next_monday)
    if (
        local.date() < next_monday
        and next_run
        and next_run["state"] == "COMPLETED"
        and next_run["started_early"]
    ):
        freshness = _early_run_freshness(next_run, next_monday, local)
        if freshness != "FRESH":
            return {
                "due": freshness == "OVERDUE",
                "eligible_after": ELIGIBLE_TIME.strftime("%H:%M"),
                "local_now": local.isoformat(),
                "monday_date": next_monday.isoformat(),
                "run_state": freshness,
            }
        current_digest = _manifest_digest(
            next_monday, _manifest_entries(workspace)
        )
        if current_digest != str(next_run["manifest_digest"]):
            return {
                "due": True,
                "eligible_after": ELIGIBLE_TIME.strftime("%H:%M"),
                "local_now": local.isoformat(),
                "monday_date": next_monday.isoformat(),
                "run_state": "INVENTORY_CHANGED",
            }
        return {
            "due": False,
            "eligible_after": ELIGIBLE_TIME.strftime("%H:%M"),
            "local_now": local.isoformat(),
            "monday_date": next_monday.isoformat(),
            "run_state": "COMPLETED",
        }
    run = load_run(workspace, monday)
    state = str(run["state"]) if run else "MISSING"
    if run and state == "COMPLETED" and run["started_early"]:
        freshness = _early_run_freshness(run, monday, local)
        if freshness != "FRESH":
            state = freshness
        current_digest = _manifest_digest(monday, _manifest_entries(workspace))
        if state == "COMPLETED" and current_digest != str(run["manifest_digest"]):
            state = "INVENTORY_CHANGED"
    return {
        "due": state != "COMPLETED",
        "eligible_after": ELIGIBLE_TIME.strftime("%H:%M"),
        "local_now": local.isoformat(),
        "monday_date": monday.isoformat(),
        "run_state": state,
    }


def _package_number(name: str) -> int | None:
    match = re.match(
        r"^_(?:SUBMITTED|ACCEPTED|REJECTED)_(\d+)_", name, re.IGNORECASE
    )
    return int(match.group(1)) if match else None


def _title_from_name(name: str) -> str:
    title = re.sub(
        r"^_(?:SUBMITTED|ACCEPTED|REJECTED)_\d+_",
        "",
        name,
        flags=re.IGNORECASE,
    )
    title = re.sub(r"_20\d{6}$", "", title)
    return re.sub(r"_+", " ", title).strip()


def _infer_product(title: str) -> str:
    words = title.split()
    return " ".join(words[: min(3, len(words))]) or "Unknown product"


def _mailbox_submissions(workspace: Path) -> dict[int, list[dict[str, Any]]]:
    path = (
        Path(workspace).resolve()
        / "notes"
        / "review_mailbox"
        / "review_mailbox.sqlite3"
    )
    if not path.is_file():
        return {}
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        try:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(work_items)")
            }
            required = {
                "id",
                "package_path",
                "submitted_path",
                "product",
                "version",
                "state",
                "submitted_at",
            }
            if not required.issubset(columns):
                return {}
            rows = connection.execute(
                """
                SELECT id, package_path, submitted_path, product, version,
                       state, submitted_at
                FROM work_items
                WHERE state = 'SUBMITTED'
                ORDER BY id
                """
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise PatchWatchError(f"cannot read optional review mailbox: {error}") from error
    by_number: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        record = dict(row)
        candidate = Path(
            str(record.get("submitted_path") or record.get("package_path") or "")
        ).name
        number = _package_number(candidate)
        if number is not None:
            by_number.setdefault(number, []).append(record)
    return by_number


def _manifest_entries(workspace: Path) -> list[dict[str, Any]]:
    workspace = Path(workspace).resolve()
    zdi = workspace / "ZDI"
    submitted = zdi / "_SUBMITTED"
    if not submitted.is_dir():
        raise PatchWatchError(f"submitted package root is missing: {submitted}")
    mailbox = _mailbox_submissions(workspace)
    entries: list[dict[str, Any]] = []
    candidates: dict[int, list[tuple[int, str, Path]]] = {}
    unnumbered: list[tuple[str, Path]] = []
    for root_name, disposition, priority in TERMINAL_SUBMISSION_ROOTS:
        root = zdi / root_name
        if not root.is_dir():
            continue
        for package in root.iterdir():
            if not package.is_dir():
                continue
            number = _package_number(package.name)
            if number is None:
                unnumbered.append((disposition, package))
                continue
            candidates.setdefault(number, []).append(
                (priority, disposition, package)
            )
    for number, locations in sorted(candidates.items()):
        locations.sort(key=lambda item: (item[0], item[2].name.casefold()))
        _, disposition, package = locations[-1]
        relative = package.relative_to(workspace).as_posix()
        title = _title_from_name(package.name)
        matching = list(mailbox.get(number, []))
        row = matching[0] if len(matching) == 1 else None
        expected_name = (
            Path(str(row.get("submitted_path") or row.get("package_path"))).name
            if row
            else ""
        )
        conflict = bool(
            len(matching) > 1
            or (
                row is not None
                and _title_from_name(expected_name).casefold() != title.casefold()
            )
            or len({_title_from_name(item[2].name).casefold() for item in locations}) > 1
        )
        product = str(row.get("product") or "").strip() if row else ""
        version = str(row.get("version") or "").strip() if row else ""
        submitted_at = str(row.get("submitted_at") or "").strip() if row else ""
        entry_id = hashlib.sha256(f"package:{number}".encode("utf-8")).hexdigest()[:24]
        product = product or _infer_product(title)
        entries.append(
            {
                "entry_id": entry_id,
                "package_number": number,
                "relative_path": relative,
                "title": title,
                "product": product,
                "version": version,
                "mailbox_item_id": int(row["id"]) if row else None,
                "submitted_at": submitted_at,
                "legacy_filesystem_only": row is None,
                "identity_conflict": conflict,
                "group_key": product.casefold(),
                "buyer_disposition": disposition,
                "duplicate_terminal_locations": [
                    item[2].relative_to(workspace).as_posix()
                    for item in sorted(locations, key=lambda value: value[2].as_posix())
                ],
            }
        )
    for disposition, package in sorted(
        unnumbered, key=lambda item: item[1].as_posix().casefold()
    ):
        relative = package.relative_to(workspace).as_posix()
        title = _title_from_name(package.name)
        product = _infer_product(title)
        entries.append(
            {
                "entry_id": hashlib.sha256(
                    f"path:{relative}".encode("utf-8")
                ).hexdigest()[:24],
                "package_number": None,
                "relative_path": relative,
                "title": title,
                "product": product,
                "version": "",
                "mailbox_item_id": None,
                "submitted_at": "",
                "legacy_filesystem_only": True,
                "identity_conflict": False,
                "group_key": product.casefold(),
                "buyer_disposition": disposition,
                "duplicate_terminal_locations": [relative],
            }
        )
    return entries


def _manifest_core(monday_date: date, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "jenny.weekly-patch-watch-manifest.v3",
        "monday_date": monday_date.isoformat(),
        "entries": entries,
    }


def _manifest_digest(monday_date: date, entries: list[dict[str, Any]]) -> str:
    stable_entries = [
        {
            "entry_id": entry["entry_id"],
            "package_number": entry["package_number"],
            "title": entry["title"],
            "product": entry["product"],
            "version": entry["version"],
            "identity_conflict": entry["identity_conflict"],
        }
        for entry in entries
    ]
    return hashlib.sha256(
        json.dumps(
            {
                "schema": "jenny.weekly-patch-watch-inventory.v1",
                "monday_date": monday_date.isoformat(),
                "entries": stable_entries,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _write_manifest(
    workspace: Path,
    monday_date: date,
    entries: list[dict[str, Any]],
    *,
    created_at: str,
) -> str:
    digest = _manifest_digest(monday_date, entries)
    manifest = {
        **_manifest_core(monday_date, entries),
        "created_at": created_at,
        "manifest_digest": digest,
        "total": len(entries),
    }
    _write_json(_run_root(workspace, monday_date) / "manifest.json", manifest)
    return digest


def start_run(
    workspace: Path,
    monday_date: date,
    *,
    started_early: bool = False,
) -> dict[str, Any]:
    if monday_date.weekday() != 0:
        raise PatchWatchError("run identity must be a local Monday date")
    existing = load_run(workspace, monday_date)
    if existing is not None:
        return existing
    entries = _manifest_entries(workspace)
    created_at = _iso_now()
    digest = _write_manifest(
        workspace,
        monday_date,
        entries,
        created_at=created_at,
    )
    manifest = {
        **_manifest_core(monday_date, entries),
        "created_at": created_at,
        "manifest_digest": digest,
        "total": len(entries),
    }
    connection = _connect(workspace)
    try:
        connection.execute(
            """
            INSERT INTO runs (
                monday_date, state, started_at, started_early, manifest_digest,
                total
            ) VALUES (?, 'RUNNING', ?, ?, ?, ?)
            """,
            (
                monday_date.isoformat(),
                manifest["created_at"],
                int(started_early),
                digest,
                len(entries),
            ),
        )
        for entry in entries:
            durable_placeholders = ", ".join(
                "?" for _ in DURABLE_PATCH_STATES
            )
            carried = connection.execute(
                f"""
                SELECT monday_date, status, result_json
                FROM entries
                WHERE entry_id = ?
                  AND monday_date < ?
                  AND status IN ({durable_placeholders})
                  AND result_json != ''
                ORDER BY monday_date DESC
                LIMIT 1
                """,
                (
                    entry["entry_id"],
                    monday_date.isoformat(),
                    *sorted(DURABLE_PATCH_STATES),
                ),
            ).fetchone()
            if carried is not None:
                try:
                    _validate_result(json.loads(str(carried["result_json"])))
                except (
                    json.JSONDecodeError,
                    PatchWatchError,
                    TypeError,
                ):
                    carried = None
            status = str(carried["status"]) if carried else "PENDING"
            result_json = str(carried["result_json"]) if carried else ""
            carried_from = str(carried["monday_date"]) if carried else ""
            connection.execute(
                """
                INSERT INTO entries (
                    monday_date, entry_id, package_number, relative_path, title,
                    product, version, mailbox_item_id, submitted_at,
                    legacy_filesystem_only, identity_conflict, group_key,
                    buyer_disposition, duplicate_terminal_locations_json,
                    status, result_json, carried_from_monday, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    monday_date.isoformat(),
                    entry["entry_id"],
                    entry["package_number"],
                    entry["relative_path"],
                    entry["title"],
                    entry["product"],
                    entry["version"],
                    entry["mailbox_item_id"],
                    entry["submitted_at"],
                    int(entry["legacy_filesystem_only"]),
                    int(entry["identity_conflict"]),
                    entry["group_key"],
                    entry["buyer_disposition"],
                    json.dumps(entry["duplicate_terminal_locations"], sort_keys=True),
                    status,
                    result_json,
                    carried_from,
                    manifest["created_at"],
                ),
            )
        connection.commit()
    finally:
        connection.close()
    return load_run(workspace, monday_date) or {}


def _sync_running_manifest(workspace: Path, monday_date: date) -> dict[str, Any]:
    """Reconcile a running scan with the current historical submission inventory."""

    run = load_run(workspace, monday_date)
    if run is None:
        raise PatchWatchError("patch-watch run does not exist")
    if run["state"] != "RUNNING":
        return run

    entries = _manifest_entries(workspace)
    existing_by_id = {str(entry["entry_id"]): entry for entry in run["entries"]}
    current_by_number = {
        int(entry["package_number"]): entry
        for entry in entries
        if entry["package_number"] is not None
    }
    existing_by_number = {
        int(entry["package_number"]): entry
        for entry in run["entries"]
        if entry["package_number"] is not None
    }
    missing_numbers = sorted(set(existing_by_number) - set(current_by_number))
    if missing_numbers:
        raise PatchWatchError(
            "historical submitted packages disappeared during the run: "
            + ", ".join(f"#{number}" for number in missing_numbers)
        )

    digest = _manifest_digest(monday_date, entries)
    # The stable digest deliberately ignores terminal archive placement and
    # buyer disposition so a SUBMITTED -> REJECTED move cannot invalidate a
    # completed research sweep.  We must still reconcile those display and
    # chronology fields into the current run, even when the research inventory
    # digest itself is unchanged.

    updated_at = _iso_now()
    connection = _connect(workspace)
    try:
        for entry in entries:
            entry_id = str(entry["entry_id"])
            existing = existing_by_id.get(entry_id)
            if existing is None and entry["package_number"] is not None:
                existing = existing_by_number.get(int(entry["package_number"]))
            if existing is not None:
                old_entry_id = str(existing["entry_id"])
                result_json = ""
                if existing.get("result") is not None:
                    migrated_result = dict(existing["result"])
                    migrated_result["entry_id"] = entry_id
                    result_json = json.dumps(migrated_result, sort_keys=True)
                connection.execute(
                    """
                    UPDATE entries
                    SET entry_id = ?, package_number = ?, relative_path = ?, title = ?,
                        product = ?, version = ?, mailbox_item_id = ?,
                        submitted_at = ?, legacy_filesystem_only = ?,
                        identity_conflict = ?, group_key = ?,
                        buyer_disposition = ?, result_json = ?,
                        duplicate_terminal_locations_json = ?, updated_at = ?
                    WHERE monday_date = ? AND entry_id = ?
                    """,
                    (
                        entry_id,
                        entry["package_number"],
                        entry["relative_path"],
                        entry["title"],
                        entry["product"],
                        entry["version"],
                        entry["mailbox_item_id"],
                        entry["submitted_at"],
                        int(entry["legacy_filesystem_only"]),
                        int(entry["identity_conflict"]),
                        entry["group_key"],
                        entry["buyer_disposition"],
                        result_json,
                        json.dumps(
                            entry["duplicate_terminal_locations"], sort_keys=True
                        ),
                        updated_at,
                        monday_date.isoformat(),
                        old_entry_id,
                    ),
                )
                continue

            connection.execute(
                """
                INSERT INTO entries (
                    monday_date, entry_id, package_number, relative_path, title,
                    product, version, mailbox_item_id, submitted_at,
                    legacy_filesystem_only, identity_conflict, group_key,
                    buyer_disposition, duplicate_terminal_locations_json,
                    status, result_json, carried_from_monday, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'PENDING', '', '', ?)
                """,
                (
                    monday_date.isoformat(),
                    entry_id,
                    entry["package_number"],
                    entry["relative_path"],
                    entry["title"],
                    entry["product"],
                    entry["version"],
                    entry["mailbox_item_id"],
                    entry["submitted_at"],
                    int(entry["legacy_filesystem_only"]),
                    int(entry["identity_conflict"]),
                    entry["group_key"],
                    entry["buyer_disposition"],
                    json.dumps(entry["duplicate_terminal_locations"], sort_keys=True),
                    updated_at,
                ),
            )
        connection.execute(
            """
            UPDATE runs
            SET manifest_digest = ?, total = ?
            WHERE monday_date = ? AND state = 'RUNNING'
            """,
            (digest, len(entries), monday_date.isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    _write_manifest(
        workspace,
        monday_date,
        entries,
        created_at=str(run["started_at"]),
    )
    return load_run(workspace, monday_date) or {}


def _row_to_entry(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["legacy_filesystem_only"] = bool(value["legacy_filesystem_only"])
    value["identity_conflict"] = bool(value["identity_conflict"])
    raw_result = value.pop("result_json")
    raw_locations = value.pop("duplicate_terminal_locations_json", "[]")
    value["duplicate_terminal_locations"] = json.loads(raw_locations or "[]")
    value["result"] = json.loads(raw_result) if raw_result else None
    return value


def load_run(workspace: Path, monday_date: date) -> dict[str, Any] | None:
    path = _database_path(workspace)
    if not path.is_file():
        return None
    connection = _connect(workspace)
    try:
        run = connection.execute(
            "SELECT * FROM runs WHERE monday_date = ?",
            (monday_date.isoformat(),),
        ).fetchone()
        if run is None:
            return None
        rows = connection.execute(
            """
            SELECT * FROM entries
            WHERE monday_date = ?
            ORDER BY group_key, package_number, relative_path
            """,
            (monday_date.isoformat(),),
        ).fetchall()
    finally:
        connection.close()
    value = dict(run)
    value["started_early"] = bool(value["started_early"])
    value["entries"] = [_row_to_entry(row) for row in rows]
    value["conflicts"] = sum(
        1 for entry in value["entries"] if entry["identity_conflict"]
    )
    value["completed"] = sum(
        1 for entry in value["entries"] if entry["status"] in TERMINAL_STATES
    )
    return value


def batch_entries(
    workspace: Path,
    monday_date: date,
    *,
    max_groups: int = 4,
    max_entries: int = 20,
) -> dict[str, Any]:
    if max_groups <= 0 or max_entries <= 0:
        raise PatchWatchError("batch limits must be positive")
    run = _sync_running_manifest(workspace, monday_date)
    selected: list[dict[str, Any]] = []
    groups: list[str] = []
    for entry in run["entries"]:
        if entry["status"] != "PENDING":
            continue
        group = str(entry["group_key"])
        if group not in groups:
            if len(groups) >= max_groups:
                continue
            groups.append(group)
        if len(selected) >= max_entries:
            break
        selected.append(
            {
                key: entry[key]
                for key in (
                    "entry_id",
                    "package_number",
                    "relative_path",
                    "title",
                    "product",
                    "version",
                    "submitted_at",
                    "legacy_filesystem_only",
                    "identity_conflict",
                    "group_key",
                    "buyer_disposition",
                    "duplicate_terminal_locations",
                )
            }
        )
    return {
        "monday_date": monday_date.isoformat(),
        "manifest_digest": run["manifest_digest"],
        "total": run["total"],
        "completed": run["completed"],
        "groups": groups,
        "entries": selected,
    }


def _valid_url(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _validate_research_coverage(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "repository_kind",
        "root_tokens",
        "checks",
    }:
        raise PatchWatchError("research_coverage is invalid")
    repository_kind = str(value["repository_kind"])
    if repository_kind not in REPOSITORY_KINDS:
        raise PatchWatchError("research_coverage repository_kind is invalid")
    root_tokens = value["root_tokens"]
    if (
        not isinstance(root_tokens, list)
        or not 2 <= len(root_tokens) <= 12
        or any(
            not isinstance(token, str)
            or not token.strip()
            or len(token.strip()) > 120
            for token in root_tokens
        )
    ):
        raise PatchWatchError("research_coverage root_tokens are invalid")
    checks = value["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= len(SOURCE_CLASSES):
        raise PatchWatchError("research_coverage checks are invalid")
    normalized_checks: list[dict[str, Any]] = []
    seen_classes: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != {
            "source_class",
            "status",
            "query",
            "urls",
        }:
            raise PatchWatchError("research_coverage check is invalid")
        source_class = str(check["source_class"])
        if source_class not in SOURCE_CLASSES or source_class in seen_classes:
            raise PatchWatchError("research_coverage source_class is invalid")
        seen_classes.add(source_class)
        check_status = str(check["status"])
        if check_status not in SOURCE_CHECK_STATES:
            raise PatchWatchError("research_coverage check status is invalid")
        query = str(check["query"]).strip()
        urls = check["urls"]
        if (
            not isinstance(urls, list)
            or len(urls) > 10
            or any(not _valid_url(url) for url in urls)
        ):
            raise PatchWatchError("research_coverage check URLs are invalid")
        if check_status == "CHECKED" and (not query or not urls):
            raise PatchWatchError(
                "checked research_coverage requires a query and URL"
            )
        normalized_checks.append(
            {
                "source_class": source_class,
                "status": check_status,
                "query": query,
                "urls": list(dict.fromkeys(str(url) for url in urls)),
            }
        )
    return {
        "repository_kind": repository_kind,
        "root_tokens": list(
            dict.fromkeys(str(token).strip() for token in root_tokens)
        ),
        "checks": normalized_checks,
    }


def _require_complete_research(coverage: dict[str, Any]) -> None:
    checks = {
        str(check["source_class"]): check for check in coverage["checks"]
    }
    if set(checks) != SOURCE_CLASSES:
        raise PatchWatchError("incomplete source coverage")
    required_checked = {"RELEASES", "ADVISORIES", "PUBLIC_WEB"}
    if coverage["repository_kind"] == "PUBLIC":
        required_checked |= {"ISSUES", "PULL_REQUESTS", "COMMITS"}
    for source_class in required_checked:
        if checks[source_class]["status"] != "CHECKED":
            raise PatchWatchError("incomplete source coverage")
    if coverage["repository_kind"] == "CLOSED":
        for source_class in {"ISSUES", "PULL_REQUESTS", "COMMITS"}:
            if checks[source_class]["status"] not in {
                "CHECKED",
                "NOT_APPLICABLE",
            }:
                raise PatchWatchError("incomplete source coverage")
    root_tokens = [
        str(token).casefold() for token in coverage["root_tokens"]
    ]
    for check in checks.values():
        if check["status"] != "CHECKED":
            continue
        query = str(check["query"]).casefold()
        if not any(token in query for token in root_tokens):
            raise PatchWatchError(
                "source coverage query is not root-specific"
            )


def _validate_result(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PatchWatchError("each result must be an object")
    required = {
        "entry_id",
        "status",
        "summary",
        "confidence",
        "checked_at",
        "source_urls",
        "chronology",
        "research_coverage",
    }
    if set(value) != required:
        raise PatchWatchError("result keys do not match the required schema")
    entry_id = str(value["entry_id"])
    if not re.fullmatch(r"[0-9a-f]{24}", entry_id):
        raise PatchWatchError("entry_id is invalid")
    status = str(value["status"])
    if status not in TERMINAL_STATES:
        raise PatchWatchError("status is not terminal")
    summary = str(value["summary"]).strip()
    if not summary or len(summary) > 1200:
        raise PatchWatchError("summary has an invalid length")
    confidence = str(value["confidence"])
    if confidence not in CONFIDENCE:
        raise PatchWatchError("confidence is invalid")
    try:
        checked_at = datetime.fromisoformat(str(value["checked_at"]))
    except ValueError as error:
        raise PatchWatchError("checked_at must be ISO-8601") from error
    if checked_at.tzinfo is None:
        raise PatchWatchError("checked_at must include a timezone")
    checked_at = checked_at.astimezone(UTC)
    if checked_at > _utc_now() + timedelta(minutes=5):
        raise PatchWatchError("checked_at cannot be in the future")
    source_urls = value["source_urls"]
    if not isinstance(source_urls, list) or len(source_urls) > 20:
        raise PatchWatchError("source_urls must be a bounded list")
    if any(not _valid_url(url) for url in source_urls):
        raise PatchWatchError("source_urls contains an invalid URL")
    if status not in {"SOURCE_UNAVAILABLE", "RECORD_INCOMPLETE"} and not source_urls:
        raise PatchWatchError("source_urls is required for this result")
    chronology = value["chronology"]
    if not isinstance(chronology, dict) or set(chronology) != {
        "submission_at",
        "public_change_at",
        "relationship",
    }:
        raise PatchWatchError("chronology is invalid")
    relationship = str(chronology["relationship"])
    if relationship not in RELATIONSHIPS:
        raise PatchWatchError("chronology relationship is invalid")
    if status in PATCH_MATCH_STATES and relationship == "NO_MATCH":
        raise PatchWatchError("patch matches require a chronology relationship")
    if status in {
        "LIKELY_EXACT_FIX",
        "FIX_RELEASED_AFTER_SUBMISSION",
        "PUBLIC_AFTER_SUBMISSION",
        "PUBLIC_BEFORE_SUBMISSION",
    } and not str(chronology["public_change_at"]).strip():
        raise PatchWatchError("exact patch matches require public_change_at")
    research_coverage = _validate_research_coverage(
        value["research_coverage"]
    )
    if status not in {"SOURCE_UNAVAILABLE", "RECORD_INCOMPLETE"}:
        _require_complete_research(research_coverage)
    return {
        "entry_id": entry_id,
        "status": status,
        "summary": summary,
        "confidence": confidence,
        "checked_at": checked_at.isoformat(),
        "source_urls": list(dict.fromkeys(str(url) for url in source_urls)),
        "chronology": {
            "submission_at": str(chronology["submission_at"]).strip(),
            "public_change_at": str(chronology["public_change_at"]).strip(),
            "relationship": relationship,
        },
        "research_coverage": research_coverage,
    }


def _parse_chronology_timestamp(value: str, field: str) -> datetime | None:
    raw = str(value).strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as error:
        raise PatchWatchError(f"{field} must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise PatchWatchError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _derived_relationship(
    submission_at: datetime | None,
    public_change_at: datetime,
) -> str:
    if submission_at is None:
        return "UNKNOWN"
    if public_change_at.date() == submission_at.date():
        return "SAME_DAY"
    if public_change_at < submission_at:
        return "PREDATES_SUBMISSION"
    return "POSTDATES_SUBMISSION"


def _bind_result_chronology(
    result: dict[str, Any],
    authoritative_submission_at: str,
) -> dict[str, Any]:
    chronology = dict(result["chronology"])
    supplied_submission = _parse_chronology_timestamp(
        chronology["submission_at"], "submission_at"
    )
    authoritative_submission = _parse_chronology_timestamp(
        authoritative_submission_at, "authoritative submission_at"
    )
    if (
        supplied_submission is not None
        and authoritative_submission is not None
        and supplied_submission != authoritative_submission
    ):
        raise PatchWatchError(
            "chronology submission_at does not match authoritative submission_at"
        )
    submission_at = authoritative_submission or supplied_submission
    public_change_at = _parse_chronology_timestamp(
        chronology["public_change_at"], "public_change_at"
    )
    checked_at = datetime.fromisoformat(result["checked_at"]).astimezone(UTC)
    if submission_at is not None and submission_at > checked_at:
        raise PatchWatchError("submission_at cannot be after checked_at")
    if public_change_at is not None and public_change_at > checked_at:
        raise PatchWatchError("public_change_at cannot be after checked_at")

    status = result["status"]
    supplied_relationship = chronology["relationship"]
    if status in PATCH_MATCH_STATES:
        if public_change_at is None:
            raise PatchWatchError("patch matches require public_change_at")
        relationship = _derived_relationship(submission_at, public_change_at)
        if supplied_relationship != relationship:
            raise PatchWatchError(
                "chronology relationship contradicts authoritative timestamps"
            )
        allowed_by_status = {
            "PUBLIC_BEFORE_SUBMISSION": {
                "PREDATES_SUBMISSION",
                "SAME_DAY",
            },
            "PUBLIC_AFTER_SUBMISSION": {
                "POSTDATES_SUBMISSION",
                "SAME_DAY",
            },
            "FIX_RELEASED_AFTER_SUBMISSION": {
                "POSTDATES_SUBMISSION",
                "SAME_DAY",
            },
        }
        if status in allowed_by_status and relationship not in allowed_by_status[status]:
            raise PatchWatchError(
                "result status contradicts authoritative chronology"
            )
    elif status == "NO_PUBLIC_CHANGE":
        relationship = "NO_MATCH"
        if supplied_relationship != relationship:
            raise PatchWatchError(
                "NO_PUBLIC_CHANGE requires NO_MATCH chronology"
            )
    else:
        relationship = supplied_relationship
        if relationship not in {"NO_MATCH", "UNKNOWN"}:
            raise PatchWatchError(
                "incomplete results require NO_MATCH or UNKNOWN chronology"
            )

    bound = dict(result)
    bound["chronology"] = {
        "submission_at": submission_at.isoformat() if submission_at else "",
        "public_change_at": (
            public_change_at.isoformat() if public_change_at else ""
        ),
        "relationship": relationship,
    }
    return bound


def _write_result_artifacts(workspace: Path, monday_date: date) -> None:
    run = load_run(workspace, monday_date)
    if run is None:
        raise PatchWatchError("patch-watch run does not exist")
    results = [
        entry["result"]
        for entry in run["entries"]
        if entry["result"] is not None
    ]
    root = _run_root(workspace, monday_date)
    results_body = "".join(
        json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n"
        for result in results
    )
    _atomic_write(root / "results.jsonl", results_body.encode("utf-8"))
    sources = []
    for result in results:
        for url in result["source_urls"]:
            sources.append(
                {
                    "entry_id": result["entry_id"],
                    "checked_at": result["checked_at"],
                    "url": url,
                }
            )
    sources_body = "".join(
        json.dumps(source, ensure_ascii=True, sort_keys=True) + "\n"
        for source in sources
    )
    _atomic_write(root / "sources.jsonl", sources_body.encode("utf-8"))


def record_results(
    workspace: Path,
    monday_date: date,
    payload: object,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "monday_date",
        "results",
    }:
        raise PatchWatchError("result payload does not match the required schema")
    if payload["schema"] != RESULT_SCHEMA:
        raise PatchWatchError("result payload schema is invalid")
    if payload["monday_date"] != monday_date.isoformat():
        raise PatchWatchError("result payload Monday does not match the run")
    raw_results = payload["results"]
    if not isinstance(raw_results, list) or not raw_results:
        raise PatchWatchError("results must be a non-empty list")
    results = [_validate_result(result) for result in raw_results]
    ids = [result["entry_id"] for result in results]
    if len(ids) != len(set(ids)):
        raise PatchWatchError("result payload contains duplicate entry IDs")
    connection = _connect(workspace)
    try:
        run = connection.execute(
            "SELECT state FROM runs WHERE monday_date = ?",
            (monday_date.isoformat(),),
        ).fetchone()
        if run is None or run["state"] != "RUNNING":
            raise PatchWatchError("run is not accepting results")
        for result in results:
            row = connection.execute(
                """
                SELECT status, result_json, submitted_at FROM entries
                WHERE monday_date = ? AND entry_id = ?
                """,
                (monday_date.isoformat(), result["entry_id"]),
            ).fetchone()
            if row is None:
                raise PatchWatchError(
                    f"unknown manifest entry: {result['entry_id']}"
                )
            result = _bind_result_chronology(result, str(row["submitted_at"]))
            rendered = json.dumps(
                result, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            if row["status"] in TERMINAL_STATES:
                if row["result_json"] != rendered:
                    raise PatchWatchError(
                        f"terminal result drift for {result['entry_id']}"
                    )
                continue
            connection.execute(
                """
                UPDATE entries
                SET status = ?, result_json = ?, updated_at = ?
                WHERE monday_date = ? AND entry_id = ?
                """,
                (
                    result["status"],
                    rendered,
                    _iso_now(),
                    monday_date.isoformat(),
                    result["entry_id"],
                ),
            )
        connection.commit()
    finally:
        connection.close()
    _write_result_artifacts(workspace, monday_date)
    run_value = load_run(workspace, monday_date)
    assert run_value is not None
    return {
        "monday_date": monday_date.isoformat(),
        "recorded": len(results),
        "completed": run_value["completed"],
        "total": run_value["total"],
    }


def _report_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    statuses = Counter(str(entry["status"]) for entry in entries)
    return {
        "total": len(entries),
        "database_backed": sum(
            1 for entry in entries if not entry["legacy_filesystem_only"]
        ),
        "legacy_filesystem_only": sum(
            1 for entry in entries if entry["legacy_filesystem_only"]
        ),
        "identity_conflicts": sum(
            1 for entry in entries if entry["identity_conflict"]
        ),
        "chronology_gaps": sum(
            1
            for entry in entries
            if not entry["submitted_at"]
            or (
                entry["result"]
                and entry["result"]["status"] in PATCH_MATCH_STATES
                and not entry["result"]["chronology"]["submission_at"]
            )
        ),
        "no_public_change": statuses["NO_PUBLIC_CHANGE"],
        "possible_fix": statuses["POSSIBLE_FIX"],
        "likely_exact_fix": statuses["LIKELY_EXACT_FIX"],
        "fix_released_after_submission": statuses[
            "FIX_RELEASED_AFTER_SUBMISSION"
        ],
        "public_after_submission": statuses["PUBLIC_AFTER_SUBMISSION"],
        "public_before_submission": statuses["PUBLIC_BEFORE_SUBMISSION"],
        "source_unavailable": statuses["SOURCE_UNAVAILABLE"],
        "record_incomplete": statuses["RECORD_INCOMPLETE"],
    }


def _report_text(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "WEEKLY SUBMITTED PATCH WATCH",
        "",
        f"Monday: {report['monday_date']}",
        f"Generated: {report['generated_at_local']}",
        f"Coverage: {counts['total']} / {counts['total']}",
        f"Database-backed: {counts['database_backed']}",
        f"Legacy filesystem-only: {counts['legacy_filesystem_only']}",
        f"Likely exact fixes: {counts['likely_exact_fix']}",
        f"Fixes released after submission: {counts['fix_released_after_submission']}",
        f"Public disclosures after submission: {counts['public_after_submission']}",
        f"Possible fixes: {counts['possible_fix']}",
        f"Public before submission: {counts['public_before_submission']}",
        f"Source gaps: {counts['source_unavailable']}",
        f"Record gaps: {counts['record_incomplete']}",
        f"Identity conflicts: {counts['identity_conflicts']}",
        "",
        report["headline"],
    ]
    for alert in report["alerts"]:
        lines.extend(
            [
                "",
                f"#{alert.get('package_number') or '-'} {alert['title']}",
                f"State: {alert['status']}",
                alert["summary"],
            ]
        )
        lines.extend(f"Source: {url}" for url in alert["source_urls"])
    return "\n".join(lines).rstrip() + "\n"


def _coverage_is_complete(result: dict[str, Any]) -> bool:
    try:
        _require_complete_research(result["research_coverage"])
    except PatchWatchError:
        return False
    return True


def _coverage_audit(run: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    audited_packages = 0
    complete_research = 0
    for entry in run["entries"]:
        result = entry["result"]
        if result is None:
            continue
        audited_packages += 1
        research_complete = _coverage_is_complete(result)
        if research_complete:
            complete_research += 1
        grouped.setdefault(entry["product"], []).append(
            {
                "package_number": entry["package_number"],
                "title": entry["title"],
                "entry_id": entry["entry_id"],
                "status": result["status"],
                "checked_at": result["checked_at"],
                "research_complete": research_complete,
                "research_coverage": result["research_coverage"],
            }
        )
    products = [
        {
            "product": product,
            "package_count": len(packages),
            "packages": sorted(
                packages,
                key=lambda item: (
                    item["package_number"] is None,
                    (
                        int(item["package_number"])
                        if item["package_number"] is not None
                        else 0
                    ),
                    str(item["title"]).casefold(),
                ),
            ),
        }
        for product, packages in sorted(
            grouped.items(), key=lambda item: item[0].casefold()
        )
    ]
    total = len(run["entries"])
    return {
        "schema": "jenny.weekly-patch-watch-coverage-audit.v1",
        "monday_date": run["monday_date"],
        "manifest_digest": run["manifest_digest"],
        "total_packages": total,
        "audited_packages": audited_packages,
        "complete_research_packages": complete_research,
        "product_count": len(products),
        "all_entries_complete": audited_packages == total,
        "products": products,
    }


def _coverage_audit_text(audit: dict[str, Any]) -> str:
    lines = [
        "WEEKLY PATCH WATCH COVERAGE AUDIT",
        "",
        f"Monday: {audit['monday_date']}",
        f"Manifest digest: {audit['manifest_digest']}",
        (
            f"Packages audited: {audit['audited_packages']} / "
            f"{audit['total_packages']}"
        ),
        f"Products audited: {audit['product_count']}",
        (
            "Full required source coverage: "
            f"{audit['complete_research_packages']} / "
            f"{audit['total_packages']}"
        ),
    ]
    for product in audit["products"]:
        lines.extend(["", f"PRODUCT: {product['product']}"])
        for package in product["packages"]:
            coverage = package["research_coverage"]
            checked = sum(
                1
                for check in coverage["checks"]
                if check["status"] == "CHECKED"
            )
            lines.append(
                f"Package #{package['package_number']}: {package['title']}"
            )
            lines.append(
                f"  Result: {package['status']} at {package['checked_at']}"
            )
            lines.append(
                f"  Coverage: {checked}/6 source classes; "
                f"repository={coverage['repository_kind']}; "
                f"complete={str(package['research_complete']).lower()}"
            )
            lines.append(
                "  Root tokens: " + ", ".join(coverage["root_tokens"])
            )
            for check in coverage["checks"]:
                urls = ", ".join(check["urls"]) or "-"
                query = check["query"] or "-"
                lines.append(
                    f"  {check['source_class']}: {check['status']} | "
                    f"query={query} | urls={urls}"
                )
    return "\n".join(lines).rstrip() + "\n"


def finalize_run(workspace: Path, monday_date: date) -> Path:
    run = _sync_running_manifest(workspace, monday_date)
    incomplete = [
        entry for entry in run["entries"] if entry["status"] not in TERMINAL_STATES
    ]
    if incomplete:
        raise PatchWatchError(
            f"run is incomplete: {len(incomplete)} manifest entries remain"
        )
    counts = _report_counts(run["entries"])
    alerts = []
    for entry in run["entries"]:
        result = entry["result"]
        assert result is not None
        if (
            result["status"]
            in {
                "POSSIBLE_FIX",
                "LIKELY_EXACT_FIX",
                "FIX_RELEASED_AFTER_SUBMISSION",
                "PUBLIC_AFTER_SUBMISSION",
                "PUBLIC_BEFORE_SUBMISSION",
                "SOURCE_UNAVAILABLE",
            }
            or (
                result["status"] == "NO_PUBLIC_CHANGE"
                and bool(result["chronology"]["public_change_at"])
            )
            or entry["identity_conflict"]
        ):
            alerts.append(
                {
                    "entry_id": entry["entry_id"],
                    "package_number": entry["package_number"],
                    "title": entry["title"],
                    "product": entry["product"],
                    "status": result["status"],
                    "summary": result["summary"],
                    "confidence": result["confidence"],
                    "source_urls": result["source_urls"],
                    "chronology": result["chronology"],
                    "identity_conflict": entry["identity_conflict"],
                }
            )
    current = _utc_now()
    local = current.astimezone()
    window_start, window_end = _calendar_window(monday_date)
    headline = (
        f"{counts['total']} submitted packages checked; "
        f"{counts['likely_exact_fix'] + counts['fix_released_after_submission']} "
        "likely public fixes, "
        f"{counts['public_after_submission']} public disclosures after submission, "
        f"{counts['possible_fix']} possible matches, "
        f"{counts['source_unavailable'] + counts['identity_conflicts']} operational gaps"
    )
    report = {
        "schema": REPORT_SCHEMA,
        "monday_date": monday_date.isoformat(),
        "generated_at": current.isoformat(),
        "generated_at_local": local.isoformat(),
        "window_start_date": window_start.isoformat(),
        "window_end_date": window_end.isoformat(),
        "manifest_digest": run["manifest_digest"],
        "state": "COMPLETED",
        "acknowledged_at": run["acknowledged_at"],
        "headline": headline,
        "counts": counts,
        "alerts": alerts,
    }
    root = _run_root(workspace, monday_date)
    report_path = root / "WEEKLY_REPORT.json"
    _write_json(report_path, report)
    _atomic_write(root / "WEEKLY_REPORT.txt", _report_text(report).encode("utf-8"))
    audit = _coverage_audit(run)
    _write_json(root / "COVERAGE_AUDIT.json", audit)
    _atomic_write(
        root / "COVERAGE_AUDIT.txt",
        _coverage_audit_text(audit).encode("utf-8"),
    )
    latest = load_weekly_report(workspace)
    if (
        latest is None
        or date.fromisoformat(str(latest["monday_date"])) <= monday_date
    ):
        _write_json(_watch_root(workspace) / LATEST_REPORT_NAME, report)
    connection = _connect(workspace)
    try:
        connection.execute(
            """
            UPDATE runs
            SET state = 'COMPLETED', completed_at = ?
            WHERE monday_date = ?
            """,
            (current.isoformat(), monday_date.isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    return report_path


def _load_report_file(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("schema"), str)
        or REPORT_SCHEMA_RE.fullmatch(str(value["schema"])) is None
        or value.get("state") != "COMPLETED"
        or not isinstance(value.get("counts"), dict)
        or not isinstance(value.get("alerts"), list)
    ):
        return None
    return value


def load_weekly_report(workspace: Path) -> dict[str, Any] | None:
    return _load_report_file(_watch_root(workspace) / LATEST_REPORT_NAME)


def acknowledge_run(
    workspace: Path,
    monday_date: date,
    manifest_digest: str,
) -> dict[str, str]:
    """Record one durable, hash-bound operator acknowledgement."""
    if re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None:
        raise PatchWatchError("manifest digest is invalid")
    connection = _connect(workspace)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT state, manifest_digest, acknowledged_at
            FROM runs
            WHERE monday_date = ?
            """,
            (monday_date.isoformat(),),
        ).fetchone()
        if row is None:
            raise PatchWatchError("patch-watch run does not exist")
        if str(row["state"]) != "COMPLETED":
            raise PatchWatchError("patch-watch run is not complete")
        if str(row["manifest_digest"]) != manifest_digest:
            raise PatchWatchError("manifest digest changed")
        acknowledged_at = str(row["acknowledged_at"])
        if not acknowledged_at:
            acknowledged_at = _iso_now()
            connection.execute(
                """
                UPDATE runs
                SET acknowledged_at = ?
                WHERE monday_date = ? AND manifest_digest = ?
                """,
                (acknowledged_at, monday_date.isoformat(), manifest_digest),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {
        "state": "ACKNOWLEDGED",
        "monday_date": monday_date.isoformat(),
        "manifest_digest": manifest_digest,
        "acknowledged_at": acknowledged_at,
    }


def load_dashboard_status(workspace: Path) -> dict[str, Any] | None:
    database = _database_path(workspace)
    report = load_weekly_report(workspace)
    if not database.is_file():
        return (
            {
                "state": "COMPLETED",
                "monday_date": str(report["monday_date"]),
                "started_at": "",
                "completed_at": str(report["generated_at"]),
                "window_started_at": _dashboard_window(
                    date.fromisoformat(str(report["monday_date"]))
                )[0],
                "window_ended_at": _dashboard_window(
                    date.fromisoformat(str(report["monday_date"]))
                )[1],
                "manifest_digest": str(report["manifest_digest"]),
                "acknowledged_at": str(report.get("acknowledged_at", "")),
                "total": int(report["counts"]["total"]),
                "completed": int(report["counts"]["total"]),
                "remaining": 0,
                "report": report,
            }
            if report
            else None
        )
    connection = _connect(workspace)
    try:
        row = connection.execute(
            """
            SELECT *
            FROM runs
            ORDER BY monday_date DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return None
    run = load_run(workspace, date.fromisoformat(str(row["monday_date"])))
    if run is None:
        return None
    exact_report = _load_report_file(
        _run_root(workspace, date.fromisoformat(str(run["monday_date"])))
        / "WEEKLY_REPORT.json"
    )
    current_report = (
        dict(exact_report)
        if exact_report
        and exact_report.get("monday_date") == run["monday_date"]
        else None
    )
    acknowledged_at = str(run["acknowledged_at"])
    if current_report is not None:
        current_report["acknowledged_at"] = acknowledged_at
    monday = date.fromisoformat(str(run["monday_date"]))
    window_started_at, window_ended_at = _dashboard_window(monday)
    return {
        "state": str(run["state"]),
        "monday_date": str(run["monday_date"]),
        "started_at": str(run["started_at"]),
        "completed_at": str(run["completed_at"]),
        "window_started_at": window_started_at,
        "window_ended_at": window_ended_at,
        "manifest_digest": str(run["manifest_digest"]),
        "acknowledged_at": acknowledged_at,
        "total": int(run["total"]),
        "completed": int(run["completed"]),
        "remaining": int(run["total"]) - int(run["completed"]),
        "report": current_report,
    }


def _parse_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from error
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_DEFAULT)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("due")
    start = commands.add_parser("start")
    start.add_argument("--monday-date", type=_parse_date, required=True)
    start.add_argument("--started-early", action="store_true")
    batch = commands.add_parser("batch")
    batch.add_argument("--monday-date", type=_parse_date, required=True)
    batch.add_argument("--max-groups", type=int, default=4)
    batch.add_argument("--max-entries", type=int, default=20)
    record = commands.add_parser("record")
    record.add_argument("--monday-date", type=_parse_date, required=True)
    record.add_argument("--input", type=Path, required=True)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--monday-date", type=_parse_date, required=True)
    acknowledge = commands.add_parser("acknowledge")
    acknowledge.add_argument("--monday-date", type=_parse_date, required=True)
    acknowledge.add_argument("--manifest-digest", required=True)
    status = commands.add_parser("status")
    status.add_argument("--monday-date", type=_parse_date, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "due":
            value = weekly_due(args.workspace)
        elif args.command == "start":
            value = start_run(
                args.workspace,
                args.monday_date,
                started_early=args.started_early,
            )
        elif args.command == "batch":
            value = batch_entries(
                args.workspace,
                args.monday_date,
                max_groups=args.max_groups,
                max_entries=args.max_entries,
            )
        elif args.command == "record":
            payload = json.loads(args.input.read_text(encoding="utf-8"))
            value = record_results(args.workspace, args.monday_date, payload)
        elif args.command == "finalize":
            value = {"report_path": str(finalize_run(args.workspace, args.monday_date))}
        elif args.command == "acknowledge":
            value = acknowledge_run(
                args.workspace,
                args.monday_date,
                args.manifest_digest,
            )
        elif args.command == "status":
            value = load_run(args.workspace, args.monday_date)
            if value is None:
                raise PatchWatchError("patch-watch run does not exist")
        else:
            return 2
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        PatchWatchError,
        sqlite3.Error,
    ) as error:
        print(f"patch watch failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    raise SystemExit(main())
