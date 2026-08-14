from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mailbox_wait import (  # noqa: E402
    DEFAULT_TRANSIENT_IO_ERROR_LIMIT,
    OWNER_GONE_DETAIL,
    connect_read_only,
    file_signature,
    is_transient_sqlite_io_error,
    process_is_alive,
)
from bounded_repair_contract import extract_repair_input_path  # noqa: E402


WORKSPACE = Path(__file__).resolve().parents[2]
DEFAULT_COORDINATION_DB = (
    WORKSPACE / "notes" / "coordination_inbox" / "coordination.sqlite3"
)
def find_ready_work(database: str | Path) -> dict | None:
    connection = connect_read_only(Path(database))
    try:
        try:
            candidate = connection.execute(
                """
                SELECT id, candidate_key, candidate_title, product, version,
                       target_slug, state, reviewer, updated_at
                FROM candidate_challenges
                WHERE state = 'PENDING'
                   OR (state = 'CLAIMED' AND reviewer = 'midlane')
                ORDER BY updated_at, id
                LIMIT 1
                """
            ).fetchone()
        except sqlite3.OperationalError:
            candidate = None
        if candidate is not None:
            return {
                "event": "MIDLANE_WORK_READY",
                "kind": "CANDIDATE_CHALLENGE",
                "candidate": dict(candidate),
            }

        try:
            mechanical_rows = connection.execute(
                """
                SELECT r.id, r.work_item_id, r.reviewed_hash,
                       r.reviewed_revision, r.issues_json, r.review_scope,
                       r.state, r.created_at,
                       w.package_path, w.product, w.version,
                       w.package_hash, w.revision, w.updated_at
                FROM final_rework_requests AS r
                JOIN work_items AS w ON w.id = r.work_item_id
                WHERE r.state = 'OPEN'
                  AND r.review_scope = 'MECHANICAL'
                  AND w.state = 'FINAL_REWORK_QUEUED'
                ORDER BY r.created_at, r.id
                """
            ).fetchall()
        except sqlite3.OperationalError:
            mechanical_rows = []
        for row in mechanical_rows:
            request = dict(row)
            try:
                issues = json.loads(request.pop("issues_json"))
            except (TypeError, json.JSONDecodeError):
                continue
            repair_input_path = extract_repair_input_path(issues)
            if repair_input_path is None:
                continue
            request["issues"] = issues
            request["repair_input_path"] = repair_input_path
            return {
                "event": "MIDLANE_WORK_READY",
                "kind": "MECHANICAL_FINAL_REWORK",
                "request": request,
            }

        item = connection.execute(
            """
            SELECT id, package_path, product, version, package_hash,
                   state, revision, updated_at
            FROM work_items
            WHERE state IN (
                'HUNTER_REFINED', 'MIDLANE_REVIEWING', 'READY_FOR_MIDLANE'
            )
            ORDER BY updated_at, id
            LIMIT 1
            """
        ).fetchone()
        if item is None:
            return None
        return {
            "event": "MIDLANE_WORK_READY",
            "kind": "PACKAGE",
            "item": dict(item),
        }
    finally:
        connection.close()


def find_ready_coordination(database: str | Path) -> dict | None:
    path = Path(database)
    if not path.is_file():
        return None
    connection = connect_read_only(path)
    try:
        try:
            message = connection.execute(
                """
                SELECT id, revision, sender, recipient, context_ref, body,
                       status, created_at, updated_at
                FROM coordination_chat_messages
                WHERE sender = 'operator'
                  AND recipient = 'midlane'
                  AND status = 'OPEN'
                ORDER BY created_at, id
                LIMIT 1
                """
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        if message is None:
            return None
        return {
            "event": "MIDLANE_WORK_READY",
            "kind": "COORDINATION_CHAT",
            "message": dict(message),
        }
    finally:
        connection.close()


def wait_for_event(
    database: str | Path,
    watch_file: str | Path,
    *,
    coordination_database: str | Path = DEFAULT_COORDINATION_DB,
    timeout_seconds: float,
    poll_seconds: float,
    sleeper: Callable[[float], None] = time.sleep,
    owner_pid: int | None = None,
    owner_alive: Callable[[int], bool] = process_is_alive,
    max_transient_io_errors: int = DEFAULT_TRANSIENT_IO_ERROR_LIMIT,
) -> dict:
    if timeout_seconds < 0:
        raise ValueError("timeout_seconds must be non-negative")
    if poll_seconds <= 0:
        raise ValueError("poll_seconds must be positive")
    if max_transient_io_errors < 0:
        raise ValueError("max_transient_io_errors must be non-negative")

    watched = Path(watch_file).resolve()
    initial_signature = file_signature(watched)
    deadline = time.monotonic() + timeout_seconds
    consecutive_io_errors = 0
    while True:
        if owner_pid is not None and not owner_alive(owner_pid):
            return {
                "event": "OWNER_GONE",
                "owner_pid": owner_pid,
                "detail": OWNER_GONE_DETAIL,
            }
        if file_signature(watched) != initial_signature:
            return {"event": "CONFIG_CHANGED", "watch_file": str(watched)}
        try:
            ready = find_ready_work(database)
            if ready is not None:
                return ready
            coordination = find_ready_coordination(coordination_database)
            if coordination is not None:
                return coordination
        except sqlite3.Error as error:
            if not is_transient_sqlite_io_error(error):
                raise
            consecutive_io_errors += 1
            remaining = deadline - time.monotonic()
            if (
                consecutive_io_errors > max_transient_io_errors
                or remaining <= 0
            ):
                raise
            sleeper(min(poll_seconds, remaining))
            continue
        consecutive_io_errors = 0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"event": "TIMEOUT", "timeout_seconds": timeout_seconds}
        sleeper(min(poll_seconds, remaining))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Block read-only until candidate or package work needs Midlane."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=WORKSPACE / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
    )
    parser.add_argument(
        "--watch-file",
        type=Path,
        default=(
            WORKSPACE
            / "tools"
            / "review_mailbox"
            / "prompts"
            / "MIDLANE_LOOP_TASK.txt"
        ),
    )
    parser.add_argument(
        "--coordination-db",
        type=Path,
        default=DEFAULT_COORDINATION_DB,
    )
    parser.add_argument("--timeout-seconds", type=float, default=3600)
    parser.add_argument("--poll-seconds", type=float, default=5)
    parser.add_argument("--owner-pid", type=int, default=os.getppid())
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = wait_for_event(
            args.db,
            args.watch_file,
            coordination_database=args.coordination_db,
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
            owner_pid=args.owner_pid,
        )
    except (OSError, sqlite3.Error, ValueError) as error:
        print(json.dumps({"event": "ERROR", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
