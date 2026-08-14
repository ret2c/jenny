from __future__ import annotations

import argparse
import json
import os
import re
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


NUMBERED_PACKAGE = re.compile(r"^\d+_.+")
WORKSPACE = Path(__file__).resolve().parents[2]


def find_ready_item(database: str | Path, workspace: str | Path) -> dict | None:
    database_path = Path(database)
    zdi_root = (Path(workspace).resolve() / "ZDI").resolve()
    connection = connect_read_only(database_path)
    try:
        rows = connection.execute(
            """
            SELECT id, package_path, product, version, package_hash,
                   revision, updated_at
            FROM work_items
            WHERE state = 'AWAITING_FINAL_REVIEW'
            ORDER BY updated_at, id
            """
        ).fetchall()
    finally:
        connection.close()

    for row in rows:
        package = Path(row["package_path"]).resolve()
        if package.parent != zdi_root:
            continue
        if not NUMBERED_PACKAGE.fullmatch(package.name):
            continue
        if not package.is_dir():
            continue
        return {
            "event": "FINAL_REVIEW_READY",
            "item": {
                "id": int(row["id"]),
                "package_path": str(package),
                "product": row["product"],
                "version": row["version"],
                "package_hash": row["package_hash"],
                "revision": int(row["revision"]),
                "updated_at": row["updated_at"],
            },
        }
    return None


def wait_for_event(
    database: str | Path,
    workspace: str | Path,
    watch_file: str | Path,
    *,
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
        current_signature = file_signature(watched)
        if current_signature != initial_signature:
            return {
                "event": "CONFIG_CHANGED",
                "watch_file": str(watched),
            }

        try:
            ready = find_ready_item(database, workspace)
            if ready is not None:
                return ready
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
        description="Block read-only until one direct package needs Final Review."
    )
    parser.add_argument("--workspace", type=Path, default=WORKSPACE)
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
            / "FINAL_REVIEWER_GOAL_TASK.txt"
        ),
    )
    parser.add_argument("--timeout-seconds", type=float, default=21600)
    parser.add_argument("--poll-seconds", type=float, default=5)
    parser.add_argument(
        "--owner-pid",
        type=int,
        default=os.getppid(),
        help="exit when this owning controller process no longer exists",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = wait_for_event(
            args.db,
            args.workspace,
            args.watch_file,
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
