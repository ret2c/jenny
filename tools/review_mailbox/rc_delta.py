from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ENTRY_RE = re.compile(
    rb"(?m)^### (RC-[A-Za-z0-9._-]+)\r?\n(?P<body>.*?)(?=^### RC-|\Z)",
    re.DOTALL,
)
RESPONSE_RE = re.compile(rb"(?m)^- Hunter status: ")
MAX_DELTA_BYTES = 64 * 1024


class RCDeltaError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _entries(value: bytes, *, unresolved_only: bool) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for match in ENTRY_RE.finditer(value):
        body = match.group("body")
        if unresolved_only and RESPONSE_RE.search(body):
            continue
        raw = match.group(0).decode("utf-8", errors="replace").strip()
        output.append(
            {
                "request_id": match.group(1).decode("ascii"),
                "text": raw,
            }
        )
    return output


def read_delta(
    *,
    workspace: str | Path,
    db_path: str | Path,
    consumer: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", consumer):
        raise RCDeltaError("consumer name is invalid")
    workspace_path = Path(workspace).resolve()
    source = workspace_path / "notes" / "review_mailbox" / "MIDLANE_TO_HUNTER.md"
    if not source.is_file():
        raise RCDeltaError(f"Remote Control log is missing: {source}")
    data = source.read_bytes()
    database = Path(db_path).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now()
    with sqlite3.connect(database, timeout=10) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS rc_offsets (
                consumer TEXT PRIMARY KEY,
                last_offset INTEGER NOT NULL,
                prefix_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        row = connection.execute(
            "SELECT * FROM rc_offsets WHERE consumer = ?", (consumer,)
        ).fetchone()
        reset = False
        baseline = row is None
        if row is not None:
            offset = int(row["last_offset"])
            prefix_valid = (
                0 <= offset <= len(data)
                and _digest(data[:offset]) == row["prefix_sha256"]
            )
            if not prefix_valid:
                reset = True
            else:
                delta = data[offset:]
                if len(delta) > MAX_DELTA_BYTES:
                    raise RCDeltaError(
                        "Remote Control delta exceeds 64 KiB; inspect the append "
                        "source before advancing the cursor"
                    )
        # The cursor bounds append validation; it is not delivery authority.
        # Unresolved requests remain visible until the append-only entry itself
        # contains a Hunter response.
        changes = _entries(data, unresolved_only=True)
        connection.execute(
            """
            INSERT INTO rc_offsets(
                consumer, last_offset, prefix_sha256, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(consumer) DO UPDATE SET
                last_offset = excluded.last_offset,
                prefix_sha256 = excluded.prefix_sha256,
                updated_at = excluded.updated_at
            """,
            (consumer, len(data), _digest(data), timestamp, timestamp),
        )
        connection.commit()
    return {
        "consumer": consumer,
        "baseline": baseline,
        "cursor_reset": reset,
        "source_size": len(data),
        "changes": changes,
    }


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Read only new Remote Control entries for one consumer"
    )
    parser.add_argument("--workspace", type=Path, default=workspace)
    parser.add_argument(
        "--db",
        type=Path,
        default=workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
    )
    parser.add_argument("--consumer", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = read_delta(
            workspace=args.workspace,
            db_path=args.db,
            consumer=args.consumer,
        )
    except (OSError, sqlite3.Error, RCDeltaError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
