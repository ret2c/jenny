from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SOURCE_ROOT = str(Path(__file__).resolve().parents[2])
if SOURCE_ROOT not in sys.path:
    sys.path.insert(0, SOURCE_ROOT)


PRESETS = ("A_TIER_ONLY", "BALANCED", "INCLUDE_B_TIER")
DEFAULT_PRESET = "A_TIER_ONLY"
STATE_REVISION_RE = re.compile(r"^Hunt profile revision:\s*(\d+)\s*$", re.MULTILINE)
STATE_PRESET_RE = re.compile(
    r"^Hunt profile:\s*(A_TIER_ONLY|BALANCED|INCLUDE_B_TIER)\s*$",
    re.MULTILINE,
)


class HuntPolicyError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class HuntPolicyStore:
    def __init__(self, db_path: str | Path, workspace: str | Path) -> None:
        self.db_path = Path(db_path).resolve()
        self.workspace = Path(workspace).resolve()
        self._last_acknowledged: dict[str, Any] = {
            "revision": 0,
            "preset": DEFAULT_PRESET,
            "state": "ACKNOWLEDGED",
            "target": None,
            "selected_at": "",
            "acknowledged_at": "",
        }
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS policy_revisions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        preset TEXT NOT NULL,
                        state TEXT NOT NULL,
                        target TEXT,
                        selected_at TEXT NOT NULL,
                        acknowledged_at TEXT,
                        prior_revision_id INTEGER,
                        FOREIGN KEY(prior_revision_id) REFERENCES policy_revisions(id),
                        CHECK(preset IN ('A_TIER_ONLY', 'BALANCED', 'INCLUDE_B_TIER')),
                        CHECK(state IN ('PENDING', 'ACKNOWLEDGED', 'SUPERSEDED'))
                    );
                    CREATE TABLE IF NOT EXISTS worker_policy_cursors (
                        worker TEXT PRIMARY KEY,
                        last_observed_pending_revision INTEGER,
                        last_acknowledged_revision INTEGER,
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                count = connection.execute(
                    "SELECT COUNT(*) FROM policy_revisions"
                ).fetchone()[0]
                if count == 0:
                    now = utc_now()
                    connection.execute(
                        """
                        INSERT INTO policy_revisions(
                            preset, state, target, selected_at, acknowledged_at,
                            prior_revision_id
                        ) VALUES (?, 'ACKNOWLEDGED', NULL, ?, ?, NULL)
                        """,
                        (DEFAULT_PRESET, now, now),
                    )
            active = self._active_row(connection)
            if active is not None:
                self._last_acknowledged = self._revision(active)

    @staticmethod
    def _validate_preset(preset: str) -> str:
        if preset not in PRESETS:
            raise HuntPolicyError(
                "invalid hunt profile; expected A_TIER_ONLY, BALANCED, or "
                "INCLUDE_B_TIER"
            )
        return preset

    @staticmethod
    def _validate_worker(worker: str) -> str:
        if not isinstance(worker, str) or re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", worker
        ) is None:
            raise HuntPolicyError("invalid worker identity")
        return worker.casefold()

    @staticmethod
    def _revision(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "revision": int(row["id"]),
            "preset": str(row["preset"]),
            "state": str(row["state"]),
            "target": row["target"],
            "selected_at": str(row["selected_at"]),
            "acknowledged_at": row["acknowledged_at"],
        }

    @staticmethod
    def _active_row(connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT id, preset, state, target, selected_at, acknowledged_at
            FROM policy_revisions
            WHERE state = 'ACKNOWLEDGED'
            ORDER BY id DESC LIMIT 1
            """
        ).fetchone()

    @staticmethod
    def _pending_row(connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT id, preset, state, target, selected_at, acknowledged_at
            FROM policy_revisions
            WHERE state = 'PENDING'
            ORDER BY id DESC LIMIT 1
            """
        ).fetchone()

    def _snapshot_from(self, connection: sqlite3.Connection) -> dict[str, Any]:
        active_row = self._active_row(connection)
        if active_row is None:
            raise HuntPolicyError("hunt profile has no acknowledged revision")
        active = self._revision(active_row)
        pending_row = self._pending_row(connection)
        pending = self._revision(pending_row) if pending_row is not None else None
        self._last_acknowledged = active
        return {
            "available": True,
            "active": active,
            "pending": pending,
            "warning": "",
        }

    def snapshot(self) -> dict[str, Any]:
        try:
            with closing(self._connect()) as connection:
                return self._snapshot_from(connection)
        except (OSError, sqlite3.Error, HuntPolicyError) as error:
            return {
                "available": False,
                "active": dict(self._last_acknowledged),
                "pending": None,
                "warning": f"hunt profile database unavailable: {error}",
            }

    def select(self, preset: str, active_target: str | None) -> dict[str, Any]:
        preset = self._validate_preset(preset)
        if active_target is not None:
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", active_target) is None:
                raise HuntPolicyError("invalid active target slug")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                active_row = self._active_row(connection)
                if active_row is None:
                    raise HuntPolicyError("hunt profile has no acknowledged revision")
                pending_row = self._pending_row(connection)
                if (
                    pending_row is not None
                    and pending_row["preset"] == preset
                    and pending_row["target"] == active_target
                ):
                    result = self._snapshot_from(connection)
                    result["changed"] = False
                    return result
                if pending_row is None and active_row["preset"] == preset:
                    result = self._snapshot_from(connection)
                    result["changed"] = False
                    return result

                now = utc_now()
                connection.execute(
                    "UPDATE policy_revisions SET state = 'SUPERSEDED' "
                    "WHERE state = 'PENDING'"
                )
                state = "PENDING" if active_target is not None else "ACKNOWLEDGED"
                acknowledged_at = None if active_target is not None else now
                connection.execute(
                    """
                    INSERT INTO policy_revisions(
                        preset, state, target, selected_at, acknowledged_at,
                        prior_revision_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preset,
                        state,
                        active_target,
                        now,
                        acknowledged_at,
                        int(active_row["id"]),
                    ),
                )
                connection.commit()
                result = self._snapshot_from(connection)
                result["changed"] = True
                return result
        except (OSError, sqlite3.Error) as error:
            raise HuntPolicyError(f"hunt profile selection failed: {error}") from error

    def pending_for(self, worker: str = "hunter") -> dict[str, Any] | None:
        worker = self._validate_worker(worker)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                active = self._active_row(connection)
                pending = self._pending_row(connection)
                if active is None:
                    raise HuntPolicyError("hunt profile has no acknowledged revision")
                self._last_acknowledged = self._revision(active)
                if pending is None:
                    connection.commit()
                    return None
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO worker_policy_cursors(
                        worker, last_observed_pending_revision,
                        last_acknowledged_revision, updated_at
                    ) VALUES (?, ?, NULL, ?)
                    ON CONFLICT(worker) DO UPDATE SET
                        last_observed_pending_revision = excluded.last_observed_pending_revision,
                        updated_at = excluded.updated_at
                    """,
                    (worker, int(pending["id"]), now),
                )
                connection.commit()
                return {
                    "revision": int(pending["id"]),
                    "from": str(active["preset"]),
                    "to": str(pending["preset"]),
                    "effective": "NEXT_CHECKPOINT",
                }
        except (OSError, sqlite3.Error) as error:
            raise HuntPolicyError(f"hunt profile lookup failed: {error}") from error

    def acknowledge(
        self,
        revision: int,
        target: str,
        state_file: str | Path,
        worker: str = "hunter",
    ) -> dict[str, Any]:
        worker = self._validate_worker(worker)
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise HuntPolicyError("revision must be a positive integer")
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", target) is None:
            raise HuntPolicyError("invalid acknowledgement target")
        expected_state = (
            self.workspace / "targets" / target / "HUNTER_STATE.md"
        ).resolve()
        observed_state = Path(state_file).resolve()
        if observed_state != expected_state:
            raise HuntPolicyError("state file is not the active target HUNTER_STATE.md")
        current_target = active_target_slug(self.workspace)
        if current_target != target:
            raise HuntPolicyError(
                "acknowledgement target is not the current ACTIVE target"
            )
        try:
            text = observed_state.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise HuntPolicyError(f"cannot read state file: {error}") from error

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                pending = self._pending_row(connection)
                if pending is None or int(pending["id"]) != revision:
                    raise HuntPolicyError("revision is not the current pending revision")
                if pending["target"] != target:
                    raise HuntPolicyError("acknowledgement target does not match selection")
                revision_match = STATE_REVISION_RE.search(text)
                preset_match = STATE_PRESET_RE.search(text)
                if (
                    revision_match is None
                    or int(revision_match.group(1)) != revision
                    or preset_match is None
                    or preset_match.group(1) != pending["preset"]
                ):
                    raise HuntPolicyError(
                        "HUNTER_STATE.md does not record the pending hunt profile"
                    )
                now = utc_now()
                connection.execute(
                    """
                    UPDATE policy_revisions
                    SET state = 'ACKNOWLEDGED', acknowledged_at = ?
                    WHERE id = ? AND state = 'PENDING'
                    """,
                    (now, revision),
                )
                connection.execute(
                    """
                    INSERT INTO worker_policy_cursors(
                        worker, last_observed_pending_revision,
                        last_acknowledged_revision, updated_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(worker) DO UPDATE SET
                        last_observed_pending_revision = excluded.last_observed_pending_revision,
                        last_acknowledged_revision = excluded.last_acknowledged_revision,
                        updated_at = excluded.updated_at
                    """,
                    (worker, revision, revision, now),
                )
                connection.commit()
                return self._snapshot_from(connection)
        except (OSError, sqlite3.Error) as error:
            raise HuntPolicyError(f"hunt profile acknowledgement failed: {error}") from error

    def history(self) -> list[dict[str, Any]]:
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT id, preset, state, target, selected_at, acknowledged_at
                    FROM policy_revisions ORDER BY id
                    """
                ).fetchall()
                return [self._revision(row) for row in rows]
        except (OSError, sqlite3.Error) as error:
            raise HuntPolicyError(f"hunt profile history failed: {error}") from error


def active_target_slug(workspace: Path) -> str | None:
    from tools.target_lifecycle.target_lifecycle import list_targets

    database = workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
    active = list_targets(database, "ACTIVE")
    if len(active) > 1:
        raise HuntPolicyError("multiple active targets prevent profile selection")
    return str(active[0]["slug"]) if active else None


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Checkpoint-applied Hunter profiles")
    parser.add_argument("--workspace", type=Path, default=workspace)
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show")
    select = commands.add_parser("select")
    select.add_argument("--preset", required=True, choices=PRESETS)
    pending = commands.add_parser("pending")
    pending.add_argument("--worker", default="hunter")
    acknowledge = commands.add_parser("acknowledge")
    acknowledge.add_argument("--revision", type=int, required=True)
    acknowledge.add_argument("--target", required=True)
    acknowledge.add_argument("--state-file", type=Path, required=True)
    acknowledge.add_argument("--worker", default="hunter")
    commands.add_parser("history")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    workspace = args.workspace.resolve()
    database = (
        args.db.resolve()
        if args.db is not None
        else workspace / "notes" / "hunt_policy" / "hunt_policy.sqlite3"
    )
    try:
        policy = HuntPolicyStore(database, workspace)
        if args.command == "show":
            output: object = policy.snapshot()
        elif args.command == "select":
            output = policy.select(args.preset, active_target_slug(workspace))
        elif args.command == "pending":
            output = {"hunt_policy_delta": policy.pending_for(args.worker)}
        elif args.command == "acknowledge":
            output = policy.acknowledge(
                args.revision,
                args.target,
                args.state_file,
                worker=args.worker,
            )
        elif args.command == "history":
            output = {"revisions": policy.history()}
        else:
            raise HuntPolicyError("unsupported command")
    except HuntPolicyError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
