from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA_VERSION = 2

WORK_ITEM_STATES = (
    "ACCEPTED",
    "AWAITING_FINAL_REVIEW",
    "DEAD",
    "FINAL_REWORK",
    "FINAL_REWORK_QUEUED",
    "HOLD",
    "HUNTER_REFINED",
    "MIDLANE_PASS",
    "MIDLANE_REVIEWING",
    "QUESTIONS_OPEN",
    "READY",
    "READY_FOR_MIDLANE",
    "REJECTED",
    "STALE",
    "SUBMITTED",
)

FINAL_REWORK_STATES = (
    "ADDRESSED",
    "CANCELLED",
    "CLAIMED",
    "CLOSED_HOLD",
    "CLOSED_TERMINAL",
    "OPEN",
    "SUPERSEDED",
    "VERIFIED",
)


def _sql_values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def apply_migrations(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"mailbox schema version {version} is newer than supported "
            f"version {SCHEMA_VERSION}"
        )
    if version < 1:
        work_values = _sql_values(WORK_ITEM_STATES)
        rework_values = _sql_values(FINAL_REWORK_STATES)
        connection.executescript(
            f"""
            CREATE TRIGGER IF NOT EXISTS validate_work_items_state_insert
            BEFORE INSERT ON work_items
            WHEN NEW.state NOT IN ({work_values})
            BEGIN
                SELECT RAISE(ABORT, 'invalid work item state');
            END;

            CREATE TRIGGER IF NOT EXISTS validate_work_items_state_update
            BEFORE UPDATE OF state ON work_items
            WHEN NEW.state NOT IN ({work_values})
            BEGIN
                SELECT RAISE(ABORT, 'invalid work item state');
            END;

            CREATE TRIGGER IF NOT EXISTS validate_final_rework_state_insert
            BEFORE INSERT ON final_rework_requests
            WHEN NEW.state NOT IN ({rework_values})
            BEGIN
                SELECT RAISE(ABORT, 'invalid final rework state');
            END;

            CREATE TRIGGER IF NOT EXISTS validate_final_rework_state_update
            BEFORE UPDATE OF state ON final_rework_requests
            WHEN NEW.state NOT IN ({rework_values})
            BEGIN
                SELECT RAISE(ABORT, 'invalid final rework state');
            END;
            """
        )
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        version = 1
    if version < 2:
        work_values = _sql_values(WORK_ITEM_STATES)
        connection.executescript(
            f"""
            DROP TRIGGER IF EXISTS validate_work_items_state_insert;
            DROP TRIGGER IF EXISTS validate_work_items_state_update;

            CREATE TRIGGER validate_work_items_state_insert
            BEFORE INSERT ON work_items
            WHEN NEW.state NOT IN ({work_values})
            BEGIN
                SELECT RAISE(ABORT, 'invalid work item state');
            END;

            CREATE TRIGGER validate_work_items_state_update
            BEFORE UPDATE OF state ON work_items
            WHEN NEW.state NOT IN ({work_values})
            BEGIN
                SELECT RAISE(ABORT, 'invalid work item state');
            END;

            UPDATE work_items
            SET state = 'READY'
            WHERE state = 'AWAITING_FINAL_REVIEW'
              AND instr(
                    lower(replace(package_path, char(92), '/')),
                    '/zdi/_ready_to_submit_'
                  ) > 0
              AND EXISTS (
                    SELECT 1 FROM events
                    WHERE events.work_item_id = work_items.id
                      AND events.event_type = 'MARKED_READY_FOR_SUBMISSION'
                      AND CASE
                            WHEN json_valid(events.detail_json)
                            THEN json_extract(
                                events.detail_json, '$.package_hash'
                            )
                            ELSE ''
                          END = work_items.package_hash
                  );

            CREATE TRIGGER IF NOT EXISTS validate_ready_path_insert
            BEFORE INSERT ON work_items
            WHEN (
                NEW.state = 'READY'
                AND instr(
                    lower(replace(NEW.package_path, char(92), '/')),
                    '/zdi/_ready_to_submit_'
                ) = 0
            ) OR (
                NEW.state = 'AWAITING_FINAL_REVIEW'
                AND instr(
                    lower(replace(NEW.package_path, char(92), '/')),
                    '/zdi/_ready_to_submit_'
                ) > 0
            )
            BEGIN
                SELECT RAISE(ABORT, 'work item state and package path disagree');
            END;

            CREATE TRIGGER IF NOT EXISTS validate_ready_path_update
            BEFORE UPDATE OF state, package_path ON work_items
            WHEN (
                NEW.state = 'READY'
                AND instr(
                    lower(replace(NEW.package_path, char(92), '/')),
                    '/zdi/_ready_to_submit_'
                ) = 0
            ) OR (
                NEW.state = 'AWAITING_FINAL_REVIEW'
                AND instr(
                    lower(replace(NEW.package_path, char(92), '/')),
                    '/zdi/_ready_to_submit_'
                ) > 0
            )
            BEGIN
                SELECT RAISE(ABORT, 'work item state and package path disagree');
            END;
            """
        )
        connection.execute("PRAGMA user_version = 2")


def connect_read_only(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA query_only = ON")
    return connection
