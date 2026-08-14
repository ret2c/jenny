from __future__ import annotations

import sqlite3


TERMINAL_ITEM_STATES = ("SUBMITTED", "HOLD", "DEAD", "REJECTED")


def supersede_older_addressed(
    connection: sqlite3.Connection,
    *,
    work_item_id: int,
    verified_request_id: int,
    timestamp: str,
) -> int:
    cursor = connection.execute(
        """
        UPDATE final_rework_requests
        SET state = 'SUPERSEDED', closed_at = ?
        WHERE work_item_id = ? AND state = 'ADDRESSED' AND id <> ?
        """,
        (timestamp, work_item_id, verified_request_id),
    )
    return int(cursor.rowcount)


def close_item_addressed(
    connection: sqlite3.Connection,
    *,
    work_item_id: int,
    timestamp: str,
    state: str = "CLOSED_TERMINAL",
) -> int:
    cursor = connection.execute(
        """
        UPDATE final_rework_requests
        SET state = ?, closed_at = ?
        WHERE work_item_id = ? AND state = 'ADDRESSED'
        """,
        (state, timestamp, work_item_id),
    )
    return int(cursor.rowcount)


def reconcile_terminal_addressed(
    connection: sqlite3.Connection,
    *,
    timestamp: str,
) -> int:
    placeholders = ", ".join("?" for _ in TERMINAL_ITEM_STATES)
    cursor = connection.execute(
        f"""
        UPDATE final_rework_requests
        SET state = 'CLOSED_TERMINAL', closed_at = ?
        WHERE state = 'ADDRESSED'
          AND work_item_id IN (
              SELECT id FROM work_items WHERE state IN ({placeholders})
          )
        """,
        (timestamp, *TERMINAL_ITEM_STATES),
    )
    return int(cursor.rowcount)
