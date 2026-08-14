from __future__ import annotations

import sqlite3
from typing import Any


def latest_rework_by_item(
    connection: sqlite3.Connection,
) -> dict[int, dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT r.id, r.work_item_id, r.state, r.reviewed_hash,
               r.reviewed_revision, r.queued_by, r.addressed_hash,
               r.addressed_revision, r.created_at, r.claimed_at,
               r.addressed_at, r.verified_at, r.closed_at
        FROM final_rework_requests AS r
        JOIN (
            SELECT work_item_id, MAX(id) AS latest_id
            FROM final_rework_requests
            GROUP BY work_item_id
        ) AS latest ON latest.latest_id = r.id
        """
    ).fetchall()
    return {int(row["work_item_id"]): dict(row) for row in rows}
