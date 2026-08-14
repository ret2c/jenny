from __future__ import annotations

import sqlite3
import os
from pathlib import Path
from typing import Callable


class TransitionRollbackError(RuntimeError):
    pass


class TransitionInProgressError(RuntimeError):
    pass


def process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return False
    if os.name == "nt":
        import ctypes

        process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not process:
            return False
        ctypes.windll.kernel32.CloseHandle(process)
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def journaled_move(
    connection: sqlite3.Connection,
    *,
    item_id: int | None,
    action: str,
    source: Path,
    destination: Path,
    expected_hash: str,
    timestamp: str,
) -> int:
    open_row = connection.execute(
        "SELECT id FROM package_transitions "
        "WHERE phase IN ('PREPARED', 'MOVED') LIMIT 1"
    ).fetchone()
    if open_row is not None:
        raise TransitionInProgressError(
            "another package transition is incomplete; reinitialize the "
            "mailbox to reconcile it before moving package bytes"
        )
    cursor = connection.execute(
        """
        INSERT INTO package_transitions(
            action, work_item_id, source_path, destination_path,
            expected_hash, phase, owner_pid, created_at, updated_at, error
        ) VALUES (?, ?, ?, ?, ?, 'PREPARED', ?, ?, ?, '')
        """,
        (
            action,
            item_id,
            str(source.resolve()),
            str(destination.resolve()),
            expected_hash,
            os.getpid(),
            timestamp,
            timestamp,
        ),
    )
    transition_id = int(cursor.lastrowid)
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        source.rename(destination)
    except OSError:
        connection.execute(
            "UPDATE package_transitions "
            "SET phase = 'ROLLED_BACK', updated_at = ? WHERE id = ?",
            (timestamp, transition_id),
        )
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        raise
    connection.execute(
        "UPDATE package_transitions "
        "SET phase = 'MOVED', updated_at = ? WHERE id = ?",
        (timestamp, transition_id),
    )
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    return transition_id


def complete_transition(
    connection: sqlite3.Connection,
    transition_id: int,
    *,
    timestamp: str,
) -> None:
    connection.execute(
        "UPDATE package_transitions "
        "SET phase = 'COMMITTED', updated_at = ?, error = '' WHERE id = ?",
        (timestamp, transition_id),
    )


def reconcile_transitions(
    connection: sqlite3.Connection,
    *,
    hash_package: Callable[[Path], str],
    legacy_committed: Callable[[sqlite3.Connection, str, Path], bool],
    timestamp: str,
) -> list[int]:
    blocked: list[int] = []
    rows = connection.execute(
        "SELECT * FROM package_transitions "
        "WHERE phase IN ('PREPARED', 'MOVED') ORDER BY id"
    ).fetchall()
    for row in rows:
        transition_id = int(row["id"])
        if process_is_alive(int(row["owner_pid"])):
            continue
        source = Path(row["source_path"]).resolve()
        destination = Path(row["destination_path"]).resolve()
        source_exists = source.is_dir()
        destination_exists = destination.is_dir()
        item = (
            connection.execute(
                "SELECT package_path FROM work_items WHERE id = ?",
                (int(row["work_item_id"]),),
            ).fetchone()
            if row["work_item_id"] is not None
            else None
        )
        committed = (
            item is not None and Path(item["package_path"]).resolve() == destination
        ) or (
            item is None
            and legacy_committed(connection, str(row["action"]), destination)
        )
        if committed and destination_exists and not source_exists:
            if hash_package(destination) == row["expected_hash"]:
                connection.execute(
                    "UPDATE package_transitions "
                    "SET phase = 'COMMITTED', updated_at = ?, error = '' "
                    "WHERE id = ?",
                    (timestamp, transition_id),
                )
                continue
        authoritative_source = item is None or Path(item["package_path"]).resolve() == source
        if authoritative_source and source_exists and not destination_exists:
            if hash_package(source) == row["expected_hash"]:
                connection.execute(
                    "UPDATE package_transitions "
                    "SET phase = 'ROLLED_BACK', updated_at = ?, error = '' "
                    "WHERE id = ?",
                    (timestamp, transition_id),
                )
                continue
        if authoritative_source and destination_exists and not source_exists:
            if hash_package(destination) == row["expected_hash"]:
                source.parent.mkdir(parents=True, exist_ok=True)
                destination.rename(source)
                connection.execute(
                    "UPDATE package_transitions "
                    "SET phase = 'ROLLED_BACK', updated_at = ?, error = '' "
                    "WHERE id = ?",
                    (timestamp, transition_id),
                )
                continue
        connection.execute(
            "UPDATE package_transitions "
            "SET phase = 'BLOCKED', updated_at = ?, error = ? WHERE id = ?",
            (timestamp, "ambiguous filesystem/database transition state", transition_id),
        )
        blocked.append(transition_id)
    return blocked


def rollback_transition(
    db_path: Path,
    transition_id: int,
    *,
    hash_package: Callable[[Path], str],
    timestamp: str,
) -> None:
    """Restore moved bytes and close one failed transition journal row."""
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM package_transitions WHERE id = ?",
            (transition_id,),
        ).fetchone()
        if row is None:
            raise TransitionRollbackError(
                f"package transition {transition_id} is missing"
            )
        if row["phase"] == "ROLLED_BACK":
            connection.commit()
            return
        if row["phase"] not in {"PREPARED", "MOVED"}:
            raise TransitionRollbackError(
                f"package transition {transition_id} cannot roll back from "
                f"{row['phase']}"
            )

        source = Path(row["source_path"]).resolve()
        destination = Path(row["destination_path"]).resolve()
        expected_hash = str(row["expected_hash"])
        source_exists = source.is_dir()
        destination_exists = destination.is_dir()

        if destination_exists and not source_exists:
            if hash_package(destination) != expected_hash:
                raise TransitionRollbackError(
                    "moved package hash differs from the transition journal"
                )
            source.parent.mkdir(parents=True, exist_ok=True)
            try:
                destination.rename(source)
            except OSError as error:
                message = f"filesystem rollback failed: {error}"
                connection.execute(
                    "UPDATE package_transitions "
                    "SET phase = 'BLOCKED', updated_at = ?, error = ? WHERE id = ?",
                    (timestamp, message, transition_id),
                )
                connection.commit()
                raise TransitionRollbackError(message) from error
            source_exists = True
            destination_exists = False

        if source_exists and not destination_exists:
            if hash_package(source) != expected_hash:
                raise TransitionRollbackError(
                    "restored package hash differs from the transition journal"
                )
            connection.execute(
                "UPDATE package_transitions "
                "SET phase = 'ROLLED_BACK', updated_at = ?, error = '' WHERE id = ?",
                (timestamp, transition_id),
            )
            connection.commit()
            return

        raise TransitionRollbackError(
            "ambiguous filesystem state prevents package rollback"
        )
    except TransitionRollbackError as error:
        if connection.in_transaction:
            connection.execute(
                "UPDATE package_transitions "
                "SET phase = 'BLOCKED', updated_at = ?, error = ? WHERE id = ? "
                "AND phase IN ('PREPARED', 'MOVED')",
                (timestamp, str(error), transition_id),
            )
            connection.commit()
        raise
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
