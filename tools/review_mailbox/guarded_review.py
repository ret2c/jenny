#!/usr/bin/env python3
"""Run one Midlane review through the audited CLI with bounded cleanup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any


WORKSPACE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE))

from tools.replay_lab.guarded_run import GuardError, RunLock, run_owned  # noqa: E402


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _hash_package(package: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(package.rglob("*"), key=lambda value: value.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(package).as_posix().encode("utf-8")
        digest.update(b"FILE\0")
        digest.update(relative)
        digest.update(b"\0")
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _candidate_paths(workspace: Path, package_path: Path) -> list[Path]:
    names = {package_path.name, f"_READY_TO_SUBMIT_{package_path.name}"}
    candidates: list[Path] = []
    for root in (workspace / "ZDI_STAGING", workspace / "ZDI"):
        for name in names:
            candidate = root / name
            if candidate.is_dir() and candidate not in candidates:
                candidates.append(candidate)
    if package_path.is_dir() and package_path not in candidates:
        candidates.insert(0, package_path)
    return candidates


def reconcile_item(workspace: Path, db: Path, item_id: int) -> dict[str, Any]:
    """Read state after a timeout; never repair or retry it."""
    try:
        connection = sqlite3.connect(
            f"file:{db.resolve().as_posix()}?mode=ro",
            uri=True,
            timeout=2,
        )
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT id, state, revision, package_path, package_hash,
                   reviewed_hash, updated_at
            FROM work_items WHERE id = ?
            """,
            (item_id,),
        ).fetchone()
        if row is None:
            return {"error": f"item {item_id} does not exist"}
        events = [
            dict(event)
            for event in connection.execute(
                """
                SELECT id, actor, event_type, created_at
                FROM events WHERE work_item_id = ?
                ORDER BY id DESC LIMIT 8
                """,
                (item_id,),
            ).fetchall()
        ]
    except (OSError, sqlite3.Error) as error:
        return {"error": str(error)}
    finally:
        if "connection" in locals():
            connection.close()

    package_path = Path(row["package_path"])
    candidates = []
    for candidate in _candidate_paths(workspace, package_path):
        try:
            observed_hash = _hash_package(candidate)
        except OSError as error:
            candidates.append({"path": str(candidate), "error": str(error)})
            continue
        candidates.append(
            {
                "hash_matches_record": observed_hash == row["package_hash"],
                "observed_hash": observed_hash,
                "path": str(candidate),
            }
        )
    return {
        "events": events,
        "item": {
            "id": row["id"],
            "package_hash": row["package_hash"],
            "package_path": row["package_path"],
            "revision": row["revision"],
            "state": row["state"],
            "updated_at": row["updated_at"],
        },
        "observed_candidates": candidates,
        "retry_allowed": False,
    }


def _compact_child_output(stdout_path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(stdout_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    item = payload.get("item") if isinstance(payload, dict) else None
    if not isinstance(item, dict):
        return None
    return {
        "id": item.get("id"),
        "package_hash": item.get("package_hash"),
        "revision": item.get("revision"),
        "state": item.get("state"),
    }


def _operation_for_item(db: Path, item_id: int) -> str:
    try:
        connection = sqlite3.connect(
            f"file:{db.resolve().as_posix()}?mode=ro",
            uri=True,
            timeout=2,
        )
        row = connection.execute(
            "SELECT state FROM work_items WHERE id = ?", (item_id,)
        ).fetchone()
    except sqlite3.Error as error:
        raise GuardError(f"cannot select guarded review operation: {error}") from error
    finally:
        if "connection" in locals():
            connection.close()
    if row is None:
        raise GuardError(f"item {item_id} does not exist")
    state = str(row[0])
    if state == "MIDLANE_REVIEWING":
        return "review"
    if state == "HUNTER_REFINED":
        return "close"
    raise GuardError(
        "guarded review requires MIDLANE_REVIEWING or HUNTER_REFINED, "
        f"found {state}"
    )


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bounded wrapper for one review-mailbox Midlane verdict."
    )
    parser.add_argument("--workspace", type=Path, default=WORKSPACE)
    parser.add_argument("--db", type=Path)
    parser.add_argument("--item", type=int, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--result-file", type=Path, required=True)
    parser.add_argument("--phase-file", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args(arguments)

    workspace = args.workspace.resolve()
    db = (args.db or workspace / "notes/review_mailbox/review_mailbox.sqlite3").resolve()
    result_file = args.result_file.resolve()
    phase_file = args.phase_file.resolve() if args.phase_file else None
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if not args.input.is_file():
        parser.error(f"review input does not exist: {args.input}")

    result_file.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = result_file.with_suffix(".stdout.json")
    stderr_path = result_file.with_suffix(".stderr.txt")
    lock_path = workspace / "scratch/review_mailbox" / f"guarded_review_item_{args.item}.lock"
    if phase_file:
        phase_file.parent.mkdir(parents=True, exist_ok=True)
        phase_file.unlink(missing_ok=True)

    try:
        operation = _operation_for_item(db, args.item)
    except GuardError as error:
        result = {
            "error": str(error),
            "item": None,
            "operation": "",
            "status": "GUARD_ERROR",
            "timed_out": False,
        }
        _atomic_write_json(result_file, result)
        print(
            f"GUARDED_REVIEW {result['status']} item={args.item} "
            f"state=- result={result_file}"
        )
        return 2

    command = [
        sys.executable,
        "-B",
        str(Path(__file__).with_name("review_mailbox.py")),
        "--workspace",
        str(workspace),
        "--db",
        str(db),
    ]
    if phase_file:
        command.extend(["--phase-file", str(phase_file)])
    command.extend(
        [operation, "--item", str(args.item), "--input", str(args.input.resolve())]
    )

    try:
        with RunLock(lock_path, {"item": args.item, "command": operation}):
            guarded = run_owned(
                command,
                args.timeout_seconds,
                stdout_path,
                stderr_path,
                workspace,
            )
        child_item = _compact_child_output(stdout_path)
        status = (
            "TIMED_OUT"
            if guarded["timed_out"]
            else "COMPLETED"
            if guarded["exit_code"] == 0 and child_item is not None
            else "FAILED"
        )
        result: dict[str, Any] = {
            "duration_seconds": guarded["duration_seconds"],
            "exit_code": guarded["exit_code"],
            "item": child_item,
            "operation": operation,
            "phase_file": str(phase_file) if phase_file else "",
            "root_exited": guarded["root_exited"],
            "status": status,
            "stderr_path": str(stderr_path),
            "stdout_path": str(stdout_path),
            "timed_out": guarded["timed_out"],
            "tree_termination_attempted": guarded["tree_termination_attempted"],
            "tree_termination_error": guarded["tree_termination_error"],
        }
        if guarded["timed_out"]:
            result["reconciliation"] = reconcile_item(workspace, db, args.item)
            result["retry_allowed"] = False
            result["retry_instruction"] = (
                "Inspect reconciliation before manually issuing any retry."
            )
    except (GuardError, OSError) as error:
        result = {
            "error": str(error),
            "item": None,
            "status": "GUARD_ERROR",
            "timed_out": False,
        }

    _atomic_write_json(result_file, result)
    state = result.get("item", {}).get("state") if result.get("item") else "-"
    print(
        f"GUARDED_REVIEW {result['status']} item={args.item} "
        f"state={state} result={result_file}"
    )
    if result["status"] == "COMPLETED":
        return 0
    if result["status"] == "TIMED_OUT":
        return 124
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
