#!/usr/bin/env python3
"""Append-only private research state for the currently active target."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

try:
    from tools.hunt_state import momentum
except ModuleNotFoundError:  # Direct script execution from tools/hunt_state.
    import momentum  # type: ignore[no-redef]


WORKSPACE = Path(__file__).resolve().parents[2]
DEFAULT_DB = WORKSPACE / "notes" / "hunt_state" / "hunt_state.sqlite3"
DEFAULT_LIFECYCLE_DB = (
    WORKSPACE / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
)

ORIGIN_KINDS = (
    "CVE",
    "ADVISORY",
    "PATCH",
    "PR",
    "LOCAL_SIBLING",
    "ARCHITECTURE",
)
HYPOTHESIS_STATES = (
    "OPEN",
    "TESTING",
    "SUPPORTED",
    "BLOCKED",
    "NEGATIVE",
    "COLLISION",
    "PROMOTED",
)
NONTERMINAL_HYPOTHESIS_STATES = (
    "OPEN",
    "TESTING",
    "SUPPORTED",
    "BLOCKED",
)
TERMINAL_HYPOTHESIS_STATES = ("NEGATIVE", "COLLISION", "PROMOTED")
CHECKPOINT_KINDS = ("ACQUISITION", "LAB", "LANE", "CANDIDATE")
CHECKPOINT_STATES = (
    "PENDING",
    "ACTIVE",
    "PAUSED",
    "BLOCKED",
    "COMPLETE",
    "SKIPPED",
)
RESUME_NONTERMINAL_LIMIT = 50
RESUME_CLOSED_LIMIT = 5


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(Path(db_path)), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def init_db(db_path: Path = DEFAULT_DB) -> None:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    origin_check = ", ".join(f"'{value}'" for value in ORIGIN_KINDS)
    hypothesis_check = ", ".join(f"'{value}'" for value in HYPOTHESIS_STATES)
    kind_check = ", ".join(f"'{value}'" for value in CHECKPOINT_KINDS)
    checkpoint_check = ", ".join(f"'{value}'" for value in CHECKPOINT_STATES)
    with closing(connect(db_path)) as connection:
        connection.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS hypothesis_revisions (
                slug TEXT NOT NULL,
                hypothesis_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                lane TEXT NOT NULL,
                origin_kind TEXT NOT NULL CHECK (origin_kind IN ({origin_check})),
                origin_ref TEXT NOT NULL,
                origin_fact TEXT NOT NULL,
                theory TEXT NOT NULL,
                entry_point TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ({hypothesis_check})),
                result TEXT NOT NULL,
                next_action TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (slug, hypothesis_id, revision)
            );

            CREATE TABLE IF NOT EXISTS checkpoint_revisions (
                slug TEXT NOT NULL,
                stage_key TEXT NOT NULL,
                revision INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ({kind_check})),
                state TEXT NOT NULL CHECK (state IN ({checkpoint_check})),
                summary TEXT NOT NULL,
                next_action TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (slug, stage_key, revision)
            );
            """
        )
        connection.commit()
# Retired compatibility API for pre-existing package-momentum records. Normal
# hunt-state initialization, CLI use, and dashboard snapshots never create,
# write, or display this state.
calculate_momentum = momentum.calculate_score
set_momentum = momentum.set_momentum
clear_momentum = momentum.clear_momentum
read_momentum = momentum.read_momentum
momentum_history = momentum.history


def _required(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    return text


def _normalize_evidence(evidence_refs: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in evidence_refs:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            normalized.append(text)
    return normalized


def _require_active_target(lifecycle_db: Path, slug: str) -> None:
    lifecycle_db = Path(lifecycle_db)
    if not lifecycle_db.is_file():
        raise ValueError(f"target lifecycle database is unavailable: {lifecycle_db}")
    try:
        with closing(connect(lifecycle_db)) as connection:
            target = connection.execute(
                "SELECT slug, status FROM targets WHERE slug = ?", (slug,)
            ).fetchone()
            if target is None:
                raise ValueError(f"unknown target slug: {slug}")
            active = connection.execute(
                "SELECT slug FROM targets WHERE status = 'ACTIVE' ORDER BY slug"
            ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise ValueError("target lifecycle database is incompatible") from exc

    if str(target["status"]) != "ACTIVE":
        raise ValueError(f"target {slug} is not ACTIVE")
    if len(active) != 1:
        raise ValueError("target lifecycle must contain exactly one ACTIVE target")
    if str(active[0]["slug"]) != slug:
        raise ValueError(f"target {slug} is not the sole ACTIVE target")


def _row_dict(row: sqlite3.Row) -> dict[str, object]:
    result = dict(row)
    evidence_json = str(result.pop("evidence_refs_json", "[]"))
    try:
        evidence = json.loads(evidence_json)
    except json.JSONDecodeError:
        evidence = []
    result["evidence_refs"] = evidence if isinstance(evidence, list) else []
    return result


def _validate_hypothesis(
    *,
    origin_kind: str,
    state: str,
    result: str,
    next_action: str,
    evidence_refs: Sequence[str],
) -> None:
    if origin_kind not in ORIGIN_KINDS:
        raise ValueError(f"unsupported origin kind: {origin_kind}")
    if state not in HYPOTHESIS_STATES:
        raise ValueError(f"unsupported hypothesis state: {state}")
    if state in ("OPEN", "TESTING", "BLOCKED") and not next_action:
        raise ValueError(f"{state} requires an exact next action")
    if state == "SUPPORTED" and (not evidence_refs or not next_action):
        raise ValueError("SUPPORTED requires evidence and an exact next action")
    if state in TERMINAL_HYPOTHESIS_STATES and (not result or not evidence_refs):
        raise ValueError(f"{state} requires result and evidence")


def set_hypothesis(
    *,
    db_path: Path = DEFAULT_DB,
    lifecycle_db: Path = DEFAULT_LIFECYCLE_DB,
    slug: str,
    hypothesis_id: str,
    lane: str,
    origin_kind: str,
    origin_ref: str,
    origin_fact: str,
    theory: str,
    entry_point: str,
    state: str,
    result: str = "",
    next_action: str = "",
    evidence_refs: Iterable[object] = (),
    now: str | None = None,
) -> dict[str, object]:
    slug = _required(slug, "slug")
    hypothesis_id = _required(hypothesis_id, "hypothesis id")
    lane = _required(lane, "lane")
    origin_kind = _required(origin_kind, "origin kind").upper()
    origin_ref = _required(origin_ref, "origin reference")
    origin_fact = _required(origin_fact, "origin fact")
    theory = _required(theory, "theory")
    entry_point = _required(entry_point, "entry point")
    state = _required(state, "state").upper()
    result = str(result or "").strip()
    next_action = str(next_action or "").strip()
    evidence = _normalize_evidence(evidence_refs)
    _validate_hypothesis(
        origin_kind=origin_kind,
        state=state,
        result=result,
        next_action=next_action,
        evidence_refs=evidence,
    )
    _require_active_target(lifecycle_db, slug)
    init_db(db_path)
    timestamp = now or utc_now()

    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        previous = connection.execute(
            "SELECT revision, created_at FROM hypothesis_revisions "
            "WHERE slug = ? AND hypothesis_id = ? ORDER BY revision DESC LIMIT 1",
            (slug, hypothesis_id),
        ).fetchone()
        revision = int(previous["revision"]) + 1 if previous else 1
        created_at = str(previous["created_at"]) if previous else timestamp
        connection.execute(
            "INSERT INTO hypothesis_revisions ("
            "slug, hypothesis_id, revision, lane, origin_kind, origin_ref, "
            "origin_fact, theory, entry_point, state, result, next_action, "
            "evidence_refs_json, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                slug,
                hypothesis_id,
                revision,
                lane,
                origin_kind,
                origin_ref,
                origin_fact,
                theory,
                entry_point,
                state,
                result,
                next_action,
                json.dumps(evidence, separators=(",", ":")),
                created_at,
                timestamp,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM hypothesis_revisions WHERE slug = ? "
            "AND hypothesis_id = ? AND revision = ?",
            (slug, hypothesis_id, revision),
        ).fetchone()
    assert row is not None
    return _row_dict(row)


def _validate_checkpoint(
    *, kind: str, state: str, summary: str, next_action: str
) -> None:
    if kind not in CHECKPOINT_KINDS:
        raise ValueError(f"unsupported checkpoint kind: {kind}")
    if state not in CHECKPOINT_STATES:
        raise ValueError(f"unsupported checkpoint state: {state}")
    if state == "COMPLETE" and not summary:
        raise ValueError("COMPLETE requires evidence or a concrete completion record")
    if state == "SKIPPED" and not summary:
        raise ValueError("SKIPPED requires a reason")
    if state == "BLOCKED" and (not summary or not next_action):
        raise ValueError("BLOCKED requires a dependency and next action")


def _latest_checkpoint_rows(connection: sqlite3.Connection, slug: str) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT c.* FROM checkpoint_revisions c JOIN ("
        "SELECT stage_key, MAX(revision) AS revision FROM checkpoint_revisions "
        "WHERE slug = ? GROUP BY stage_key"
        ") latest ON latest.stage_key = c.stage_key AND latest.revision = c.revision "
        "WHERE c.slug = ? ORDER BY c.stage_key",
        (slug, slug),
    ).fetchall()


def set_checkpoint(
    *,
    db_path: Path = DEFAULT_DB,
    lifecycle_db: Path = DEFAULT_LIFECYCLE_DB,
    slug: str,
    stage_key: str,
    kind: str,
    state: str,
    summary: str,
    next_action: str = "",
    evidence_refs: Iterable[object] = (),
    now: str | None = None,
) -> dict[str, object]:
    slug = _required(slug, "slug")
    stage_key = _required(stage_key, "stage key")
    kind = _required(kind, "kind").upper()
    state = _required(state, "state").upper()
    summary = str(summary or "").strip()
    next_action = str(next_action or "").strip()
    evidence = _normalize_evidence(evidence_refs)
    _validate_checkpoint(
        kind=kind, state=state, summary=summary, next_action=next_action
    )
    _require_active_target(lifecycle_db, slug)
    init_db(db_path)
    timestamp = now or utc_now()

    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if state == "ACTIVE":
            for active in _latest_checkpoint_rows(connection, slug):
                if active["state"] != "ACTIVE" or active["stage_key"] == stage_key:
                    continue
                connection.execute(
                    "INSERT INTO checkpoint_revisions ("
                    "slug, stage_key, revision, kind, state, summary, next_action, "
                    "evidence_refs_json, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, 'PAUSED', ?, ?, ?, ?, ?)",
                    (
                        slug,
                        str(active["stage_key"]),
                        int(active["revision"]) + 1,
                        str(active["kind"]),
                        str(active["summary"]),
                        str(active["next_action"]),
                        str(active["evidence_refs_json"]),
                        str(active["created_at"]),
                        timestamp,
                    ),
                )

        previous = connection.execute(
            "SELECT revision, created_at FROM checkpoint_revisions "
            "WHERE slug = ? AND stage_key = ? ORDER BY revision DESC LIMIT 1",
            (slug, stage_key),
        ).fetchone()
        revision = int(previous["revision"]) + 1 if previous else 1
        created_at = str(previous["created_at"]) if previous else timestamp
        connection.execute(
            "INSERT INTO checkpoint_revisions ("
            "slug, stage_key, revision, kind, state, summary, next_action, "
            "evidence_refs_json, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                slug,
                stage_key,
                revision,
                kind,
                state,
                summary,
                next_action,
                json.dumps(evidence, separators=(",", ":")),
                created_at,
                timestamp,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM checkpoint_revisions WHERE slug = ? "
            "AND stage_key = ? AND revision = ?",
            (slug, stage_key, revision),
        ).fetchone()
    assert row is not None
    return _row_dict(row)


def hypothesis_list(
    db_path: Path, slug: str, *, latest_only: bool = True
) -> list[dict[str, object]]:
    if not Path(db_path).is_file():
        return []
    with closing(connect(db_path)) as connection:
        if latest_only:
            rows = connection.execute(
                "SELECT h.* FROM hypothesis_revisions h JOIN ("
                "SELECT hypothesis_id, MAX(revision) AS revision "
                "FROM hypothesis_revisions WHERE slug = ? GROUP BY hypothesis_id"
                ") latest ON latest.hypothesis_id = h.hypothesis_id "
                "AND latest.revision = h.revision WHERE h.slug = ? "
                "ORDER BY h.hypothesis_id",
                (slug, slug),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM hypothesis_revisions WHERE slug = ? "
                "ORDER BY hypothesis_id, revision",
                (slug,),
            ).fetchall()
    return [_row_dict(row) for row in rows]


def checkpoint_list(
    db_path: Path, slug: str, *, latest_only: bool = True
) -> list[dict[str, object]]:
    if not Path(db_path).is_file():
        return []
    with closing(connect(db_path)) as connection:
        if latest_only:
            rows = _latest_checkpoint_rows(connection, slug)
        else:
            rows = connection.execute(
                "SELECT * FROM checkpoint_revisions WHERE slug = ? "
                "ORDER BY stage_key, revision",
                (slug,),
            ).fetchall()
    return [_row_dict(row) for row in rows]


def build_summary(db_path: Path, slug: str) -> dict[str, int]:
    checkpoints = checkpoint_list(db_path, slug)
    hypotheses = hypothesis_list(db_path, slug)
    return {
        "complete": sum(row["state"] == "COMPLETE" for row in checkpoints),
        "active": sum(row["state"] == "ACTIVE" for row in checkpoints),
        "blocked": sum(row["state"] == "BLOCKED" for row in checkpoints),
        "open_hypotheses": sum(
            row["state"] in NONTERMINAL_HYPOTHESIS_STATES for row in hypotheses
        ),
    }


def _checkpoint_resume_row(row: dict[str, object]) -> dict[str, object]:
    return {
        key: row[key]
        for key in (
            "stage_key",
            "revision",
            "kind",
            "state",
            "summary",
            "next_action",
            "evidence_refs",
            "updated_at",
        )
    }


def _hypothesis_resume_row(row: dict[str, object]) -> dict[str, object]:
    return {
        key: row[key]
        for key in (
            "hypothesis_id",
            "revision",
            "lane",
            "origin_kind",
            "origin_ref",
            "theory",
            "entry_point",
            "state",
            "result",
            "next_action",
            "evidence_refs",
            "updated_at",
        )
    }


def build_resume(db_path: Path, slug: str) -> dict[str, object]:
    checkpoints = checkpoint_list(db_path, slug)
    hypotheses = hypothesis_list(db_path, slug)
    active = [row for row in checkpoints if row["state"] == "ACTIVE"]
    paused_blocked = [
        row for row in checkpoints if row["state"] in ("PAUSED", "BLOCKED")
    ]
    paused_blocked.sort(key=lambda row: (str(row["state"]), str(row["stage_key"])))
    nonterminal = [
        row for row in hypotheses if row["state"] in NONTERMINAL_HYPOTHESIS_STATES
    ]
    nonterminal.sort(key=lambda row: str(row["hypothesis_id"]))
    closed = [
        row for row in hypotheses if row["state"] in TERMINAL_HYPOTHESIS_STATES
    ]
    closed.sort(
        key=lambda row: (str(row["updated_at"]), str(row["hypothesis_id"])),
        reverse=True,
    )
    checkpoint_counts = {
        state: sum(row["state"] == state for row in checkpoints)
        for state in CHECKPOINT_STATES
    }
    hypothesis_counts = {
        state: sum(row["state"] == state for row in hypotheses)
        for state in HYPOTHESIS_STATES
    }
    next_actions = [
        {
            "kind": "checkpoint",
            "id": row["stage_key"],
            "action": row["next_action"],
        }
        for row in checkpoints
        if row["next_action"] and row["state"] not in ("COMPLETE", "SKIPPED")
    ] + [
        {
            "kind": "hypothesis",
            "id": row["hypothesis_id"],
            "action": row["next_action"],
        }
        for row in nonterminal
        if row["next_action"]
    ]
    next_actions.sort(key=lambda row: (str(row["kind"]), str(row["id"])))
    return {
        "schema": "jenny.hunt-state.resume.v1",
        "slug": slug,
        "active_checkpoint": _checkpoint_resume_row(active[0]) if active else None,
        "paused_or_blocked_checkpoints": [
            _checkpoint_resume_row(row) for row in paused_blocked
        ],
        "next_actions": next_actions[:RESUME_NONTERMINAL_LIMIT],
        "nonterminal_hypotheses": [
            _hypothesis_resume_row(row)
            for row in nonterminal[:RESUME_NONTERMINAL_LIMIT]
        ],
        "nonterminal_hypotheses_truncated": max(
            0, len(nonterminal) - RESUME_NONTERMINAL_LIMIT
        ),
        "recent_closed_hypotheses": [
            _hypothesis_resume_row(row) for row in closed[:RESUME_CLOSED_LIMIT]
        ],
        "counts": {
            "checkpoints": checkpoint_counts,
            "hypotheses": hypothesis_counts,
        },
    }


def _write_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--lifecycle-db", type=Path, default=DEFAULT_LIFECYCLE_DB)
    subparsers = parser.add_subparsers(dest="command", required=True)

    hypothesis_set = subparsers.add_parser("hypothesis-set")
    hypothesis_set.add_argument("--slug", required=True)
    hypothesis_set.add_argument("--hypothesis-id", required=True)
    hypothesis_set.add_argument("--lane", required=True)
    hypothesis_set.add_argument("--origin-kind", choices=ORIGIN_KINDS, required=True)
    hypothesis_set.add_argument("--origin-ref", required=True)
    hypothesis_set.add_argument("--origin-fact", required=True)
    hypothesis_set.add_argument("--theory", required=True)
    hypothesis_set.add_argument("--entry-point", required=True)
    hypothesis_set.add_argument("--state", choices=HYPOTHESIS_STATES, required=True)
    hypothesis_set.add_argument("--result", default="")
    hypothesis_set.add_argument("--next-action", default="")
    hypothesis_set.add_argument("--evidence-ref", action="append", default=[])

    hypothesis_list_parser = subparsers.add_parser("hypothesis-list")
    hypothesis_list_parser.add_argument("--slug", required=True)
    hypothesis_list_parser.add_argument("--history", action="store_true")

    checkpoint_set = subparsers.add_parser("checkpoint-set")
    checkpoint_set.add_argument("--slug", required=True)
    checkpoint_set.add_argument("--stage-key", required=True)
    checkpoint_set.add_argument("--kind", choices=CHECKPOINT_KINDS, required=True)
    checkpoint_set.add_argument("--state", choices=CHECKPOINT_STATES, required=True)
    checkpoint_set.add_argument("--summary", required=True)
    checkpoint_set.add_argument("--next-action", default="")
    checkpoint_set.add_argument("--evidence-ref", action="append", default=[])

    checkpoint_list_parser = subparsers.add_parser("checkpoint-list")
    checkpoint_list_parser.add_argument("--slug", required=True)
    checkpoint_list_parser.add_argument("--history", action="store_true")

    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("--slug", required=True)
    resume_parser = subparsers.add_parser("resume")
    resume_parser.add_argument("--slug", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "hypothesis-set":
            payload = set_hypothesis(
                db_path=args.db,
                lifecycle_db=args.lifecycle_db,
                slug=args.slug,
                hypothesis_id=args.hypothesis_id,
                lane=args.lane,
                origin_kind=args.origin_kind,
                origin_ref=args.origin_ref,
                origin_fact=args.origin_fact,
                theory=args.theory,
                entry_point=args.entry_point,
                state=args.state,
                result=args.result,
                next_action=args.next_action,
                evidence_refs=args.evidence_ref,
            )
        elif args.command == "hypothesis-list":
            payload = {
                "schema": "jenny.hunt-state.hypotheses.v1",
                "slug": args.slug,
                "hypotheses": hypothesis_list(
                    args.db, args.slug, latest_only=not args.history
                ),
            }
        elif args.command == "checkpoint-set":
            payload = set_checkpoint(
                db_path=args.db,
                lifecycle_db=args.lifecycle_db,
                slug=args.slug,
                stage_key=args.stage_key,
                kind=args.kind,
                state=args.state,
                summary=args.summary,
                next_action=args.next_action,
                evidence_refs=args.evidence_ref,
            )
        elif args.command == "checkpoint-list":
            payload = {
                "schema": "jenny.hunt-state.checkpoints.v1",
                "slug": args.slug,
                "checkpoints": checkpoint_list(
                    args.db, args.slug, latest_only=not args.history
                ),
            }
        elif args.command == "summary":
            payload = {
                "schema": "jenny.hunt-state.summary.v1",
                "slug": args.slug,
                **build_summary(args.db, args.slug),
            }
        elif args.command == "resume":
            payload = build_resume(args.db, args.slug)
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    _write_json(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
