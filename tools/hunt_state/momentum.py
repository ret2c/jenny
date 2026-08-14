"""Legacy package-momentum compatibility; retired from active JENNY workflow."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping


SCHEMA = "jenny.package-momentum.v1"
MILESTONES = ("L0", "L1", "L2", "L3A", "L3B", "L3C", "L4")
MILESTONE_STATES = ("UNPROVEN", "PROVEN", "BLOCKED")
WEIGHTS = {
    "L0": 10,
    "L1": 20,
    "L2": 20,
    "L3A": 15,
    "L3B": 5,
    "L3C": 10,
    "L4": 15,
}
HARD_CAPS = (
    ("L0", 10),
    ("L1", 30),
    ("L2", 50),
    ("L3A", 55),
    ("L3B", 75),
    ("L4", 90),
)
STAGE_NAMES = {
    "L0": "Current identity and lab",
    "L1": "Product-path reachability",
    "L2": "Supported boundary and control",
    "L3A": "Live proof",
    "L3B": "Negative control",
    "L3C": "Deterministic replay",
    "L4": "Currentness, impact, and economics",
}
POTENTIAL_LABELS = {
    "A_TIER": "A-TIER",
    "CHAIN_COMPONENT": "A-TIER CHAIN",
    "TIER_B_EXCEPTION": "B-TIER",
}


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


def init_db(db_path: Path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS momentum_revisions (
                slug TEXT NOT NULL,
                hypothesis_id TEXT NOT NULL,
                task_binding TEXT NOT NULL DEFAULT '',
                revision INTEGER NOT NULL,
                record_state TEXT NOT NULL
                    CHECK (record_state IN ('ACTIVE', 'CLEARED')),
                milestones_json TEXT NOT NULL,
                primary_blocker TEXT NOT NULL,
                invalidation_reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (slug, hypothesis_id, revision)
            )
            """
        )
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(momentum_revisions)"
            ).fetchall()
        }
        if "task_binding" not in columns:
            connection.execute(
                "ALTER TABLE momentum_revisions "
                "ADD COLUMN task_binding TEXT NOT NULL DEFAULT ''"
            )
        connection.commit()


def _required(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    return text


def _require_active_target(lifecycle_db: Path, slug: str) -> None:
    if not Path(lifecycle_db).is_file():
        raise ValueError(f"target lifecycle database is unavailable: {lifecycle_db}")
    with closing(connect(lifecycle_db)) as connection:
        target = connection.execute(
            "SELECT slug, status FROM targets WHERE slug = ?", (slug,)
        ).fetchone()
        active = connection.execute(
            "SELECT slug FROM targets WHERE status = 'ACTIVE' ORDER BY slug"
        ).fetchall()
    if target is None:
        raise ValueError(f"unknown target slug: {slug}")
    if str(target["status"]) != "ACTIVE":
        raise ValueError(f"target {slug} is not ACTIVE")
    if len(active) != 1 or str(active[0]["slug"]) != slug:
        raise ValueError("target lifecycle must contain this sole ACTIVE target")


def _normalize_evidence_ref(workspace: Path, value: object) -> str:
    reference = _required(value, "evidence reference")
    candidate = Path(reference)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (workspace / candidate).resolve()
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("evidence reference must stay inside the workspace") from exc
    if not resolved.is_file():
        raise ValueError(f"PROVEN requires existing evidence: {reference}")
    return relative.as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_binding(workspace: Path, value: object) -> dict[str, object]:
    reference = _normalize_evidence_ref(workspace, value)
    path = (workspace / reference).resolve()
    return {
        "path": reference,
        "size": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def validate_payload(
    payload: Mapping[str, object],
    workspace: Path,
) -> dict[str, object]:
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"momentum schema must be {SCHEMA}")
    slug = _required(payload.get("slug"), "slug")
    hypothesis_id = _required(payload.get("hypothesis_id"), "hypothesis id")
    task_binding = _required(payload.get("task_binding"), "task binding")
    blocker = _required(payload.get("primary_blocker"), "primary blocker")
    invalidation_reason = str(payload.get("invalidation_reason") or "").strip()
    raw_milestones = payload.get("milestones")
    if not isinstance(raw_milestones, Mapping):
        raise ValueError("milestones must be an object")
    if set(raw_milestones) != set(MILESTONES):
        raise ValueError("milestones must contain exactly L0, L1, L2, L3A, L3B, L3C, L4")

    milestones: dict[str, dict[str, object]] = {}
    workspace = Path(workspace).resolve()
    for milestone in MILESTONES:
        value = raw_milestones[milestone]
        if not isinstance(value, Mapping):
            raise ValueError(f"{milestone} must be an object")
        state = str(value.get("state") or "").strip().upper()
        if state not in MILESTONE_STATES:
            raise ValueError(f"{milestone} state is invalid")
        refs = value.get("evidence_refs", [])
        if not isinstance(refs, list):
            raise ValueError(f"{milestone} evidence_refs must be an array")
        normalized: list[str] = []
        bindings: list[dict[str, object]] = []
        if state == "PROVEN":
            if not refs:
                raise ValueError(f"{milestone} PROVEN requires existing evidence")
            bindings = [_evidence_binding(workspace, ref) for ref in refs]
            normalized = [str(binding["path"]) for binding in bindings]
        elif refs:
            raise ValueError(f"{milestone} evidence_refs are valid only for PROVEN")
        milestones[milestone] = {
            "state": state,
            "evidence_refs": list(dict.fromkeys(normalized)),
            "evidence_bindings": bindings,
        }
    return {
        "schema": SCHEMA,
        "slug": slug,
        "hypothesis_id": hypothesis_id,
        "task_binding": task_binding,
        "milestones": milestones,
        "primary_blocker": blocker,
        "invalidation_reason": invalidation_reason,
    }


def _label(score: int) -> str:
    if score == 100:
        return "PACKAGE ADMITTED"
    if score >= 90:
        return "ADMISSION READY"
    if score >= 80:
        return "STRONG CANDIDATE"
    if score >= 60:
        return "PROOF BUILDING"
    if score >= 40:
        return "BOUNDARY TRACED"
    if score >= 20:
        return "CANDIDATE FORMING"
    return "RECON"


def _proof_stage(
    milestones: Mapping[str, Mapping[str, object]],
    admitted: bool,
) -> str:
    for milestone in MILESTONES:
        state = str(milestones[milestone]["state"])
        if state != "PROVEN":
            suffix = "blocked" if state == "BLOCKED" else "unproven"
            return f"{STAGE_NAMES[milestone]} {suffix}"
    return "Package admitted" if admitted else "Candidate Challenge pending"


def calculate_score(
    milestones: Mapping[str, Mapping[str, object]],
    *,
    admitted: bool,
) -> dict[str, object]:
    score = sum(
        WEIGHTS[milestone]
        for milestone in MILESTONES
        if str(milestones[milestone].get("state")) == "PROVEN"
    )
    if admitted:
        score += 5
    for milestone, cap in HARD_CAPS:
        if str(milestones[milestone].get("state")) != "PROVEN":
            score = min(score, cap)
            break
    if not admitted:
        score = min(score, 95)
    return {
        "score": score,
        "label": _label(score),
        "stage": _proof_stage(milestones, admitted),
    }


def _latest_row(
    connection: sqlite3.Connection,
    slug: str,
    hypothesis_id: str | None = None,
) -> sqlite3.Row | None:
    if hypothesis_id is None:
        return connection.execute(
            """
            SELECT * FROM momentum_revisions
            WHERE slug = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (slug,),
        ).fetchone()
    return connection.execute(
        """
        SELECT * FROM momentum_revisions
        WHERE slug = ? AND hypothesis_id = ?
        ORDER BY revision DESC LIMIT 1
        """,
        (slug, hypothesis_id),
    ).fetchone()


def _challenge_status(
    challenge_db: Path | None,
    slug: str,
    hypothesis_id: str,
    milestones: Mapping[str, object],
) -> tuple[bool, str, str, int | None]:
    if challenge_db is None or not Path(challenge_db).is_file():
        return False, "UNRATED", "", None
    try:
        uri = f"file:{Path(challenge_db).resolve().as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, candidate_key, disposition, dossier_json, dossier_sha256
                FROM candidate_challenges
                WHERE target_slug = ? AND state = 'DECIDED'
                ORDER BY updated_at DESC, id DESC
                """,
                (slug,),
            ).fetchall()
    except (sqlite3.DatabaseError, OSError):
        return False, "UNRATED", "", None

    row = next(
        (item for item in rows if str(item["candidate_key"]) == hypothesis_id),
        None,
    )
    if row is None:
        l4 = milestones.get("L4", {})
        bindings = l4.get("evidence_bindings", []) if isinstance(l4, Mapping) else []
        dossier_hashes = {
            str(binding.get("sha256"))
            for binding in bindings
            if isinstance(binding, Mapping) and binding.get("sha256")
        }
        row = next(
            (
                item
                for item in rows
                if str(item["dossier_sha256"]) in dossier_hashes
            ),
            None,
        )
    if row is None:
        return False, "UNRATED", "", None
    try:
        dossier = json.loads(str(row["dossier_json"]))
        portfolio_class = dossier["economic_outcome"]["portfolio_class"]
    except (KeyError, TypeError, json.JSONDecodeError):
        return False, "UNRATED", str(row["disposition"]), int(row["id"])
    potential = POTENTIAL_LABELS.get(str(portfolio_class), "UNRATED")
    disposition = str(row["disposition"])
    return disposition in {"ADMIT_PROOF", "OPERATOR_EXCEPTION"}, potential, disposition, int(row["id"])


def _package_has_left_proof_stage(
    challenge_db: Path | None,
    challenge_id: int | None,
) -> bool:
    if challenge_db is None or challenge_id is None or not Path(challenge_db).is_file():
        return False
    try:
        uri = f"file:{Path(challenge_db).resolve().as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(work_items)").fetchall()
            }
            if "candidate_challenge_id" not in columns:
                return False
            row = connection.execute(
                """
                SELECT state FROM work_items
                WHERE candidate_challenge_id = ?
                ORDER BY updated_at DESC, id DESC LIMIT 1
                """,
                (challenge_id,),
            ).fetchone()
    except (sqlite3.DatabaseError, OSError):
        return False
    # Package construction is tracked separately. Once a work item exists, this
    # legacy record is no longer relevant to its current workflow state.
    return row is not None


def set_momentum(
    *,
    db_path: Path,
    lifecycle_db: Path,
    workspace: Path,
    payload: Mapping[str, object],
    now: str | None = None,
) -> dict[str, object]:
    normalized = validate_payload(payload, workspace)
    slug = str(normalized["slug"])
    hypothesis_id = str(normalized["hypothesis_id"])
    _require_active_target(lifecycle_db, slug)
    init_db(db_path)
    timestamp = now or utc_now()
    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        previous = _latest_row(connection, slug, hypothesis_id)
        previous_milestones: dict[str, object] = {}
        if previous is not None and str(previous["record_state"]) == "ACTIVE":
            previous_milestones = json.loads(str(previous["milestones_json"]))
        downgraded = any(
            previous_milestones.get(key, {}).get("state") == "PROVEN"
            and normalized["milestones"][key]["state"] != "PROVEN"
            for key in MILESTONES
        )
        if downgraded and not normalized["invalidation_reason"]:
            raise ValueError("downgrading PROVEN requires an invalidation reason")
        revision = int(previous["revision"]) + 1 if previous is not None else 1
        created_at = str(previous["created_at"]) if previous is not None else timestamp
        connection.execute(
            """
            INSERT INTO momentum_revisions(
                slug, hypothesis_id, task_binding, revision, record_state, milestones_json,
                primary_blocker, invalidation_reason, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
            """,
            (
                slug,
                hypothesis_id,
                normalized["task_binding"],
                revision,
                json.dumps(normalized["milestones"], sort_keys=True),
                normalized["primary_blocker"],
                normalized["invalidation_reason"],
                created_at,
                timestamp,
            ),
        )
        connection.commit()
    return {
        **normalized,
        "revision": revision,
        "record_state": "ACTIVE",
        "created_at": created_at,
        "updated_at": timestamp,
    }


def clear_momentum(
    *,
    db_path: Path,
    lifecycle_db: Path,
    slug: str,
    hypothesis_id: str,
    reason: str,
    now: str | None = None,
) -> dict[str, object]:
    slug = _required(slug, "slug")
    hypothesis_id = _required(hypothesis_id, "hypothesis id")
    reason = _required(reason, "clear reason")
    _require_active_target(lifecycle_db, slug)
    init_db(db_path)
    timestamp = now or utc_now()
    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        previous = _latest_row(connection, slug, hypothesis_id)
        if previous is None:
            raise ValueError("cannot clear missing momentum state")
        if str(previous["record_state"]) == "CLEARED":
            connection.rollback()
            return {
                "schema": SCHEMA,
                "slug": slug,
                "hypothesis_id": hypothesis_id,
                "revision": int(previous["revision"]),
                "record_state": "CLEARED",
                "invalidation_reason": str(previous["invalidation_reason"]),
                "updated_at": str(previous["updated_at"]),
            }
        revision = int(previous["revision"]) + 1
        connection.execute(
            """
            INSERT INTO momentum_revisions(
                slug, hypothesis_id, task_binding, revision, record_state, milestones_json,
                primary_blocker, invalidation_reason, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'CLEARED', ?, '', ?, ?, ?)
            """,
            (
                slug,
                hypothesis_id,
                str(previous["task_binding"]),
                revision,
                str(previous["milestones_json"]),
                reason,
                str(previous["created_at"]),
                timestamp,
            ),
        )
        connection.commit()
    return {
        "schema": SCHEMA,
        "slug": slug,
        "hypothesis_id": hypothesis_id,
        "revision": revision,
        "record_state": "CLEARED",
        "invalidation_reason": reason,
        "updated_at": timestamp,
    }


def read_momentum(
    db_path: Path,
    slug: str,
    *,
    challenge_db: Path | None = None,
    workspace: Path | None = None,
    active_task: str | None = None,
) -> dict[str, object] | None:
    if not Path(db_path).is_file():
        return None
    try:
        with closing(connect(db_path)) as connection:
            row = _latest_row(connection, slug)
    except sqlite3.DatabaseError:
        return None
    if row is None or str(row["record_state"]) != "ACTIVE":
        return None
    if active_task is not None:
        bound_task = str(row["task_binding"] or "").strip()
        current_task = str(active_task or "").strip()
        if not bound_task or bound_task.casefold() != current_task.casefold():
            return None
    try:
        milestones = json.loads(str(row["milestones_json"]))
        if set(milestones) != set(MILESTONES):
            return None
        if any(
            milestones[key].get("state") not in MILESTONE_STATES
            for key in MILESTONES
        ):
            return None
    except (AttributeError, TypeError, json.JSONDecodeError):
        return None
    if workspace is None:
        database_parent = Path(db_path).resolve().parent
        workspace = (
            database_parent.parent.parent
            if database_parent.name == "hunt_state"
            and database_parent.parent.name == "notes"
            else database_parent
        )
    workspace = Path(workspace).resolve()
    effective_milestones = json.loads(json.dumps(milestones))
    integrity = "VALID"
    integrity_rank = {"VALID": 0, "UNBOUND": 1, "CHANGED": 2, "MISSING": 3}
    for key in MILESTONES:
        milestone = milestones[key]
        if milestone.get("state") != "PROVEN":
            continue
        refs = milestone.get("evidence_refs", [])
        bindings = milestone.get("evidence_bindings", [])
        status = "VALID"
        if not isinstance(bindings, list) or len(bindings) != len(refs):
            status = "UNBOUND"
        else:
            for binding in bindings:
                if not isinstance(binding, dict):
                    status = "UNBOUND"
                    break
                candidate = (workspace / str(binding.get("path", ""))).resolve()
                try:
                    candidate.relative_to(workspace)
                except ValueError:
                    status = "MISSING"
                    break
                if not candidate.is_file():
                    status = "MISSING"
                    break
                if candidate.stat().st_size != binding.get("size"):
                    status = "CHANGED"
                    break
                digest = _sha256_file(candidate)
                if digest != binding.get("sha256"):
                    status = "CHANGED"
                    break
        if integrity_rank[status] > integrity_rank[integrity]:
            integrity = status
        if status != "VALID":
            effective_milestones[key] = {
                "state": "UNPROVEN",
                "evidence_refs": [],
                "evidence_bindings": [],
            }

    admitted, potential, disposition, challenge_id = _challenge_status(
        challenge_db,
        str(row["slug"]),
        str(row["hypothesis_id"]),
        effective_milestones,
    )
    if disposition in {"BANK", "CONSOLIDATE", "WRITE_OFF"}:
        return None
    if _package_has_left_proof_stage(challenge_db, challenge_id):
        return None
    score = calculate_score(effective_milestones, admitted=admitted)
    primary_blocker = "" if admitted else str(row["primary_blocker"])
    return {
        "schema": SCHEMA,
        "slug": str(row["slug"]),
        "hypothesis_id": str(row["hypothesis_id"]),
        "revision": int(row["revision"]),
        "score": score["score"],
        "label": score["label"],
        "stage": score["stage"],
        "potential": potential,
        "primary_blocker": primary_blocker,
        "evidence_integrity": integrity,
        "milestones": {
            key: str(effective_milestones[key]["state"])
            for key in MILESTONES
        },
        "admitted": admitted,
        "updated_at": str(row["updated_at"]),
    }


def history(
    db_path: Path,
    slug: str,
    hypothesis_id: str,
) -> list[dict[str, object]]:
    if not Path(db_path).is_file():
        return []
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT * FROM momentum_revisions
            WHERE slug = ? AND hypothesis_id = ?
            ORDER BY revision
            """,
            (slug, hypothesis_id),
        ).fetchall()
    return [
        {
            **dict(row),
            "milestones": json.loads(str(row["milestones_json"])),
        }
        for row in rows
    ]
