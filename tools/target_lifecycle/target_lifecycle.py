#!/usr/bin/env python3
"""Small SQLite ledger and validators for target scope and cleanup state."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WORKSPACE = Path(__file__).resolve().parents[2]
DEFAULT_DB = WORKSPACE / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"

ALLOWED_STATES = (
    "CANDIDATE",
    "SCOPED",
    "ACTIVE",
    "PARKED_REHYDRATABLE",
    "DISCOURAGED",
    "HARD_EXCLUDED",
    "ARCHIVED",
)

TARGET_SCOPE_WORDS = frozenset({"goal", "hunt", "target"})
PACKAGE_SCOPE_WORDS = frozenset({"bundle", "case", "finding", "item", "package", "report"})
TARGET_IDENTIFIER_STOPWORDS = frozenset({"and", "data", "enterprise", "for", "manager", "server", "the"})

TARGET_FIELDS = (
    "slug",
    "product",
    "vendor",
    "category",
    "status",
    "admission_decision",
    "fit_score",
    "current_version",
    "scope_path",
    "goal_path",
    "mirror_path",
    "goal_sha256",
    "reason",
    "scoped_at",
    "cleaned_at",
)

REQUIRED_GOAL_SECTIONS: dict[str, tuple[str, ...]] = {
    "Authority and duration": ("authority and duration",),
    "Mission and economic standard": ("mission and economic standard",),
    "Current target identity": ("current target identity",),
    "Architecture and trust boundaries": ("architecture and trust boundaries",),
    "Historical security lineage": (
        "historical security lineage",
        "public and duplicate exclusions",
    ),
    "Ranked hunting lanes": ("ranked hunting lanes",),
    "Public and local duplicate exclusions": (
        "public and local duplicate exclusions",
        "public and duplicate exclusions",
    ),
    "Acquisition, lab, provenance, and disk budget": (
        "acquisition, lab, provenance, and disk budget",
        "lab, provenance, and execution rules",
    ),
    "Coverage and durable records": (
        "coverage and durable records",
        "durable private work records",
    ),
    "Candidate admission and proof gates": ("candidate admission and proof gates",),
    "Hunter, Midlane, and Final Reviewer workflow": (
        "hunter, midlane, and final reviewer workflow",
        "hunter and review-mailbox workflow",
    ),
    "Diminishing returns and stop behavior": (
        "diminishing returns and stop behavior",
        "diminishing-return marker",
    ),
    "Final decision rules": ("final decision rules",),
}

HISTORICAL_LABELS = ("FACT", "INFERENCE", "NUDGE", "DISCOURAGED")
UNFINISHED_PATTERNS = (
    ("TBD", re.compile(r"\bTBD\b", re.IGNORECASE)),
    ("TODO", re.compile(r"\bTODO\b", re.IGNORECASE)),
    ("FIXME", re.compile(r"\bFIXME\b", re.IGNORECASE)),
    ("template token", re.compile(r"\{\{[^{}\r\n]+\}\}")),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db(db_path: Path = DEFAULT_DB) -> None:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    state_check = ", ".join(f"'{state}'" for state in ALLOWED_STATES)
    with closing(connect(db_path)) as conn:
        conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS targets (
                slug TEXT PRIMARY KEY,
                product TEXT NOT NULL,
                vendor TEXT,
                category TEXT,
                status TEXT NOT NULL CHECK (status IN ({state_check})),
                admission_decision TEXT,
                fit_score INTEGER CHECK (fit_score IS NULL OR fit_score BETWEEN 0 AND 100),
                current_version TEXT,
                scope_path TEXT,
                goal_path TEXT,
                mirror_path TEXT,
                goal_sha256 TEXT,
                reason TEXT,
                scoped_at TEXT,
                cleaned_at TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                slug TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail TEXT NOT NULL,
                metadata_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (slug) REFERENCES targets(slug)
            );
            """
        )
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(targets)")
        }
        if "goal_sha256" not in columns:
            conn.execute("ALTER TABLE targets ADD COLUMN goal_sha256 TEXT")
        active_rows = conn.execute(
            "SELECT slug FROM targets WHERE status = 'ACTIVE' ORDER BY slug"
        ).fetchall()
        if len(active_rows) > 1:
            rendered = ", ".join(str(row["slug"]) for row in active_rows)
            conn.rollback()
            raise ValueError(
                "target lifecycle integrity failure: multiple ACTIVE targets: "
                f"{rendered}"
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS targets_one_active "
            "ON targets(status) WHERE status = 'ACTIVE'"
        )
        conn.commit()


def _validate_state(state: str) -> None:
    if state not in ALLOWED_STATES:
        raise ValueError(
            f"unsupported lifecycle state {state!r}; expected one of {', '.join(ALLOWED_STATES)}"
        )


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_recorded_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path.resolve() if path.is_absolute() else (WORKSPACE / path).resolve()


def _validate_declared_evidence_appendix(
    goal_path: Path,
    required_appendix: Path,
) -> list[str]:
    """Require the GOAL pointer to resolve to the validated appendix bytes."""
    if not goal_path.is_file():
        return [f"goal file does not exist: {goal_path}"]
    text = goal_path.read_text(encoding="utf-8", errors="replace")
    match = re.search(
        r"^Evidence appendix:\s+`([^`]*EVIDENCE_APPENDIX\.md)`\s*$",
        text,
        re.MULTILINE,
    )
    if match is None:
        if "Goal schema: 2" not in text:
            return []
        return ["goal has no declared evidence appendix pointer"]
    raw_path = Path(match.group(1))
    if raw_path.is_absolute():
        declared = raw_path.resolve()
    elif raw_path.parent == Path("."):
        declared = (goal_path.parent / raw_path).resolve()
    else:
        declared = (WORKSPACE / raw_path).resolve()
    if not declared.is_file():
        return [f"declared evidence appendix does not exist: {declared}"]
    if not required_appendix.is_file():
        return [f"required evidence appendix does not exist: {required_appendix}"]
    if declared.read_bytes() != required_appendix.read_bytes():
        return ["declared evidence appendix differs from validated scope appendix"]
    return []


def _publish_new_target_scope_pair(
    goal_path: Path,
    appendix_path: Path,
    mirror_path: Path,
    *,
    fetch_text: Any = None,
) -> Path:
    target_appendix = mirror_path.parent / "EVIDENCE_APPENDIX.md"
    if mirror_path.exists():
        raise ValueError("publish-mirror requires an absent destination mirror")
    if target_appendix.exists():
        raise ValueError(
            "publish-mirror requires an absent target-local evidence appendix"
        )
    mirror_path.parent.mkdir(parents=True, exist_ok=True)
    staged_goal = mirror_path.with_name(mirror_path.name + f".{os.getpid()}.tmp")
    staged_appendix = target_appendix.with_name(
        target_appendix.name + f".{os.getpid()}.tmp"
    )
    for staged in (staged_goal, staged_appendix):
        if staged.exists():
            raise ValueError(f"scope publication staging path already exists: {staged}")
    published_goal = False
    published_appendix = False
    try:
        staged_goal.write_bytes(goal_path.read_bytes())
        staged_appendix.write_bytes(appendix_path.read_bytes())
        os.replace(staged_appendix, target_appendix)
        published_appendix = True
        os.replace(staged_goal, mirror_path)
        published_goal = True
        if mirror_path.read_bytes() != goal_path.read_bytes():
            raise RuntimeError("published goal mirror bytes differ from validated source")
        if target_appendix.read_bytes() != appendix_path.read_bytes():
            raise RuntimeError(
                "published evidence appendix bytes differ from validated source"
            )
        mirror_errors = _validate_goal_source(
            mirror_path,
            resolve_currentness=True,
            fetch_text=fetch_text,
            required_schema_version=2,
        )
        if mirror_errors:
            raise ValueError(
                "published Hunter mirror validation failed: "
                + "; ".join(mirror_errors)
            )
        return target_appendix
    except BaseException:
        if published_goal:
            mirror_path.unlink(missing_ok=True)
        if published_appendix:
            target_appendix.unlink(missing_ok=True)
        raise
    finally:
        staged_goal.unlink(missing_ok=True)
        staged_appendix.unlink(missing_ok=True)


def _normalize_instruction_path(value: str) -> str:
    return value.replace("\\", "/").casefold()


def _load_python_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _target_scoper_script(name: str) -> Path:
    candidates = (WORKSPACE / "skills" / "target-scoper" / "scripts" / name,)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    rendered = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"target-scoper script not found; checked: {rendered}")


def _is_compact_goal(path: Path) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return (
        "## Current identity and acquisition gate" in text
        and "Evidence appendix:" in text
    )


def _validate_goal_contract(
    goal_path: Path,
    mirror_path: Path,
    *,
    resolve_currentness: bool = False,
    fetch_text: Any = None,
    required_schema_version: int | None = None,
) -> list[str]:
    if not goal_path.is_file():
        return [f"goal file does not exist: {goal_path}"]
    if not mirror_path.is_file():
        return [f"mirror file does not exist: {mirror_path}"]
    if goal_path.read_bytes() != mirror_path.read_bytes():
        return ["goal and mirror bytes differ"]
    if not _is_compact_goal(goal_path) and required_schema_version is None:
        return validate_goal(goal_path, mirror_path)
    module = _load_python_module(
        "jenny_goal_linter",
        _target_scoper_script("lint_goal.py"),
    )
    kwargs: dict[str, Any] = {"resolve_currentness": resolve_currentness}
    if fetch_text is not None:
        kwargs["fetch_text"] = fetch_text
    if required_schema_version is not None:
        kwargs["required_schema_version"] = required_schema_version
    return list(module.lint_goal(goal_path, **kwargs))


def _validate_goal_source(
    goal_path: Path,
    *,
    resolve_currentness: bool = False,
    fetch_text: Any = None,
    required_schema_version: int | None = None,
) -> list[str]:
    if not goal_path.is_file():
        return [f"goal file does not exist: {goal_path}"]
    if not _is_compact_goal(goal_path) and required_schema_version is None:
        return validate_goal(goal_path)
    module = _load_python_module(
        "jenny_goal_linter",
        _target_scoper_script("lint_goal.py"),
    )
    kwargs: dict[str, Any] = {"resolve_currentness": resolve_currentness}
    if fetch_text is not None:
        kwargs["fetch_text"] = fetch_text
    if required_schema_version is not None:
        kwargs["required_schema_version"] = required_schema_version
    return list(module.lint_goal(goal_path, **kwargs))


def _instruction_clauses(instruction: str) -> list[str]:
    normalized = " ".join(instruction.split())
    return [
        clause.strip()
        for clause in re.split(
            r"(?:[.!?;]+\s+|\s*,?\s+(?:but|however)\s+)",
            normalized,
            flags=re.IGNORECASE,
        )
        if clause.strip()
    ]


def _instruction_is_affirmative(instruction: str, actions: tuple[str, ...]) -> bool:
    for clause in _instruction_clauses(instruction):
        normalized = clause.casefold()
        if not any(re.search(pattern, normalized) for pattern in actions):
            continue
        if re.search(r"\b(?:do\s+not|don't|dont|never|not)\b", normalized):
            continue
        return True
    return False


def _instruction_affirmatively_names_path(
    instruction: str,
    actions: tuple[str, ...],
    accepted_paths: set[str],
) -> bool:
    affirmative = False
    for clause in _instruction_clauses(instruction):
        normalized_clause = _normalize_instruction_path(clause)
        if not any(path and path in normalized_clause for path in accepted_paths):
            continue
        if not any(re.search(pattern, normalized_clause) for pattern in actions):
            continue
        if re.search(
            r"\b(?:do\s+not|don't|dont|never|not)\b",
            normalized_clause,
        ):
            return False
        affirmative = True
    return affirmative


def _instruction_affirmatively_names_target(
    instruction: str,
    actions: tuple[str, ...],
    identifiers: set[str],
) -> bool:
    normalized_identifiers = {
        " ".join(identifier.casefold().replace("-", " ").split())
        for identifier in identifiers
        if identifier.strip()
    }
    affirmative = False
    for clause in _instruction_clauses(instruction):
        normalized_clause = " ".join(clause.casefold().replace("-", " ").split())
        if not any(
            re.search(
                rf"(?<![a-z0-9]){re.escape(identifier)}(?![a-z0-9])",
                normalized_clause,
            )
            for identifier in normalized_identifiers
        ):
            continue
        if not any(re.search(pattern, normalized_clause) for pattern in actions):
            continue
        if re.search(r"\b(?:do\s+not|don't|dont|never|not)\b", normalized_clause):
            return False
        affirmative = True
    return affirmative


def _validate_activation_goal(
    target: dict[str, Any],
    operator_instruction: str,
) -> tuple[Path, str]:
    original = _resolve_recorded_path(target.get("goal_path"))
    mirror = _resolve_recorded_path(target.get("mirror_path"))
    if original is None or mirror is None:
        raise ValueError(
            "target activation requires recorded goal_path and mirror_path"
        )
    errors = _validate_goal_contract(
        original,
        mirror,
        resolve_currentness=True,
    )
    if errors:
        raise ValueError("target activation goal validation failed: " + "; ".join(errors))
    accepted_paths = {
        _normalize_instruction_path(str(mirror)),
        _normalize_instruction_path(str(original)),
    }
    workspace = WORKSPACE.resolve()
    for path in (mirror, original):
        try:
            relative = path.relative_to(workspace)
        except ValueError:
            continue
        accepted_paths.add(_normalize_instruction_path(relative.as_posix()))
    recorded_mirror = str(target.get("mirror_path") or "")
    recorded_original = str(target.get("goal_path") or "")
    if recorded_mirror:
        accepted_paths.add(_normalize_instruction_path(recorded_mirror))
    if recorded_original:
        accepted_paths.add(_normalize_instruction_path(recorded_original))
    actions = (
        r"\bactivate\b",
        r"\bexecute\b",
        r"\bstart\b",
        r"\brun\b",
        r"\bswitch\b.*\b(?:target|goal|hunt)\b",
        r"\b(?:hunt|work)\b.*\b(?:target|goal)\b",
    )
    path_authorized = _instruction_affirmatively_names_path(
        operator_instruction,
        actions,
        accepted_paths,
    )
    target_authorized = _instruction_affirmatively_names_target(
        operator_instruction,
        actions,
        {
            str(target.get("slug") or ""),
            str(target.get("product") or ""),
        },
    )
    if not path_authorized and not target_authorized:
        raise ValueError(
            "operator instruction must affirmatively authorize activation or "
            "execution of the recorded goal or exact target"
        )
    return mirror, sha256_file(mirror)


def get_target(db_path: Path, slug: str) -> dict[str, Any] | None:
    init_db(db_path)
    with closing(connect(db_path)) as conn:
        return _row_to_dict(conn.execute("SELECT * FROM targets WHERE slug = ?", (slug,)).fetchone())


def verify_checkout(db_path: Path, slug: str) -> list[str]:
    """Validate the complete Scoper-to-Hunter handoff for one recorded target."""
    target = get_target(db_path, slug)
    if target is None:
        return ["target has no lifecycle scope row"]
    scope = _resolve_recorded_path(target.get("scope_path"))
    goal = _resolve_recorded_path(target.get("goal_path"))
    mirror = _resolve_recorded_path(target.get("mirror_path"))
    errors: list[str] = []
    appendix: Path | None = None
    if scope is None:
        errors.append("target has no recorded scope path")
    else:
        appendix = scope / "EVIDENCE_APPENDIX.md"
        if not appendix.is_file():
            errors.append("required evidence appendix does not exist")
    if goal is None or mirror is None:
        errors.append("target has no recorded goal and mirror paths")
    else:
        errors.extend(_validate_goal_contract(goal, mirror))
        if appendix is not None and appendix.is_file():
            errors.extend(_validate_declared_evidence_appendix(goal, appendix))
        if mirror.is_file():
            mirror_text = mirror.read_text(encoding="utf-8", errors="replace")
            target_appendix = mirror.parent / "EVIDENCE_APPENDIX.md"
            if "Goal schema: 2" in mirror_text:
                if not target_appendix.is_file():
                    errors.append(
                        "target-local evidence appendix does not exist beside Hunter mirror"
                    )
                elif appendix is not None and appendix.is_file():
                    if target_appendix.read_bytes() != appendix.read_bytes():
                        errors.append(
                            "target-local evidence appendix differs from validated scope appendix"
                        )
                    errors.extend(
                        _validate_declared_evidence_appendix(mirror, target_appendix)
                    )
                    errors.extend(_validate_goal_source(mirror))
        if mirror.is_file() and target.get("goal_sha256") != sha256_file(mirror):
            errors.append("recorded goal hash does not match mirror")
    return errors


def migrate_legacy_scope(
    db_path: Path,
    slug: str,
    *,
    expected_goal_sha256: str,
    expected_appendix_sha256: str,
) -> dict[str, Any]:
    """Record a missing legacy checkout receipt without changing target state or bytes."""
    for label, value in (
        ("expected goal SHA-256", expected_goal_sha256),
        ("expected appendix SHA-256", expected_appendix_sha256),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")

    init_db(db_path)
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM targets WHERE slug = ?", (slug,)
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown target slug {slug!r}; scope the target first")
            target = dict(row)
            if target["status"] not in {"SCOPED", "PARKED_REHYDRATABLE"}:
                raise ValueError(
                    "legacy scope migration requires a SCOPED or "
                    "PARKED_REHYDRATABLE target"
                )
            if target.get("goal_sha256"):
                raise ValueError(
                    "legacy scope migration requires an absent recorded goal hash"
                )

            scope = _resolve_recorded_path(target.get("scope_path"))
            goal = _resolve_recorded_path(target.get("goal_path"))
            mirror = _resolve_recorded_path(target.get("mirror_path"))
            if scope is None:
                raise ValueError("legacy scope migration requires a recorded scope path")
            appendix = scope / "EVIDENCE_APPENDIX.md"
            if not appendix.is_file():
                raise ValueError(
                    "legacy scope migration requires the current Target Scoper "
                    "evidence appendix"
                )
            if goal is None or mirror is None:
                raise ValueError(
                    "legacy scope migration requires recorded goal and mirror paths"
                )
            errors = _validate_goal_contract(
                goal,
                mirror,
                resolve_currentness=True,
            )
            if errors:
                raise ValueError(
                    "legacy scope migration goal validation failed: "
                    + "; ".join(errors)
                )

            goal_sha256 = sha256_file(goal)
            mirror_sha256 = sha256_file(mirror)
            appendix_sha256 = sha256_file(appendix)
            if goal_sha256 != mirror_sha256:
                raise ValueError("legacy scope migration goal and mirror bytes changed")
            if goal_sha256 != expected_goal_sha256:
                raise ValueError("legacy scope migration goal SHA-256 does not match")
            if appendix_sha256 != expected_appendix_sha256:
                raise ValueError("legacy scope migration appendix SHA-256 does not match")

            now = utc_now()
            updated = conn.execute(
                """
                UPDATE targets
                SET goal_sha256 = ?, updated_at = ?
                WHERE slug = ? AND status = ? AND COALESCE(goal_sha256, '') = ''
                """,
                (goal_sha256, now, slug, target["status"]),
            )
            if updated.rowcount != 1:
                raise ValueError("legacy scope authority changed concurrently")
            metadata = {
                "appendix_path": str(appendix),
                "appendix_sha256": appendix_sha256,
                "goal_path": str(goal),
                "goal_sha256": goal_sha256,
                "mirror_path": str(mirror),
                "status": str(target["status"]),
            }
            conn.execute(
                """
                INSERT INTO events(slug, event_type, detail, metadata_json, created_at)
                VALUES (?, 'LEGACY_SCOPE_MIGRATED', ?, ?, ?)
                """,
                (
                    slug,
                    "Validated current Target Scoper appendix and byte-identical GOAL receipt",
                    json.dumps(metadata, sort_keys=True),
                    now,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    result = get_target(db_path, slug)
    assert result is not None
    return result


def refresh_final_rework_goal(
    db_path: Path,
    mailbox_db: Path,
    item_id: int,
    *,
    target_slug: str,
    product: str,
    version: str,
    workspace: Path = WORKSPACE,
) -> dict[str, Any]:
    """Refresh only a claimed Final Rework target's parked GOAL binding."""
    if not isinstance(item_id, int) or item_id <= 0:
        raise ValueError("final rework item must be a positive integer")
    db_path = Path(db_path).resolve()
    mailbox_db = Path(mailbox_db).resolve()
    workspace = Path(workspace).resolve()
    if not db_path.is_file() or not mailbox_db.is_file():
        raise ValueError("final rework GOAL refresh databases are unavailable")

    def recorded_path(value: object) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError("parked target has no recorded goal/mirror pair")
        path = Path(value)
        return path.resolve() if path.is_absolute() else (workspace / path).resolve()

    with closing(connect(db_path)) as conn:
        conn.execute("ATTACH DATABASE ? AS mailbox", (str(mailbox_db),))
        conn.execute("BEGIN IMMEDIATE")
        try:
            authority = conn.execute(
                """
                SELECT
                    wi.state,
                    wi.product AS item_product,
                    wi.version AS item_version,
                    wi.package_hash,
                    wi.package_path,
                    wi.revision,
                    wi.candidate_challenge_id,
                    cc.target_slug,
                    cc.product AS candidate_product,
                    cc.version AS candidate_version,
                    cc.package_number,
                    frr.id AS request_id,
                    frr.review_scope,
                    frr.prior_candidate_challenge_id
                FROM mailbox.work_items AS wi
                JOIN mailbox.candidate_challenges AS cc
                  ON cc.id = wi.candidate_challenge_id
                JOIN mailbox.final_rework_requests AS frr
                  ON frr.work_item_id = wi.id AND frr.state = 'CLAIMED'
                WHERE wi.id = ?
                ORDER BY frr.id DESC
                LIMIT 1
                """,
                (item_id,),
            ).fetchone()
            if (
                authority is None
                or authority["state"] != "FINAL_REWORK"
                or authority["target_slug"] != target_slug
                or authority["item_product"] != product
                or authority["candidate_product"] != product
                or authority["item_version"] != version
                or authority["candidate_version"] != version
                or authority["package_number"] is None
                or authority["review_scope"] not in {"EVIDENCE_ONLY", "SEMANTIC"}
                or authority["prior_candidate_challenge_id"]
                != authority["candidate_challenge_id"]
            ):
                raise ValueError(
                    "GOAL refresh requires the same claimed Final Rework item identity "
                    "and reviewed lineage"
                )
            package_match = re.match(
                r"^(\d+)_", Path(str(authority["package_path"])).name
            )
            if (
                package_match is None
                or int(package_match.group(1)) != int(authority["package_number"])
            ):
                raise ValueError(
                    "GOAL refresh requires matching claimed Final Rework package identity"
                )

            target = conn.execute(
                """
                SELECT slug, product, current_version, status, scope_path,
                       goal_path, mirror_path, goal_sha256
                FROM targets WHERE slug = ?
                """,
                (target_slug,),
            ).fetchone()
            if (
                target is None
                or target["product"] != product
                or str(target["current_version"] or "") != version
            ):
                raise ValueError("claimed Final Rework target identity does not match lifecycle")

            scope = recorded_path(target["scope_path"])
            appendix = scope / "EVIDENCE_APPENDIX.md"
            if not appendix.is_file():
                raise ValueError(
                    "claimed Final Rework requires the current Target Scoper "
                    "evidence appendix"
                )
            prior_hash = str(target["goal_sha256"] or "")
            if re.fullmatch(r"[0-9a-f]{64}", prior_hash) is None:
                raise ValueError(
                    "claimed Final Rework requires explicit legacy scope migration "
                    "before target-bound rework"
                )

            goal = recorded_path(target["goal_path"])
            mirror = recorded_path(target["mirror_path"])
            errors = _validate_goal_contract(goal, mirror)
            if errors:
                raise ValueError(
                    "parked Final Rework GOAL validation failed: " + "; ".join(errors)
                )
            current_hash = sha256_file(mirror)
            if current_hash == prior_hash:
                conn.commit()
                return {
                    "item_id": item_id,
                    "refreshed": False,
                    "goal_sha256": current_hash,
                    "status": str(target["status"]),
                    "target_slug": target_slug,
                }
            if target["status"] != "PARKED_REHYDRATABLE":
                raise ValueError(
                    "changed GOAL refresh requires the item's PARKED_REHYDRATABLE target"
                )

            now = utc_now()
            updated = conn.execute(
                """
                UPDATE targets
                SET goal_sha256 = ?, updated_at = ?
                WHERE slug = ? AND status = 'PARKED_REHYDRATABLE'
                  AND COALESCE(goal_sha256, '') = ?
                """,
                (current_hash, now, target_slug, prior_hash),
            )
            if updated.rowcount != 1:
                raise ValueError("parked Final Rework GOAL authority changed concurrently")
            metadata = {
                "item_id": item_id,
                "package_number": int(authority["package_number"]),
                "package_hash": str(authority["package_hash"]),
                "request_id": int(authority["request_id"]),
                "revision": int(authority["revision"]),
                "prior_goal_sha256": prior_hash,
                "goal_sha256": current_hash,
            }
            conn.execute(
                """
                INSERT INTO events(slug, event_type, detail, metadata_json, created_at)
                VALUES (?, 'FINAL_REWORK_GOAL_REFRESHED', ?, ?, ?)
                """,
                (
                    target_slug,
                    "Claimed Final Rework refreshed byte-identical parked GOAL authority",
                    json.dumps(metadata, sort_keys=True),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO mailbox.events(
                    work_item_id, actor, event_type, detail_json, created_at
                ) VALUES (?, 'hunter', 'FINAL_REWORK_GOAL_REFRESHED', ?, ?)
                """,
                (item_id, json.dumps(metadata, sort_keys=True), now),
            )
            conn.commit()
            return {
                "item_id": item_id,
                "refreshed": True,
                "goal_sha256": current_hash,
                "prior_goal_sha256": prior_hash,
                "status": "PARKED_REHYDRATABLE",
                "target_slug": target_slug,
            }
        except BaseException:
            conn.rollback()
            raise


def list_targets(db_path: Path, status: str | None = None) -> list[dict[str, Any]]:
    init_db(db_path)
    if status is not None:
        _validate_state(status)
    with closing(connect(db_path)) as conn:
        if status is None:
            rows = conn.execute("SELECT * FROM targets ORDER BY updated_at DESC, slug").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM targets WHERE status = ? ORDER BY updated_at DESC, slug",
                (status,),
            ).fetchall()
    return [dict(row) for row in rows]


def upsert_target(db_path: Path, record: dict[str, Any]) -> dict[str, Any]:
    init_db(db_path)
    unknown = set(record) - set(TARGET_FIELDS)
    if unknown:
        raise ValueError(f"unknown target fields: {', '.join(sorted(unknown))}")
    if not record.get("slug"):
        raise ValueError("slug is required")
    if not record.get("status"):
        raise ValueError("status is required")
    _validate_state(str(record["status"]))
    if record.get("fit_score") is not None:
        score = int(record["fit_score"])
        if score < 0 or score > 100:
            raise ValueError("fit_score must be between 0 and 100")
        record = {**record, "fit_score": score}

    existing = get_target(db_path, str(record["slug"])) or {}
    if record["status"] == "ACTIVE" and existing.get("status") != "ACTIVE":
        raise ValueError(
            "ACTIVE is an operator-authorized transition; use the activate command"
        )
    if existing.get("status") == "ACTIVE" and record["status"] != "ACTIVE":
        raise ValueError(
            "parking an ACTIVE target is an operator-authorized transition; "
            "use the park command or activate --switch-active"
        )
    merged = {field: record.get(field, existing.get(field)) for field in TARGET_FIELDS}
    if not merged.get("product"):
        raise ValueError("product is required for a new target")
    merged["updated_at"] = utc_now()

    columns = (*TARGET_FIELDS, "updated_at")
    placeholders = ", ".join("?" for _ in columns)
    updates = ", ".join(f"{column}=excluded.{column}" for column in columns if column != "slug")
    values = [merged.get(column) for column in columns]
    with closing(connect(db_path)) as conn:
        with conn:
            conn.execute(
                f"INSERT INTO targets ({', '.join(columns)}) VALUES ({placeholders}) "
                f"ON CONFLICT(slug) DO UPDATE SET {updates}",
                values,
            )
    result = get_target(db_path, str(merged["slug"]))
    assert result is not None
    return result


def complete_scope(
    db_path: Path,
    decision_path: Path,
    *,
    fetch_text: Any = None,
    publish_mirror: bool = False,
) -> dict[str, Any]:
    """Validate and atomically record a completed SCOPED target."""
    decision_path = Path(decision_path).resolve()
    payload = json.loads(decision_path.read_text(encoding="utf-8"))
    validator = _load_python_module(
        "jenny_scope_decision_validator",
        _target_scoper_script("validate_scope_decision.py"),
    )
    errors = list(validator.validate(payload))
    if errors:
        raise ValueError("scope decision validation failed: " + "; ".join(errors))
    if payload.get("verdict") != "SCOPED":
        raise ValueError("complete-scope requires verdict SCOPED")

    target = payload["target"]
    paths = payload["paths"]

    def resolve_path(value: str) -> Path:
        candidate = Path(value)
        return candidate.resolve() if candidate.is_absolute() else (WORKSPACE / candidate).resolve()

    goal_path = resolve_path(paths["goal"])
    mirror_path = resolve_path(paths["mirror"])
    scope_dir = resolve_path(paths["scope_dir"])
    bundle_errors = list(
        validator.validate_bundle(payload, scope_dir, workspace=WORKSPACE)
    )
    if bundle_errors:
        raise ValueError(
            "scope bundle validation failed: " + "; ".join(bundle_errors)
        )
    appendix_path = scope_dir / "EVIDENCE_APPENDIX.md"
    if publish_mirror:
        if mirror_path.exists():
            raise ValueError("publish-mirror requires an absent destination mirror")
        if not appendix_path.is_file():
            raise ValueError(f"required evidence appendix does not exist: {appendix_path}")
        goal_errors = _validate_goal_source(
            goal_path,
            resolve_currentness=True,
            fetch_text=fetch_text,
            required_schema_version=2,
        )
    else:
        goal_errors = _validate_goal_contract(
            goal_path,
            mirror_path,
            resolve_currentness=True,
            fetch_text=fetch_text,
            required_schema_version=2,
        )
    if goal_errors:
        raise ValueError("scope goal validation failed: " + "; ".join(goal_errors))
    appendix_pointer_errors = _validate_declared_evidence_appendix(
        goal_path, appendix_path
    )
    if appendix_pointer_errors:
        raise ValueError(
            "scope evidence appendix validation failed: "
            + "; ".join(appendix_pointer_errors)
        )

    slug = str(target["slug"])
    now = utc_now()
    score = int(payload["score"]["total"])
    reasons = payload.get("decisive_reasons") or []
    reason = "; ".join(str(value) for value in reasons)
    record = {
        "slug": slug,
        "product": str(target["product"]),
        "vendor": str(target.get("vendor") or ""),
        "category": str(target.get("category") or ""),
        "status": "SCOPED",
        "admission_decision": "SCOPED",
        "fit_score": score,
        "current_version": str(target["current_version"]),
        "scope_path": str(scope_dir),
        "goal_path": str(goal_path),
        "mirror_path": str(mirror_path),
        "goal_sha256": sha256_file(goal_path if publish_mirror else mirror_path),
        "reason": reason,
        "scoped_at": str(payload["generated_at"]),
        "cleaned_at": None,
        "updated_at": now,
    }
    columns = (*TARGET_FIELDS, "updated_at")
    placeholders = ", ".join("?" for _ in columns)
    updates = ", ".join(
        f"{column}=excluded.{column}" for column in columns if column != "slug"
    )
    published_target_appendix: Path | None = None
    if publish_mirror:
        published_target_appendix = _publish_new_target_scope_pair(
            goal_path,
            appendix_path,
            mirror_path,
            fetch_text=fetch_text,
        )
    try:
        init_db(db_path)
        with closing(connect(db_path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT status FROM targets WHERE slug = ?", (slug,)
                ).fetchone()
                if existing is not None and existing["status"] == "ACTIVE":
                    raise ValueError("complete-scope cannot overwrite an ACTIVE target")
                conn.execute(
                    f"INSERT INTO targets ({', '.join(columns)}) VALUES ({placeholders}) "
                    f"ON CONFLICT(slug) DO UPDATE SET {updates}",
                    [record[column] for column in columns],
                )
                conn.execute(
                    "INSERT INTO events "
                    "(slug, event_type, detail, metadata_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        slug,
                        "SCOPED",
                        "Validated target scope completed",
                        json.dumps(
                            {
                                "decision_path": str(decision_path),
                                "goal_sha256": record["goal_sha256"],
                                "fit_score": score,
                            },
                            sort_keys=True,
                        ),
                        now,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    except BaseException:
        if publish_mirror:
            mirror_path.unlink(missing_ok=True)
            if published_target_appendix is not None:
                published_target_appendix.unlink(missing_ok=True)
        raise
    result = get_target(db_path, slug)
    assert result is not None
    return result


def refresh_scoped_scope(
    db_path: Path,
    decision_path: Path,
    *,
    expected_goal_sha256: str,
    operator_instruction: str,
    fetch_text: Any = None,
) -> dict[str, Any]:
    """Compare-and-swap a validated revision onto one inactive SCOPED target."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_goal_sha256) is None:
        raise ValueError(
            "expected goal SHA-256 must be 64 lowercase hexadecimal characters"
        )
    instruction = operator_instruction.strip()
    if not instruction:
        raise ValueError("the current operator instruction is required for scope refresh")

    decision_path = Path(decision_path).resolve()
    payload = json.loads(decision_path.read_text(encoding="utf-8"))
    validator = _load_python_module(
        "jenny_scoped_scope_decision_validator",
        _target_scoper_script("validate_scope_decision.py"),
    )
    errors = list(validator.validate(payload))
    if errors:
        raise ValueError("scope decision validation failed: " + "; ".join(errors))
    if payload.get("verdict") != "SCOPED":
        raise ValueError("SCOPED target refresh requires verdict SCOPED")

    target_payload = payload["target"]
    paths = payload["paths"]

    def resolve_path(value: str) -> Path:
        candidate = Path(value)
        return (
            candidate.resolve()
            if candidate.is_absolute()
            else (WORKSPACE / candidate).resolve()
        )

    scope_dir = resolve_path(paths["scope_dir"])
    goal_path = resolve_path(paths["goal"])
    mirror_path = resolve_path(paths["mirror"])
    bundle_errors = list(
        validator.validate_bundle(payload, scope_dir, workspace=WORKSPACE)
    )
    if bundle_errors:
        raise ValueError(
            "scope bundle validation failed: " + "; ".join(bundle_errors)
        )
    appendix_path = scope_dir / "EVIDENCE_APPENDIX.md"
    if not appendix_path.is_file():
        raise ValueError(
            f"SCOPED target refresh requires EVIDENCE_APPENDIX.md: {appendix_path}"
        )
    goal_errors = _validate_goal_source(
        goal_path,
        resolve_currentness=True,
        fetch_text=fetch_text,
        required_schema_version=2,
    )
    if goal_errors:
        raise ValueError(
            "SCOPED target refresh goal validation failed: " + "; ".join(goal_errors)
        )
    appendix_pointer_errors = _validate_declared_evidence_appendix(
        goal_path, appendix_path
    )
    if appendix_pointer_errors:
        raise ValueError(
            "SCOPED target refresh evidence appendix validation failed: "
            + "; ".join(appendix_pointer_errors)
        )

    identifiers = {
        str(target_payload["slug"]),
        str(target_payload["product"]),
    }
    if not _instruction_affirmatively_names_target(
        instruction,
        (r"\bprep(?:are)?\b", r"\bscope\b", r"\brefresh\b", r"\bupdate\b", r"\brevise\b"),
        identifiers,
    ):
        raise ValueError(
            "operator instruction must affirmatively authorize preparation or refresh "
            "of the exact target"
        )

    goal_bytes = goal_path.read_bytes()
    goal_hash = hashlib.sha256(goal_bytes).hexdigest()
    if goal_hash == expected_goal_sha256:
        raise ValueError("SCOPED target refresh requires changed validated GOAL bytes")
    appendix_hash = sha256_file(appendix_path)
    slug = str(target_payload["slug"])
    score = int(payload["score"]["total"])
    reason = "; ".join(str(value) for value in payload.get("decisive_reasons") or [])
    now = utc_now()

    init_db(db_path)
    mirror_path.parent.mkdir(parents=True, exist_ok=True)
    staged_path = mirror_path.with_name(mirror_path.name + f".refresh-{os.getpid()}.tmp")
    target_appendix = mirror_path.parent / "EVIDENCE_APPENDIX.md"
    staged_appendix = target_appendix.with_name(
        target_appendix.name + f".refresh-{os.getpid()}.tmp"
    )
    if staged_path.exists() or staged_appendix.exists():
        raise ValueError("SCOPED target refresh staging path already exists")
    staged_path.write_bytes(goal_bytes)
    staged_appendix.write_bytes(appendix_path.read_bytes())
    replaced_mirror = False
    replaced_appendix = False
    prior_mirror_bytes: bytes | None = None
    prior_appendix_bytes: bytes | None = None
    try:
        with closing(connect(db_path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM targets WHERE slug = ?", (slug,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"unknown target slug {slug!r}; scope the target first")
                target = dict(row)
                if target["status"] != "SCOPED":
                    raise ValueError(
                        "SCOPED target refresh requires the target to remain SCOPED"
                    )
                if str(target.get("goal_sha256") or "") != expected_goal_sha256:
                    raise ValueError(
                        "SCOPED target refresh compare-and-swap failed: recorded prior hash changed"
                    )
                if target["product"] != target_payload["product"]:
                    raise ValueError("SCOPED target refresh cannot change target product identity")
                recorded_goal = _resolve_recorded_path(target.get("goal_path"))
                recorded_mirror = _resolve_recorded_path(target.get("mirror_path"))
                if recorded_goal != goal_path or recorded_mirror != mirror_path:
                    raise ValueError(
                        "SCOPED target refresh cannot change the recorded goal or mirror path"
                    )
                if not mirror_path.is_file():
                    raise ValueError("SCOPED target refresh requires the recorded prior mirror")
                prior_mirror_bytes = mirror_path.read_bytes()
                if hashlib.sha256(prior_mirror_bytes).hexdigest() != expected_goal_sha256:
                    raise ValueError(
                        "SCOPED target refresh compare-and-swap failed: prior mirror bytes changed"
                    )
                if (
                    goal_path.read_bytes() != goal_bytes
                    or sha256_file(appendix_path) != appendix_hash
                    or staged_path.read_bytes() != goal_bytes
                    or staged_appendix.read_bytes() != appendix_path.read_bytes()
                ):
                    raise ValueError("SCOPED target refresh bundle bytes changed during validation")

                prior_appendix_bytes = (
                    target_appendix.read_bytes() if target_appendix.is_file() else None
                )
                os.replace(staged_appendix, target_appendix)
                replaced_appendix = True
                os.replace(staged_path, mirror_path)
                replaced_mirror = True
                mirror_errors = _validate_goal_source(
                    mirror_path,
                    resolve_currentness=True,
                    fetch_text=fetch_text,
                    required_schema_version=2,
                )
                if mirror_errors:
                    raise ValueError(
                        "refreshed Hunter mirror validation failed: "
                        + "; ".join(mirror_errors)
                    )
                updated = conn.execute(
                    """
                    UPDATE targets
                    SET vendor = ?, category = ?, admission_decision = 'SCOPED',
                        fit_score = ?, current_version = ?, scope_path = ?,
                        goal_path = ?, mirror_path = ?, goal_sha256 = ?, reason = ?,
                        scoped_at = ?, updated_at = ?
                    WHERE slug = ? AND status = 'SCOPED' AND goal_sha256 = ?
                    """,
                    (
                        str(target_payload.get("vendor") or ""),
                        str(target_payload.get("category") or ""),
                        score,
                        str(target_payload["current_version"]),
                        str(scope_dir),
                        str(goal_path),
                        str(mirror_path),
                        goal_hash,
                        reason,
                        str(payload["generated_at"]),
                        now,
                        slug,
                        expected_goal_sha256,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError(
                        "SCOPED target refresh compare-and-swap failed concurrently"
                    )
                metadata = {
                    "appendix_path": str(appendix_path),
                    "appendix_sha256": appendix_hash,
                    "decision_path": str(decision_path),
                    "goal_path": str(goal_path),
                    "goal_sha256": goal_hash,
                    "mirror_path": str(mirror_path),
                    "operator_instruction": instruction,
                    "prior_goal_sha256": expected_goal_sha256,
                    "scope_revision": int(payload["scope_revision"]),
                    "status": "SCOPED",
                }
                conn.execute(
                    """
                    INSERT INTO events(slug, event_type, detail, metadata_json, created_at)
                    VALUES (?, 'SCOPE_REFRESHED', ?, ?, ?)
                    """,
                    (
                        slug,
                        "Validated inactive SCOPED target and atomically refreshed its GOAL mirror",
                        json.dumps(metadata, sort_keys=True),
                        now,
                    ),
                )
                conn.commit()
            except BaseException:
                conn.rollback()
                if replaced_mirror and prior_mirror_bytes is not None:
                    restore_path = mirror_path.with_name(
                        mirror_path.name + f".restore-{os.getpid()}.tmp"
                    )
                    restore_path.write_bytes(prior_mirror_bytes)
                    os.replace(restore_path, mirror_path)
                    replaced_mirror = False
                if replaced_appendix:
                    if prior_appendix_bytes is None:
                        target_appendix.unlink(missing_ok=True)
                    else:
                        restore_appendix = target_appendix.with_name(
                            target_appendix.name + f".restore-{os.getpid()}.tmp"
                        )
                        restore_appendix.write_bytes(prior_appendix_bytes)
                        os.replace(restore_appendix, target_appendix)
                    replaced_appendix = False
                raise
    finally:
        staged_path.unlink(missing_ok=True)
        staged_appendix.unlink(missing_ok=True)

    if mirror_path.read_bytes() != goal_bytes:
        raise RuntimeError("refreshed goal mirror bytes differ from validated source")
    if target_appendix.read_bytes() != appendix_path.read_bytes():
        raise RuntimeError(
            "refreshed evidence appendix bytes differ from validated source"
        )
    result = get_target(db_path, slug)
    assert result is not None
    return result


def refresh_active_scope(
    db_path: Path,
    decision_path: Path,
    *,
    expected_goal_sha256: str,
    operator_instruction: str,
    fetch_text: Any = None,
) -> dict[str, Any]:
    """Atomically rebind one ACTIVE target to a fully validated scope revision."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_goal_sha256) is None:
        raise ValueError(
            "expected goal SHA-256 must be 64 lowercase hexadecimal characters"
        )
    instruction = operator_instruction.strip()
    if not instruction:
        raise ValueError("the current operator instruction is required for scope refresh")

    decision_path = Path(decision_path).resolve()
    payload = json.loads(decision_path.read_text(encoding="utf-8"))
    validator = _load_python_module(
        "jenny_active_scope_decision_validator",
        _target_scoper_script("validate_scope_decision.py"),
    )
    errors = list(validator.validate(payload))
    if errors:
        raise ValueError("scope decision validation failed: " + "; ".join(errors))
    if payload.get("verdict") != "SCOPED":
        raise ValueError("active scope refresh requires verdict SCOPED")

    target_payload = payload["target"]
    paths = payload["paths"]

    def resolve_path(value: str) -> Path:
        candidate = Path(value)
        return (
            candidate.resolve()
            if candidate.is_absolute()
            else (WORKSPACE / candidate).resolve()
        )

    scope_dir = resolve_path(paths["scope_dir"])
    goal_path = resolve_path(paths["goal"])
    mirror_path = resolve_path(paths["mirror"])
    bundle_errors = list(
        validator.validate_bundle(payload, scope_dir, workspace=WORKSPACE)
    )
    if bundle_errors:
        raise ValueError(
            "scope bundle validation failed: " + "; ".join(bundle_errors)
        )
    appendix_path = scope_dir / "EVIDENCE_APPENDIX.md"
    if not appendix_path.is_file():
        raise ValueError(
            f"active scope refresh requires EVIDENCE_APPENDIX.md: {appendix_path}"
        )
    if (
        not goal_path.is_file()
        or not mirror_path.is_file()
        or goal_path.read_bytes() != mirror_path.read_bytes()
    ):
        raise ValueError(
            "active scope refresh requires a byte-identical goal/mirror pair"
        )
    goal_errors = _validate_goal_contract(
        goal_path,
        mirror_path,
        resolve_currentness=True,
        fetch_text=fetch_text,
        required_schema_version=2,
    )
    if goal_errors:
        raise ValueError(
            "active scope refresh goal validation failed: " + "; ".join(goal_errors)
        )
    appendix_pointer_errors = _validate_declared_evidence_appendix(
        goal_path, appendix_path
    )
    if appendix_pointer_errors:
        raise ValueError(
            "active scope refresh evidence appendix validation failed: "
            + "; ".join(appendix_pointer_errors)
        )

    accepted_paths = {
        _normalize_instruction_path(str(goal_path)),
        _normalize_instruction_path(str(mirror_path)),
        _normalize_instruction_path(str(paths["goal"])),
        _normalize_instruction_path(str(paths["mirror"])),
    }
    if not _instruction_affirmatively_names_path(
        instruction,
        (r"\brefresh\b", r"\bupdate\b", r"\brebind\b"),
        accepted_paths,
    ):
        raise ValueError(
            "operator instruction must affirmatively authorize refresh of the exact goal path"
        )

    slug = str(target_payload["slug"])
    current_hash = sha256_file(mirror_path)
    if current_hash == expected_goal_sha256:
        raise ValueError("active scope refresh requires changed validated GOAL bytes")
    appendix_hash = sha256_file(appendix_path)
    now = utc_now()
    score = int(payload["score"]["total"])
    reason = "; ".join(str(value) for value in payload.get("decisive_reasons") or [])

    init_db(db_path)
    target_appendix = mirror_path.parent / "EVIDENCE_APPENDIX.md"
    staged_appendix = target_appendix.with_name(
        target_appendix.name + f".refresh-{os.getpid()}.tmp"
    )
    if staged_appendix.exists():
        raise ValueError("active scope refresh appendix staging path already exists")
    staged_appendix.write_bytes(appendix_path.read_bytes())
    prior_appendix_bytes = (
        target_appendix.read_bytes() if target_appendix.is_file() else None
    )
    replaced_appendix = False
    try:
        with closing(connect(db_path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM targets WHERE slug = ?", (slug,)
                ).fetchone()
                if row is None:
                    raise ValueError(f"unknown target slug {slug!r}; scope the target first")
                target = dict(row)
                if target["status"] != "ACTIVE":
                    raise ValueError("active scope refresh requires the target to remain ACTIVE")
                if str(target.get("goal_sha256") or "") != expected_goal_sha256:
                    raise ValueError(
                        "active scope refresh compare-and-swap failed: recorded prior hash changed"
                    )
                if target["product"] != target_payload["product"]:
                    raise ValueError("active scope refresh cannot change target product identity")
                if (
                    sha256_file(goal_path) != current_hash
                    or sha256_file(mirror_path) != current_hash
                    or sha256_file(appendix_path) != appendix_hash
                    or staged_appendix.read_bytes() != appendix_path.read_bytes()
                ):
                    raise ValueError("active scope refresh bundle bytes changed during validation")

                os.replace(staged_appendix, target_appendix)
                replaced_appendix = True
                mirror_errors = _validate_goal_source(
                    mirror_path,
                    resolve_currentness=True,
                    fetch_text=fetch_text,
                    required_schema_version=2,
                )
                if mirror_errors:
                    raise ValueError(
                        "refreshed Hunter mirror validation failed: "
                        + "; ".join(mirror_errors)
                    )
                updated = conn.execute(
                """
                UPDATE targets
                SET vendor = ?, category = ?, admission_decision = 'SCOPED',
                    fit_score = ?, current_version = ?, scope_path = ?,
                    goal_path = ?, mirror_path = ?, goal_sha256 = ?, reason = ?,
                    scoped_at = ?, updated_at = ?
                WHERE slug = ? AND status = 'ACTIVE' AND goal_sha256 = ?
                """,
                (
                    str(target_payload.get("vendor") or ""),
                    str(target_payload.get("category") or ""),
                    score,
                    str(target_payload["current_version"]),
                    str(scope_dir),
                    str(goal_path),
                    str(mirror_path),
                    current_hash,
                    reason,
                    str(payload["generated_at"]),
                    now,
                    slug,
                    expected_goal_sha256,
                ),
            )
                if updated.rowcount != 1:
                    raise ValueError(
                        "active scope refresh compare-and-swap failed concurrently"
                    )
                metadata = {
                    "appendix_path": str(appendix_path),
                    "appendix_sha256": appendix_hash,
                    "decision_path": str(decision_path),
                    "goal_path": str(goal_path),
                    "goal_sha256": current_hash,
                    "mirror_appendix_path": str(target_appendix),
                    "operator_instruction": instruction,
                    "prior_goal_sha256": expected_goal_sha256,
                    "scope_revision": int(payload["scope_revision"]),
                }
                conn.execute(
                """
                INSERT INTO events(slug, event_type, detail, metadata_json, created_at)
                VALUES (?, 'SCOPE_REFRESHED', ?, ?, ?)
                """,
                (
                    slug,
                    "Validated ACTIVE target scope refreshed by exact operator authority",
                    json.dumps(metadata, sort_keys=True),
                    now,
                ),
            )
                conn.commit()
            except Exception:
                conn.rollback()
                if replaced_appendix:
                    if prior_appendix_bytes is None:
                        target_appendix.unlink(missing_ok=True)
                    else:
                        restore_appendix = target_appendix.with_name(
                            target_appendix.name + f".restore-{os.getpid()}.tmp"
                        )
                        restore_appendix.write_bytes(prior_appendix_bytes)
                        os.replace(restore_appendix, target_appendix)
                    replaced_appendix = False
                raise
    finally:
        staged_appendix.unlink(missing_ok=True)

    if target_appendix.read_bytes() != appendix_path.read_bytes():
        raise RuntimeError(
            "refreshed evidence appendix bytes differ from validated source"
        )

    result = get_target(db_path, slug)
    assert result is not None
    return result


def activate_target(
    db_path: Path,
    slug: str,
    operator_instruction: str,
    switch_active: bool = False,
) -> dict[str, Any]:
    """Activate one prepared target under a recorded operator instruction."""
    init_db(db_path)
    instruction = operator_instruction.strip()
    if not instruction:
        raise ValueError("the current operator instruction is required for activation")

    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM targets WHERE slug = ?", (slug,)
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown target slug {slug!r}; scope the target first")
            target = dict(row)
            mirror, goal_sha256 = _validate_activation_goal(target, instruction)
            scope = _resolve_recorded_path(target.get("scope_path"))
            appendix = scope / "EVIDENCE_APPENDIX.md" if scope is not None else None
            recorded_hash = str(target.get("goal_sha256") or "")
            if appendix is None or not appendix.is_file() or not recorded_hash:
                raise ValueError(
                    "target activation requires explicit legacy scope migration "
                    "with a current Target Scoper evidence appendix"
                )
            if recorded_hash != goal_sha256:
                raise ValueError(
                    "target activation checkout failed: recorded goal hash does not "
                    "match the byte-identical goal/mirror pair"
                )
            if target["status"] == "ACTIVE":
                conn.commit()
                current = conn.execute(
                    "SELECT * FROM targets WHERE slug = ?", (slug,)
                ).fetchone()
                assert current is not None
                return dict(current)
            if target["status"] not in {"SCOPED", "PARKED_REHYDRATABLE"}:
                raise ValueError(
                    f"cannot activate {slug!r} from {target['status']}; "
                    "expected SCOPED or PARKED_REHYDRATABLE"
                )

            active_rows = conn.execute(
                "SELECT slug, status FROM targets "
                "WHERE status = 'ACTIVE' AND slug <> ? ORDER BY slug",
                (slug,),
            ).fetchall()
            active_slugs = [str(active["slug"]) for active in active_rows]
            if active_slugs and not switch_active:
                raise ValueError(
                    "another target is already ACTIVE: "
                    + ", ".join(active_slugs)
                    + "; repeat with --switch-active only when the operator explicitly switched targets"
                )

            now = utc_now()
            for active_slug in active_slugs:
                conn.execute(
                    "UPDATE targets SET status = ?, updated_at = ? WHERE slug = ?",
                    ("PARKED_REHYDRATABLE", now, active_slug),
                )
                conn.execute(
                    "INSERT INTO events "
                    "(slug, event_type, detail, metadata_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        active_slug,
                        "PARKED_FOR_TARGET_SWITCH",
                        f"Operator switched active target to {slug}",
                        json.dumps(
                            {
                                "activated_slug": slug,
                                "operator_instruction": instruction,
                            },
                            sort_keys=True,
                        ),
                        now,
                    ),
                )

            conn.execute(
                "UPDATE targets SET status = ?, mirror_path = ?, goal_sha256 = ?, "
                "updated_at = ? WHERE slug = ?",
                ("ACTIVE", str(mirror), goal_sha256, now, slug),
            )
            conn.execute(
                "INSERT INTO events "
                "(slug, event_type, detail, metadata_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    slug,
                    "ACTIVATED",
                    "Target activated by explicit operator instruction",
                    json.dumps(
                        {
                            "operator_instruction": instruction,
                            "previous_status": target["status"],
                            "switched_from": active_slugs,
                            "goal_path": str(mirror),
                            "goal_sha256": goal_sha256,
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError as error:
            conn.rollback()
            raise ValueError(
                "another target became ACTIVE during activation; retry from current state"
            ) from error
        except Exception:
            conn.rollback()
            raise

    result = get_target(db_path, slug)
    assert result is not None
    return result


def _instruction_authorizes_target_park(
    instruction: str,
    target: dict[str, Any],
) -> bool:
    if not _instruction_is_affirmative(
        instruction,
        (
            r"\bpark\b",
            r"\bstand\s+down\b",
            r"\bstop\b.*\b(?:target|goal|hunt)\b",
            r"\bretire\b",
            r"\bswitch\s+away\b",
        ),
    ):
        return False
    normalized = " ".join(instruction.casefold().split())
    if re.search(r"\b(?:continue|keep)\b.*\b(?:active|hunt|target|working)\b", normalized):
        return False
    tokens = set(re.findall(r"[a-z0-9]+", instruction.casefold()))
    has_explicit_target_scope = bool(tokens & TARGET_SCOPE_WORDS)
    has_package_scope = bool(tokens & PACKAGE_SCOPE_WORDS)
    if has_package_scope and not has_explicit_target_scope:
        return False

    identity_text = " ".join(
        str(target.get(field) or "") for field in ("slug", "product", "vendor")
    )
    identity_tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", identity_text.casefold())
        if len(token) >= 3 and token not in TARGET_IDENTIFIER_STOPWORDS
    }
    return has_explicit_target_scope or bool(tokens & identity_tokens)


def park_target(
    db_path: Path,
    slug: str,
    operator_instruction: str,
) -> dict[str, Any]:
    """Park one active target under a recorded operator instruction."""
    init_db(db_path)
    instruction = operator_instruction.strip()
    if not instruction:
        raise ValueError("the current operator instruction is required for parking")

    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM targets WHERE slug = ?", (slug,)
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown target slug {slug!r}; scope the target first")
            target = dict(row)
            if target["status"] == "PARKED_REHYDRATABLE":
                return target
            if target["status"] != "ACTIVE":
                raise ValueError(
                    f"cannot park {slug!r} from {target['status']}; expected ACTIVE"
                )
            if not _instruction_authorizes_target_park(instruction, target):
                raise ValueError(
                    "the operator instruction does not establish target-level parking authority; "
                    "it must explicitly name the target or say target, hunt, or goal, and a "
                    "package-scoped instruction cannot park the target"
                )

            now = utc_now()
            conn.execute(
                "UPDATE targets SET status = ?, updated_at = ? WHERE slug = ?",
                ("PARKED_REHYDRATABLE", now, slug),
            )
            conn.execute(
                "INSERT INTO events "
                "(slug, event_type, detail, metadata_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    slug,
                    "PARKED_BY_OPERATOR",
                    "Target parked by explicit operator instruction",
                    json.dumps(
                        {
                            "operator_instruction": instruction,
                            "previous_status": target["status"],
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    result = get_target(db_path, slug)
    assert result is not None
    return result


def add_event(
    db_path: Path,
    slug: str,
    event_type: str,
    detail: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    if get_target(db_path, slug) is None:
        raise ValueError(f"unknown target slug {slug!r}; upsert the target first")
    if not event_type.strip() or not detail.strip():
        raise ValueError("event_type and detail are required")
    created_at = utc_now()
    metadata_json = json.dumps(metadata, sort_keys=True) if metadata is not None else None
    with closing(connect(db_path)) as conn:
        with conn:
            cursor = conn.execute(
                "INSERT INTO events (slug, event_type, detail, metadata_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (slug, event_type, detail, metadata_json, created_at),
            )
            event_id = cursor.lastrowid
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    assert row is not None
    return dict(row)


DIMINISHING_PACKAGE_REFERENCE = re.compile(
    r"(?i)\b(?P<kind>package|item)\s*#?\s*(?P<number>\d+)\b"
)


def validate_diminishing_returns_marker(
    workspace: Path,
    slug: str,
    marker_path: Path,
) -> dict[str, Any]:
    workspace = Path(workspace).resolve()
    marker = Path(marker_path).resolve()
    expected_root = (workspace / "targets" / slug).resolve()
    try:
        marker.relative_to(expected_root)
    except ValueError as error:
        raise ValueError(
            "diminishing-return marker must remain under its target directory"
        ) from error
    if not marker.is_file():
        raise ValueError(f"diminishing-return marker does not exist: {marker}")
    try:
        text = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("diminishing-return marker is not readable UTF-8") from error

    references = sorted(
        {
            (match.group("kind").casefold(), int(match.group("number")))
            for match in DIMINISHING_PACKAGE_REFERENCE.finditer(text)
        }
    )
    if not references:
        return {"slug": slug, "marker": str(marker), "package_references": []}

    mailbox_db = (
        workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
    )
    if not mailbox_db.is_file():
        raise ValueError(
            "diminishing-return package references require the review mailbox database"
        )
    uri = mailbox_db.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=1)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        package_numbers = [number for kind, number in references if kind == "package"]
        item_ids = [number for kind, number in references if kind == "item"]
        package_bindings: dict[int, str] = {}
        item_bindings: dict[int, str] = {}
        if package_numbers:
            placeholders = ", ".join("?" for _ in package_numbers)
            for row in connection.execute(
                f"SELECT package_number, target_slug FROM candidate_challenges "
                f"WHERE package_number IN ({placeholders})",
                package_numbers,
            ):
                package_bindings[int(row["package_number"])] = str(
                    row["target_slug"] or ""
                )
        if item_ids:
            placeholders = ", ".join("?" for _ in item_ids)
            for row in connection.execute(
                f"""
                SELECT wi.id AS item_id, cc.target_slug
                FROM work_items AS wi
                LEFT JOIN candidate_challenges AS cc
                  ON cc.id = wi.candidate_challenge_id
                WHERE wi.id IN ({placeholders})
                """,
                item_ids,
            ):
                item_bindings[int(row["item_id"])] = str(row["target_slug"] or "")

    for kind, reference in references:
        bindings = package_bindings if kind == "package" else item_bindings
        if reference not in bindings or not bindings[reference]:
            raise ValueError(
                f"diminishing-return {kind} {reference} is not bound in workflow state"
            )
        if bindings[reference] != slug:
            raise ValueError(
                f"diminishing-return {kind} {reference} belongs to target "
                f"{bindings[reference]}, not {slug}"
            )
    return {
        "slug": slug,
        "marker": str(marker),
        "package_references": [
            number for kind, number in references if kind == "package"
        ],
        "item_references": [number for kind, number in references if kind == "item"],
    }


def _heading_text(text: str) -> str:
    return "\n".join(line.lstrip("#").strip().lower() for line in text.splitlines() if line.startswith("#"))


def validate_goal(goal_path: Path, mirror_path: Path | None = None) -> list[str]:
    goal_path = Path(goal_path)
    if not goal_path.is_file():
        return [f"goal file does not exist: {goal_path}"]
    if _is_compact_goal(goal_path):
        if mirror_path is not None:
            return _validate_goal_contract(goal_path, Path(mirror_path))
        return _validate_goal_source(goal_path)

    errors: list[str] = []
    raw = goal_path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"goal is not valid UTF-8: {exc}"]

    headings = _heading_text(text)
    for display, aliases in REQUIRED_GOAL_SECTIONS.items():
        if not any(alias in headings for alias in aliases):
            errors.append(f"missing required goal section: {display}")
    for label, pattern in UNFINISHED_PATTERNS:
        if pattern.search(text):
            errors.append(f"unfinished marker present: {label}")
    for label in HISTORICAL_LABELS:
        if f"{label}:" not in text:
            errors.append(f"missing historical lineage label: {label}")
    if mirror_path is not None:
        mirror_path = Path(mirror_path)
        if not mirror_path.is_file():
            errors.append(f"mirror file does not exist: {mirror_path}")
        elif mirror_path.read_bytes() != raw:
            errors.append("goal and mirror bytes differ")
    return errors


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _protected_roots(workspace: Path, slug: str) -> tuple[Path, ...]:
    return (
        workspace / "ZDI",
        workspace / "ZDI_STAGING",
        workspace / "notes",
        workspace / "targets" / slug / "findings",
        workspace / ".codex",
        workspace / "skills",
        workspace / "tools",
    )


def _registered_hyperv_disk_attachments() -> tuple[list[dict[str, str]], list[str]]:
    if os.name != "nt":
        return [], []
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if powershell is None:
        return [], ["cannot inventory registered Hyper-V disks: PowerShell is unavailable"]
    script = r"""
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    ConvertTo-Json -InputObject @() -Compress
    exit 0
}
$attachments = @()
foreach ($vm in @(Get-VM -ErrorAction Stop)) {
    foreach ($disk in @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)) {
        if ($disk.Path) {
            $attachments += [pscustomobject]@{
                vm_name = [string]$vm.Name
                path = [string]$disk.Path
            }
        }
    }
}
ConvertTo-Json -InputObject @($attachments) -Compress
"""
    try:
        completed = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], [f"cannot inventory registered Hyper-V disks: {type(exc).__name__}"]
    if completed.returncode != 0:
        return [], [
            "cannot inventory registered Hyper-V disks: "
            f"PowerShell exited {completed.returncode}"
        ]
    try:
        payload = json.loads(completed.stdout.strip() or "[]")
    except json.JSONDecodeError:
        return [], ["cannot inventory registered Hyper-V disks: invalid JSON"]
    if not isinstance(payload, list):
        return [], ["cannot inventory registered Hyper-V disks: result is not an array"]
    attachments: list[dict[str, str]] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            return [], [
                "cannot inventory registered Hyper-V disks: "
                f"entry {index} is not an object"
            ]
        vm_name = str(entry.get("vm_name", "")).strip()
        disk_path = str(entry.get("path", "")).strip()
        if not vm_name or not disk_path or not Path(disk_path).is_absolute():
            return [], [
                "cannot inventory registered Hyper-V disks: "
                f"entry {index} is incomplete"
            ]
        attachments.append({"vm_name": vm_name, "path": disk_path})
    return attachments, []


def validate_cleanup_manifest(manifest_path: Path, workspace: Path = WORKSPACE) -> list[str]:
    manifest_path = Path(manifest_path)
    workspace = Path(workspace).resolve()
    errors: list[str] = []
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"cannot read cleanup manifest: {exc}"]
    if not isinstance(data, dict):
        return ["cleanup manifest must be a JSON object"]

    slug = str(data.get("target_slug", "")).strip()
    if not slug:
        errors.append("target_slug is required")
    if not data.get("target_root"):
        errors.append("target_root is required")
    resources = data.get("resources")
    if not isinstance(resources, list):
        return errors + ["resources must be an array"]

    protected = tuple(path.resolve() for path in _protected_roots(workspace, slug))
    seen_ids: set[str] = set()
    delete_candidates: list[tuple[str, Path]] = []
    planned_hyperv_removals: set[str] = set()
    for index, resource in enumerate(resources):
        prefix = f"resources[{index}]"
        if not isinstance(resource, dict):
            errors.append(f"{prefix} must be an object")
            continue
        resource_id = str(resource.get("resource_id", "")).strip()
        if not resource_id:
            errors.append(f"{prefix}.resource_id is required")
        elif resource_id in seen_ids:
            errors.append(f"{prefix}.resource_id is duplicated: {resource_id}")
        seen_ids.add(resource_id)

        classification = resource.get("classification")
        action = resource.get("planned_action")
        external_resource = str(resource.get("external_resource", "")).strip()
        if classification not in {"PRESERVE", "REHYDRATABLE", "AMBIGUOUS_OR_SHARED"}:
            errors.append(f"{prefix}.classification is invalid")
        if action not in {"PRESERVE", "DELETE", "LEAVE"}:
            errors.append(f"{prefix}.planned_action is invalid")
        if action == "DELETE":
            if classification != "REHYDRATABLE":
                errors.append(f"{prefix}: DELETE requires REHYDRATABLE classification")
            if not str(resource.get("ownership_evidence", "")).strip():
                errors.append(f"{prefix}: DELETE requires ownership_evidence")
            if not str(resource.get("restore_source", "")).strip():
                errors.append(f"{prefix}: DELETE requires restore_source")
        if classification == "PRESERVE" and action != "PRESERVE":
            errors.append(f"{prefix}: PRESERVE classification requires PRESERVE action")
        if classification == "AMBIGUOUS_OR_SHARED" and action == "DELETE":
            errors.append(f"{prefix}: ambiguous or shared resources cannot be deleted")
        if (
            action == "DELETE"
            and classification == "REHYDRATABLE"
            and external_resource.lower().startswith("hyperv-vm:")
        ):
            vm_name = external_resource.split(":", 1)[1].strip()
            if vm_name:
                planned_hyperv_removals.add(vm_name.casefold())

        raw_path = resource.get("resolved_path")
        if action == "DELETE" and raw_path:
            candidate = Path(str(raw_path))
            if not candidate.is_absolute():
                candidate = workspace / candidate
            candidate = candidate.resolve()
            delete_candidates.append((prefix, candidate))
            for root in protected:
                if _is_within(candidate, root) or _is_within(root, candidate):
                    errors.append(f"{prefix}: delete candidate intersects protected root {root}")
                    break
        elif action == "DELETE" and not resource.get("external_resource"):
            errors.append(f"{prefix}: DELETE requires resolved_path or external_resource")
    if delete_candidates:
        attachments, inventory_errors = _registered_hyperv_disk_attachments()
        errors.extend(inventory_errors)
        if not inventory_errors:
            for prefix, candidate in delete_candidates:
                for attachment in attachments:
                    disk_path = Path(attachment["path"]).resolve()
                    vm_name = attachment["vm_name"]
                    if (
                        _is_within(disk_path, candidate)
                        and vm_name.casefold() not in planned_hyperv_removals
                    ):
                        errors.append(
                            f"{prefix}: delete candidate contains registered Hyper-V disk "
                            f"for VM {vm_name}: {disk_path}"
                        )
    return errors


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _target_record_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "slug": args.slug,
            "product": args.product,
            "vendor": args.vendor,
            "category": args.category,
            "status": args.status,
            "admission_decision": args.admission_decision,
            "fit_score": args.fit_score,
            "current_version": args.current_version,
            "scope_path": args.scope_path,
            "goal_path": args.goal_path,
            "mirror_path": args.mirror_path,
            "reason": args.reason,
            "scoped_at": args.scoped_at,
            "cleaned_at": args.cleaned_at,
        }.items()
        if value is not None
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize the two-table database")

    complete = sub.add_parser(
        "complete-scope",
        help="validate a SCOPED decision and atomically record target plus event",
    )
    complete.add_argument("--decision", type=Path, required=True)
    complete.add_argument(
        "--publish-mirror",
        action="store_true",
        help="record a validated scope, then create its previously absent Hunter goal mirror",
    )

    refresh_scoped = sub.add_parser(
        "refresh-scoped-scope",
        help="compare-and-swap a validated revision onto an inactive SCOPED target",
    )
    refresh_scoped.add_argument("--decision", type=Path, required=True)
    refresh_scoped.add_argument("--expected-goal-sha256", required=True)
    refresh_scoped.add_argument("--operator-instruction", required=True)

    refresh_scope = sub.add_parser(
        "refresh-active-scope",
        help="compare-and-swap an ACTIVE target onto a fully validated scope revision",
    )
    refresh_scope.add_argument("--decision", type=Path, required=True)
    refresh_scope.add_argument("--expected-goal-sha256", required=True)
    refresh_scope.add_argument("--operator-instruction", required=True)

    upsert = sub.add_parser("upsert", help="create or update one target")
    upsert.add_argument("--slug", required=True)
    upsert.add_argument("--product")
    upsert.add_argument("--vendor")
    upsert.add_argument("--category")
    upsert.add_argument("--status", required=True, choices=ALLOWED_STATES)
    upsert.add_argument("--admission-decision")
    upsert.add_argument("--fit-score", type=int)
    upsert.add_argument("--current-version")
    upsert.add_argument("--scope-path")
    upsert.add_argument("--goal-path")
    upsert.add_argument("--mirror-path")
    upsert.add_argument("--reason")
    upsert.add_argument("--scoped-at")
    upsert.add_argument("--cleaned-at")

    activate = sub.add_parser(
        "activate", help="activate a prepared target under an explicit operator instruction"
    )
    activate.add_argument("--slug", required=True)
    activate.add_argument("--operator-instruction", required=True)
    activate.add_argument(
        "--switch-active",
        action="store_true",
        help="park an existing ACTIVE target when the operator explicitly switches",
    )

    park = sub.add_parser(
        "park", help="park an ACTIVE target under an explicit operator instruction"
    )
    park.add_argument("--slug", required=True)
    park.add_argument("--operator-instruction", required=True)

    event = sub.add_parser("event", help="append a target lifecycle event")
    event.add_argument("--slug", required=True)
    event.add_argument("--type", required=True, dest="event_type")
    event.add_argument("--detail", required=True)
    event.add_argument("--metadata-json")

    diminishing = sub.add_parser(
        "validate-diminishing-returns",
        help="validate that a target marker contains only target-bound packages",
    )
    diminishing.add_argument("--slug", required=True)
    diminishing.add_argument("--marker", type=Path, required=True)
    diminishing.add_argument("--workspace", type=Path, default=WORKSPACE)

    show = sub.add_parser("show", help="show one target")
    show.add_argument("--slug", required=True)

    listing = sub.add_parser("list", help="list targets")
    listing.add_argument("--status", choices=ALLOWED_STATES)

    checkout = sub.add_parser(
        "verify-checkout", help="validate the lifecycle row, appendix, goal mirror, and hash for one target"
    )
    checkout.add_argument("--slug", required=True)

    migrate = sub.add_parser(
        "migrate-legacy-scope",
        help="validate a legacy Scoper appendix and record its missing GOAL receipt",
    )
    migrate.add_argument("--slug", required=True)
    migrate.add_argument("--expected-goal-sha256", required=True)
    migrate.add_argument("--expected-appendix-sha256", required=True)

    goal = sub.add_parser("validate-goal", help="validate a standalone goal and optional mirror")
    goal.add_argument("--goal", type=Path, required=True)
    goal.add_argument("--mirror", type=Path)

    cleanup = sub.add_parser("validate-cleanup", help="validate a cleanup manifest")
    cleanup.add_argument("--manifest", type=Path, required=True)
    cleanup.add_argument("--workspace", type=Path, default=WORKSPACE)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            init_db(args.db)
            _print_json({"database": str(args.db), "states": ALLOWED_STATES})
        elif args.command == "complete-scope":
            _print_json(
                complete_scope(args.db, args.decision, publish_mirror=args.publish_mirror)
            )
        elif args.command == "refresh-scoped-scope":
            _print_json(
                refresh_scoped_scope(
                    args.db,
                    args.decision,
                    expected_goal_sha256=args.expected_goal_sha256,
                    operator_instruction=args.operator_instruction,
                )
            )
        elif args.command == "refresh-active-scope":
            _print_json(
                refresh_active_scope(
                    args.db,
                    args.decision,
                    expected_goal_sha256=args.expected_goal_sha256,
                    operator_instruction=args.operator_instruction,
                )
            )
        elif args.command == "upsert":
            _print_json(upsert_target(args.db, _target_record_from_args(args)))
        elif args.command == "activate":
            _print_json(
                activate_target(
                    args.db,
                    args.slug,
                    args.operator_instruction,
                    args.switch_active,
                )
            )
        elif args.command == "park":
            _print_json(
                park_target(args.db, args.slug, args.operator_instruction)
            )
        elif args.command == "event":
            metadata = json.loads(args.metadata_json) if args.metadata_json else None
            _print_json(add_event(args.db, args.slug, args.event_type, args.detail, metadata))
        elif args.command == "validate-diminishing-returns":
            _print_json(
                validate_diminishing_returns_marker(
                    args.workspace,
                    args.slug,
                    args.marker,
                )
            )
        elif args.command == "show":
            _print_json(get_target(args.db, args.slug))
        elif args.command == "list":
            _print_json(list_targets(args.db, args.status))
        elif args.command == "verify-checkout":
            errors = verify_checkout(args.db, args.slug)
            _print_json({"slug": args.slug, "valid": not errors, "errors": errors})
            return 0 if not errors else 1
        elif args.command == "migrate-legacy-scope":
            _print_json(
                migrate_legacy_scope(
                    args.db,
                    args.slug,
                    expected_goal_sha256=args.expected_goal_sha256,
                    expected_appendix_sha256=args.expected_appendix_sha256,
                )
            )
        elif args.command == "validate-goal":
            errors = validate_goal(args.goal, args.mirror)
            _print_json(
                {
                    "goal": str(args.goal),
                    "mirror": str(args.mirror) if args.mirror else None,
                    "valid": not errors,
                    "errors": errors,
                    "sha256": hashlib.sha256(args.goal.read_bytes()).hexdigest() if args.goal.is_file() else None,
                }
            )
            return 0 if not errors else 1
        elif args.command == "validate-cleanup":
            errors = validate_cleanup_manifest(args.manifest, args.workspace)
            _print_json({"manifest": str(args.manifest), "valid": not errors, "errors": errors})
            return 0 if not errors else 1
    except (ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
