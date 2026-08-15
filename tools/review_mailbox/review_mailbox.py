# ruff: noqa: E402

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from coordination_inbox.coordination_inbox import (  # noqa: E402
    CoordinationInbox,
    CoordinationInboxError,
)

from package_safety import (
    private_marker,
    question_requires_private_content,
    validate_external_package,
)
from package_preflight import (
    ADMISSION_GATE_IDS as PREFLIGHT_ADMISSION_GATE_IDS,
    FINAL_CHECK_IDS as PREFLIGHT_FINAL_CHECK_IDS,
    MECHANICAL_GATE_IDS as PREFLIGHT_MECHANICAL_GATE_IDS,
    PORTFOLIO_ADMISSION_SCHEMA,
    SCHEMA as PREFLIGHT_SCHEMA,
    load_candidate_inventory,
)
from candidate_challenge import (
    ADMITTED_DISPOSITIONS,
    CandidateChallengeError,
    validate_result as validate_candidate_challenge_result,
)
from bounded_repair_contract import (
    BoundedRepairContractError,
    validate_queued_mechanical_repair,
)
from human_time import format_duration, format_local_time
from mailbox_rework import (
    close_item_addressed,
    reconcile_terminal_addressed,
    supersede_older_addressed,
)
from mailbox_queries import latest_rework_by_item
from mailbox_schema import apply_migrations, connect_read_only
from mailbox_transitions import (
    TransitionInProgressError,
    TransitionRollbackError,
    complete_transition,
    journaled_move,
    reconcile_transitions,
    rollback_transition,
)


NUMBERED_PACKAGE = re.compile(r"^\d+_.+")
READY_PREFIX = "_READY_TO_SUBMIT_"
SUBMITTED_PREFIX = "_SUBMITTED_"
ACCEPTED_PREFIX = "_ACCEPTED_"
REJECTED_PREFIX = "_REJECTED_"
DEAD_ARCHIVE_DIR = "_NUMBERED"
TRACKED_PACKAGE = re.compile(r"^(?:_READY_TO_SUBMIT_)?\d+_.+")
HUNTER_MUTABLE_STATES = {"QUESTIONS_OPEN", "FINAL_REWORK", "STALE"}
WORKER_STALE_AFTER_SECONDS = 30 * 60
DEFAULT_ACTIVITY_HEARTBEAT_MINIMUM_SECONDS = 10 * 60
FINAL_REWORK_SCOPES = {"MECHANICAL", "EVIDENCE_ONLY", "SEMANTIC"}
FINAL_DETERMINATION_SCHEMA = "jenny.final-review-determination.v1"
FINAL_DETERMINATION_FIELDS = (
    "technical_readiness",
    "portfolio_recommendation",
    "same_product_rank",
    "actual_vulnerability",
    "exploit_path",
    "threat_actor_impact",
    "decisive_proof",
    "cvss",
    "duplicate_posture",
    "estimated_payout",
    "discovery_difficulty",
)
REJECTION_REASON_CODES = {
    "BUYER_NOT_INTERESTED_VULN_TYPE",
    "DUPLICATE",
    "FIXED_BEFORE_SUBMISSION",
    "OTHER",
    "OUT_OF_SCOPE_PRODUCT",
    "PUBLIC_PRIOR_ART",
}
READ_ONLY_COMMANDS = {
    "accepted-comps",
    "candidate-inventory",
    "questions",
    "rework-details",
    "status",
}
_PHASE_FILE: Path | None = None


def _is_canonical_mailbox_database(path: Path) -> bool:
    parts = tuple(part.casefold() for part in path.parts)
    return parts[-3:] == (
        "notes",
        "review_mailbox",
        "review_mailbox.sqlite3",
    )


class MailboxError(RuntimeError):
    pass


def _validate_final_determination(
    payload: dict[str, Any],
    item: dict[str, Any],
) -> dict[str, Any]:
    required = {
        "schema",
        "item_id",
        "reviewed_hash",
        "reviewed_revision",
        "verdict",
        *FINAL_DETERMINATION_FIELDS,
    }
    if set(payload) != required:
        missing = sorted(required - set(payload))
        extra = sorted(set(payload) - required)
        raise MailboxError(
            "final determination fields disagree with the schema"
            f"; missing={missing}; extra={extra}"
        )
    if payload.get("schema") != FINAL_DETERMINATION_SCHEMA:
        raise MailboxError("final determination schema is invalid")
    if payload.get("item_id") != int(item["id"]):
        raise MailboxError("final determination item identity does not match")
    if payload.get("reviewed_revision") != int(item["revision"]):
        raise MailboxError("final determination revision does not match")
    reviewed_hash = payload.get("reviewed_hash")
    if (
        not isinstance(reviewed_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", reviewed_hash) is None
        or reviewed_hash != str(item["package_hash"])
    ):
        raise MailboxError("final determination reviewed hash does not match")
    if payload.get("verdict") != "READY":
        raise MailboxError("final determination verdict must be READY")
    if payload.get("technical_readiness") != "TECHNICALLY READY":
        raise MailboxError("READY requires TECHNICALLY READY")
    if payload.get("portfolio_recommendation") != "SUBMIT NOW":
        raise MailboxError("READY requires SUBMIT NOW")

    normalized: dict[str, Any] = {
        "schema": FINAL_DETERMINATION_SCHEMA,
        "item_id": int(item["id"]),
        "reviewed_hash": reviewed_hash,
        "reviewed_revision": int(item["revision"]),
        "verdict": "READY",
    }
    for field in FINAL_DETERMINATION_FIELDS:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            raise MailboxError(f"final determination {field} is required")
        value = value.strip()
        if len(value) > 4000:
            raise MailboxError(f"final determination {field} is too long")
        normalized[field] = value
    if re.search(r"\b(?:10|[0-9])\.\d\b", normalized["cvss"]) is None:
        raise MailboxError("final determination CVSS must include a numeric score")
    if "CVSS:3." not in normalized["cvss"]:
        raise MailboxError("final determination CVSS must include the full vector")
    return normalized


def _phase(name: str, **detail: Any) -> None:
    if _PHASE_FILE is None:
        return
    payload = {
        "at": utc_now(),
        "phase": name,
        **detail,
    }
    try:
        _PHASE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _PHASE_FILE.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")
    except OSError:
        # Diagnostics must never change mailbox behavior.
        pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def local_display_time() -> str:
    return format_local_time(datetime.now().astimezone())


def _age_fields(value: str, now: datetime | None = None) -> dict[str, Any]:
    reference = now or datetime.now(UTC)
    parsed = datetime.fromisoformat(value)
    age_seconds = max(0, int((reference - parsed).total_seconds()))
    return {
        "age": format_duration(age_seconds),
        "age_seconds": age_seconds,
    }


def direct_hold_is_private_policy_conflict(text: str) -> bool:
    normalized = text.lower()
    technical_clear = (
        "technical evidence package remains sound" in normalized
        or "not a technical quality issue" in normalized
        or "no technical blocker" in normalized
    )
    external_boundary = "vendor-visible" in normalized or "external-facing" in normalized
    return bool(
        private_marker(text)
        and "policy conflict" in normalized
        and technical_clear
        and external_boundary
    )


class Mailbox:
    def __init__(
        self,
        db_path: str | Path,
        workspace: str | Path,
        require_preflight: bool | None = None,
        require_candidate_challenge: bool | None = None,
        *,
        _read_only: bool = False,
    ) -> None:
        self.db_path = Path(db_path).resolve()
        self.workspace = Path(workspace).resolve()
        self._active_transition_id: int | None = None
        self._read_only = _read_only
        self.require_preflight = (
            bool(require_preflight)
            if require_preflight is not None
            else (
                self.workspace
                / "tools"
                / "review_mailbox"
                / "package_preflight.py"
            ).is_file()
        )
        self.require_candidate_challenge = (
            bool(require_candidate_challenge)
            if require_candidate_challenge is not None
            else (
                self.workspace
                / "tools"
                / "review_mailbox"
                / "candidate_challenge.py"
            ).is_file()
        )
        if self._read_only:
            if not self.db_path.is_file():
                raise MailboxError(f"mailbox database does not exist: {self.db_path}")
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()

    @classmethod
    def open_read_only(
        cls,
        db_path: str | Path,
        workspace: str | Path,
    ) -> Mailbox:
        return cls(db_path, workspace, _read_only=True)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        _phase("DB_CONNECT_START")
        if self._read_only:
            connection = connect_read_only(self.db_path)
        else:
            connection = sqlite3.connect(self.db_path, timeout=10)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")
        _phase("DB_CONNECT_COMPLETE")
        try:
            yield connection
            if not self._read_only:
                _phase("DB_COMMIT_START")
                connection.commit()
                _phase("DB_COMMIT_COMPLETE")
            self._active_transition_id = None
        except Exception as error:
            _phase("DB_ROLLBACK_START")
            connection.rollback()
            _phase("DB_ROLLBACK_COMPLETE")
            transition_id = self._active_transition_id
            self._active_transition_id = None
            if transition_id is not None:
                try:
                    rollback_transition(
                        self.db_path,
                        transition_id,
                        hash_package=self._hash_package,
                        timestamp=utc_now(),
                    )
                except TransitionRollbackError as rollback_error:
                    raise MailboxError(
                        "package transition rollback failed: "
                        f"{rollback_error}"
                    ) from error
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS work_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_path TEXT NOT NULL UNIQUE,
                    product TEXT NOT NULL,
                    version TEXT NOT NULL,
                    package_hash TEXT NOT NULL,
                    reviewed_hash TEXT,
                    state TEXT NOT NULL,
                    hunter_note TEXT NOT NULL DEFAULT '',
                    review_summary TEXT NOT NULL DEFAULT '',
                    final_determination_json TEXT NOT NULL DEFAULT '{}',
                    hold_reason TEXT NOT NULL DEFAULT '',
                    revision INTEGER NOT NULL DEFAULT 1,
                    closure_completed INTEGER NOT NULL DEFAULT 0,
                    claimed_at TEXT,
                    package_manifest_json TEXT NOT NULL DEFAULT '[]',
                    submitted_path TEXT NOT NULL DEFAULT '',
                    submitted_hash TEXT NOT NULL DEFAULT '',
                    submitted_manifest_json TEXT NOT NULL DEFAULT '[]',
                    submission_drift INTEGER NOT NULL DEFAULT 0,
                    submission_note TEXT NOT NULL DEFAULT '',
                    submitted_at TEXT,
                    dead_reason TEXT NOT NULL DEFAULT '',
                    dead_at TEXT,
                    dead_from_state TEXT NOT NULL DEFAULT '',
                    dead_operator TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
                    question_text TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    closure_condition TEXT NOT NULL,
                    status TEXT NOT NULL,
                    answer_text TEXT NOT NULL DEFAULT '',
                    answer_refs_json TEXT NOT NULL DEFAULT '[]',
                    closure_note TEXT NOT NULL DEFAULT '',
                    closure_refs_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER REFERENCES work_items(id),
                    actor TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS accepted_acquisitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER REFERENCES work_items(id),
                    package_number INTEGER NOT NULL,
                    product TEXT NOT NULL,
                    title TEXT NOT NULL,
                    package_path TEXT NOT NULL,
                    accepted_hash TEXT NOT NULL,
                    accepted_revision INTEGER,
                    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
                    currency TEXT NOT NULL,
                    case_id TEXT NOT NULL DEFAULT '',
                    vulnerability_family TEXT NOT NULL DEFAULT '',
                    attacker_position TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    accepted_at TEXT NOT NULL,
                    reversed_at TEXT,
                    reversal_reason TEXT NOT NULL DEFAULT ''
                );

                CREATE UNIQUE INDEX IF NOT EXISTS
                    accepted_acquisitions_active_item
                ON accepted_acquisitions(work_item_id)
                WHERE status = 'ACTIVE' AND work_item_id IS NOT NULL;

                CREATE UNIQUE INDEX IF NOT EXISTS
                    accepted_acquisitions_active_package
                ON accepted_acquisitions(package_number)
                WHERE status = 'ACTIVE';

                CREATE TABLE IF NOT EXISTS rejections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER UNIQUE REFERENCES work_items(id),
                    package_number INTEGER NOT NULL UNIQUE,
                    product TEXT NOT NULL,
                    title TEXT NOT NULL,
                    package_path TEXT NOT NULL,
                    rejected_hash TEXT NOT NULL,
                    rejected_revision INTEGER NOT NULL,
                    reason_code TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    case_id TEXT NOT NULL DEFAULT '',
                    public_reference TEXT NOT NULL DEFAULT '',
                    rejected_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS final_rework_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
                    reviewed_hash TEXT NOT NULL,
                    reviewed_revision INTEGER NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    issues_json TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    review_scope TEXT NOT NULL DEFAULT 'SEMANTIC',
                    prior_candidate_challenge_id INTEGER,
                    state TEXT NOT NULL,
                    queued_by TEXT NOT NULL,
                    addressed_hash TEXT NOT NULL DEFAULT '',
                    addressed_revision INTEGER,
                    created_at TEXT NOT NULL,
                    claimed_at TEXT,
                    addressed_at TEXT,
                    verified_at TEXT,
                    closed_at TEXT,
                    UNIQUE(work_item_id, reviewed_hash, request_fingerprint)
                );

                CREATE TABLE IF NOT EXISTS consumer_offsets (
                    consumer TEXT PRIMARY KEY,
                    last_event_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS worker_status (
                    worker TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    task TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS worker_activity (
                    worker TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    source TEXT NOT NULL,
                    session_hash TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS package_builds (
                    package_number INTEGER PRIMARY KEY,
                    package_path TEXT NOT NULL UNIQUE,
                    product TEXT NOT NULL,
                    version TEXT NOT NULL,
                    candidate_challenge_id INTEGER,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS operator_requests (
                    worker TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    cleared_at TEXT,
                    clear_note TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS operator_approval_requests (
                    worker TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    cleared_at TEXT,
                    clear_note TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS package_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    work_item_id INTEGER REFERENCES work_items(id),
                    source_path TEXT NOT NULL,
                    destination_path TEXT NOT NULL,
                    expected_hash TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK (
                        phase IN (
                            'PREPARED', 'MOVED', 'COMMITTED',
                            'ROLLED_BACK', 'BLOCKED'
                        )
                    ),
                    owner_pid INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS package_outcome_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
                    outcome TEXT NOT NULL CHECK (outcome IN ('HOLD', 'DEAD')),
                    package_path TEXT NOT NULL,
                    product TEXT NOT NULL,
                    package_hash TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'OPEN'
                        CHECK (state IN ('OPEN', 'ACKNOWLEDGED')),
                    created_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    UNIQUE(work_item_id, outcome, revision, package_hash)
                );

                CREATE TABLE IF NOT EXISTS package_mutation_authorities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
                    baseline_hash TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('PENDING', 'CONSUMED', 'USED', 'CANCELLED')
                    ),
                    issued_at TEXT NOT NULL,
                    consumed_at TEXT,
                    used_at TEXT,
                    UNIQUE(work_item_id, revision)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS package_transition_one_open
                ON package_transitions((1))
                WHERE phase IN ('PREPARED', 'MOVED');

                CREATE TRIGGER IF NOT EXISTS package_transition_commit_path
                AFTER UPDATE OF package_path ON work_items
                BEGIN
                    UPDATE package_transitions
                    SET phase = 'COMMITTED',
                        updated_at = NEW.updated_at,
                        error = ''
                    WHERE work_item_id = NEW.id
                      AND destination_path = NEW.package_path
                      AND phase = 'MOVED';
                END;

                CREATE TRIGGER IF NOT EXISTS package_outcome_notification
                AFTER UPDATE OF state ON work_items
                WHEN NEW.state IN ('HOLD', 'DEAD') AND OLD.state <> NEW.state
                BEGIN
                    INSERT OR IGNORE INTO package_outcome_notifications(
                        work_item_id, outcome, package_path, product,
                        package_hash, revision, reason, state, created_at
                    ) VALUES (
                        NEW.id,
                        NEW.state,
                        NEW.package_path,
                        NEW.product,
                        NEW.package_hash,
                        NEW.revision,
                        CASE
                            WHEN NEW.state = 'DEAD' THEN NEW.dead_reason
                            ELSE NEW.hold_reason
                        END,
                        'OPEN',
                        NEW.updated_at
                    );
                END;
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(work_items)")
            }
            migrations = {
                "package_manifest_json": "TEXT NOT NULL DEFAULT '[]'",
                "submitted_path": "TEXT NOT NULL DEFAULT ''",
                "submitted_hash": "TEXT NOT NULL DEFAULT ''",
                "submitted_manifest_json": "TEXT NOT NULL DEFAULT '[]'",
                "submission_drift": "INTEGER NOT NULL DEFAULT 0",
                "submission_note": "TEXT NOT NULL DEFAULT ''",
                "submitted_at": "TEXT",
                "dead_reason": "TEXT NOT NULL DEFAULT ''",
                "dead_at": "TEXT",
                "dead_from_state": "TEXT NOT NULL DEFAULT ''",
                "dead_operator": "TEXT NOT NULL DEFAULT ''",
                "final_determination_json": "TEXT NOT NULL DEFAULT '{}'",
            }
            for name, definition in migrations.items():
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE work_items ADD COLUMN {name} {definition}"
                    )
            work_item_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(work_items)")
            }
            if "candidate_challenge_id" not in work_item_columns:
                connection.execute(
                    "ALTER TABLE work_items ADD COLUMN candidate_challenge_id INTEGER"
                )
            package_build_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(package_builds)")
            }
            if "candidate_challenge_id" not in package_build_columns:
                connection.execute(
                    "ALTER TABLE package_builds "
                    "ADD COLUMN candidate_challenge_id INTEGER"
                )
            final_rework_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(final_rework_requests)"
                )
            }
            if "review_scope" not in final_rework_columns:
                connection.execute(
                    "ALTER TABLE final_rework_requests "
                    "ADD COLUMN review_scope TEXT NOT NULL DEFAULT 'SEMANTIC'"
                )
            if "prior_candidate_challenge_id" not in final_rework_columns:
                connection.execute(
                    "ALTER TABLE final_rework_requests "
                    "ADD COLUMN prior_candidate_challenge_id INTEGER"
                )
            apply_migrations(connection)
            reconcile_terminal_addressed(connection, timestamp=utc_now())
        self._reconcile_package_transitions()

    def _legacy_transition_committed(
        self,
        connection: sqlite3.Connection,
        action: str,
        destination: Path,
    ) -> bool:
        package_number = int(self._package_number(destination.name))
        if action == "RECONCILE_REJECTED":
            row = connection.execute(
                "SELECT package_path FROM rejections WHERE package_number = ?",
                (package_number,),
            ).fetchone()
        elif action == "RECONCILE_ACCEPTED":
            row = connection.execute(
                "SELECT package_path FROM accepted_acquisitions "
                "WHERE package_number = ? AND status = 'ACTIVE'",
                (package_number,),
            ).fetchone()
        else:
            row = None
        return row is not None and Path(row["package_path"]).resolve() == destination

    def _reconcile_package_transitions(self) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            blocked = reconcile_transitions(
                connection,
                hash_package=self._hash_package,
                legacy_committed=self._legacy_transition_committed,
                timestamp=utc_now(),
            )
        if blocked:
            rendered = ", ".join(str(value) for value in blocked)
            raise MailboxError(
                "ambiguous package transition requires manual audit: " + rendered
            )

    def _journaled_move(
        self,
        connection: sqlite3.Connection,
        item_id: int | None,
        action: str,
        source: Path,
        destination: Path,
        expected_hash: str,
    ) -> int:
        try:
            transition_id = journaled_move(
                connection,
                item_id=item_id,
                action=action,
                source=source,
                destination=destination,
                expected_hash=expected_hash,
                timestamp=utc_now(),
            )
        except TransitionInProgressError as error:
            raise MailboxError(str(error)) from error
        self._active_transition_id = transition_id
        return transition_id

    @staticmethod
    def _complete_package_transition(
        connection: sqlite3.Connection,
        transition_id: int,
    ) -> None:
        complete_transition(
            connection,
            transition_id,
            timestamp=utc_now(),
        )

    def _resolve_numbered_package(self, package_path: str | Path) -> Path:
        package = Path(package_path).resolve()
        if not NUMBERED_PACKAGE.fullmatch(package.name):
            raise MailboxError("package folder name must begin with a number and underscore")
        if not package.is_dir():
            raise MailboxError(f"package folder does not exist: {package}")
        return package

    def _resolve_tracked_package(self, package_path: str | Path) -> Path:
        package = Path(package_path).resolve()
        if not TRACKED_PACKAGE.fullmatch(package.name):
            raise MailboxError(
                "tracked package folder must be numbered or use the READY prefix"
            )
        if not package.is_dir():
            raise MailboxError(f"package folder does not exist: {package}")
        return package

    def _validate_staging_package(self, package_path: str | Path) -> Path:
        package = self._resolve_numbered_package(package_path)
        staging_root = (self.workspace / "ZDI_STAGING").resolve()
        if package.parent != staging_root:
            raise MailboxError(
                "new packages must be direct numbered folders under workspace/ZDI_STAGING"
            )
        return package

    def _validate_tracked_package(self, package_path: str | Path) -> Path:
        package = self._resolve_tracked_package(package_path)
        zdi_root = (self.workspace / "ZDI").resolve()
        allowed_roots = {
            (self.workspace / "ZDI_STAGING").resolve(),
            (self.workspace / "ZDI_STAGING" / "_HOLD").resolve(),
            zdi_root,
        }
        if package.parent not in allowed_roots:
            raise MailboxError(
                "tracked package must be directly under ZDI_STAGING, "
                "ZDI_STAGING/_HOLD, or ZDI"
            )
        if package.name.startswith(READY_PREFIX) and package.parent != zdi_root:
            raise MailboxError("READY-prefixed packages must remain directly under ZDI")
        return package

    def _dead_item_for_number(
        self, connection: sqlite3.Connection, package_name: str
    ) -> sqlite3.Row | None:
        package_number = self._package_number(package_name)
        for row in connection.execute(
            "SELECT id, package_path FROM work_items WHERE state = 'DEAD' ORDER BY id"
        ):
            try:
                dead_number = self._package_number(Path(row["package_path"]).name)
            except MailboxError:
                continue
            if dead_number == package_number:
                return row
        return None

    def _hash_package(self, package: Path) -> str:
        _phase("HASH_START", package=str(package))
        digest = hashlib.sha256()
        for path in sorted(package.rglob("*"), key=lambda value: value.as_posix()):
            if path.is_symlink():
                raise MailboxError(f"package contains a symbolic link: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(package).as_posix().encode("utf-8")
            digest.update(b"FILE\0")
            digest.update(relative)
            digest.update(b"\0")
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            digest.update(b"\0")
        value = digest.hexdigest()
        _phase("HASH_COMPLETE", package=str(package), package_hash=value)
        return value

    def _manifest_package(self, package: Path) -> list[dict[str, Any]]:
        manifest: list[dict[str, Any]] = []
        for path in sorted(package.rglob("*"), key=lambda value: value.as_posix()):
            if path.is_symlink():
                raise MailboxError(f"package contains a symbolic link: {path}")
            if not path.is_file():
                continue
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            manifest.append(
                {
                    "path": path.relative_to(package).as_posix(),
                    "sha256": digest.hexdigest(),
                    "size": path.stat().st_size,
                }
            )
        return manifest

    @staticmethod
    def _validate_external_package(package: Path) -> None:
        try:
            validate_external_package(package)
        except ValueError as error:
            raise MailboxError(str(error)) from error

    def _claimed_final_rework_preflight_context(
        self,
        connection: sqlite3.Connection,
        package: Path,
        package_hash: str,
        product: str,
        goal_path: Path,
        goal_hash: str,
    ) -> dict[str, Any] | None:
        item, _rename_request_id = self._registration_identity(connection, package)
        if item is None or item["state"] != "FINAL_REWORK":
            return None
        request_rows = connection.execute(
            """
            SELECT * FROM final_rework_requests
            WHERE work_item_id = ? AND state = 'CLAIMED'
            ORDER BY id
            """,
            (int(item["id"]),),
        ).fetchall()
        if len(request_rows) != 1:
            raise MailboxError(
                "final rework preflight requires exactly one claimed request"
            )
        request = request_rows[0]
        candidate_id = item["candidate_challenge_id"]
        if candidate_id is None:
            raise MailboxError(
                "final rework preflight has no rebound Candidate Challenge"
            )
        candidate = connection.execute(
            "SELECT * FROM candidate_challenges WHERE id = ?",
            (int(candidate_id),),
        ).fetchone()
        if candidate is None:
            raise MailboxError("final rework Candidate Challenge binding is missing")
        package_number = int(self._package_number(package.name))
        prior_candidate_id = request["prior_candidate_challenge_id"]
        candidate_rebound = (
            prior_candidate_id is not None
            and int(prior_candidate_id) != int(candidate_id)
        )
        if (
            request["review_scope"] not in {"EVIDENCE_ONLY", "SEMANTIC"}
            or prior_candidate_id is None
            or (
                request["review_scope"] == "SEMANTIC"
                and not candidate_rebound
            )
            or request["reviewed_hash"] != item["package_hash"]
            or int(request["reviewed_revision"]) != int(item["revision"])
            or candidate["state"] != "DECIDED"
            or candidate["disposition"] not in ADMITTED_DISPOSITIONS
            or candidate["package_number"] != package_number
            or candidate["product"] != product
            or candidate["product"] != item["product"]
            or candidate["version"] != item["version"]
            or Path(str(candidate["goal_path"])).resolve() != goal_path
            or candidate["goal_hash"] != goal_hash
        ):
            raise MailboxError(
                "final rework preflight candidate, request, package, goal, or product "
                "lineage does not agree"
            )
        authority = connection.execute(
            """
            SELECT state, baseline_hash FROM package_mutation_authorities
            WHERE work_item_id = ? AND revision = ?
            """,
            (int(item["id"]), int(item["revision"])),
        ).fetchone()
        if (
            authority is None
            or authority["state"] != "CONSUMED"
            or authority["baseline_hash"] != request["reviewed_hash"]
        ):
            raise MailboxError(
                "final rework preflight lacks current Hunter mutation authority"
            )

        if candidate_rebound:
            rebound_matches = []
            for event in connection.execute(
                """
                SELECT detail_json FROM events
                WHERE work_item_id = ?
                  AND event_type = 'FINAL_REWORK_CANDIDATE_REBOUND'
                ORDER BY id
                """,
                (int(item["id"]),),
            ):
                try:
                    detail = json.loads(str(event["detail_json"]))
                except (TypeError, json.JSONDecodeError):
                    continue
                if (
                    isinstance(detail, dict)
                    and detail.get("candidate_id") == int(candidate_id)
                    and detail.get("request_id") == int(request["id"])
                    and detail.get("package_hash") == package_hash
                    and detail.get("package_number") == package_number
                    and detail.get("prior_candidate_id")
                    == int(prior_candidate_id)
                ):
                    rebound_matches.append(detail)
            if len(rebound_matches) != 1:
                raise MailboxError(
                    "final rework preflight lacks one exact candidate rebound event"
                )
        return {
            "item_id": int(item["id"]),
            "request_id": int(request["id"]),
            "candidate_id": int(candidate_id),
            "prior_candidate_id": int(prior_candidate_id),
            "candidate_rebound": candidate_rebound,
            "package_number": package_number,
            "package_hash": package_hash,
            "product": product,
            "version": str(item["version"]),
            "target_slug": str(candidate["target_slug"]),
            "goal_path": str(goal_path),
            "goal_hash": goal_hash,
        }

    def _validate_preflight_lifecycle_binding(
        self,
        goal_path: Path,
        goal_hash: str,
        product: str,
        final_rework: dict[str, Any] | None,
    ) -> None:
        lifecycle_db = (
            self.workspace
            / "notes"
            / "target_lifecycle"
            / "target_lifecycle.sqlite3"
        )
        if not lifecycle_db.is_file():
            raise MailboxError(
                "package preflight has no active target lifecycle binding"
            )
        try:
            with sqlite3.connect(lifecycle_db, timeout=10) as lifecycle:
                lifecycle.row_factory = sqlite3.Row
                lifecycle.execute("PRAGMA busy_timeout = 10000")
                rows = lifecycle.execute(
                    "SELECT slug, product, status, mirror_path, goal_sha256 "
                    "FROM targets ORDER BY slug"
                ).fetchall()
        except sqlite3.Error as error:
            raise MailboxError(
                f"cannot validate active target lifecycle binding: {error}"
            ) from error
        active_rows = [row for row in rows if row["status"] == "ACTIVE"]
        if len(active_rows) != 1:
            raise MailboxError(
                "package preflight requires exactly one active target lifecycle binding"
            )

        def matches(row: sqlite3.Row) -> bool:
            mirror_value = str(row["mirror_path"] or "")
            if not mirror_value:
                return False
            mirror = Path(mirror_value)
            if not mirror.is_absolute():
                mirror = self.workspace / mirror
            return (
                mirror.resolve() == goal_path
                and str(row["goal_sha256"] or "") == goal_hash
                and str(row["product"]) == product
            )

        if matches(active_rows[0]):
            return
        if final_rework is None:
            raise MailboxError(
                "package preflight goal does not match the active target lifecycle goal"
            )
        if not final_rework["candidate_rebound"]:
            raise MailboxError(
                "cross-target final rework requires an exact candidate rebound"
            )
        recorded = [
            row for row in rows if row["slug"] == final_rework["target_slug"]
        ]
        if (
            len(recorded) != 1
            or recorded[0]["status"] not in {"ACTIVE", "PARKED_REHYDRATABLE"}
            or not matches(recorded[0])
        ):
            raise MailboxError(
                "final rework preflight does not match its recorded target lifecycle"
            )

    def _validate_preflight_result(
        self,
        package: Path,
        package_hash: str,
        preflight_result: str | Path | None,
        product: str,
    ) -> dict[str, Any] | None:
        if preflight_result is None:
            if self.require_preflight:
                raise MailboxError(
                    "hash-bound package preflight result is required for registration"
                )
            return None
        result_path = Path(preflight_result).resolve()
        try:
            result_path.relative_to(self.workspace)
        except ValueError as error:
            raise MailboxError(
                "package preflight result must be a private workspace file"
            ) from error
        for external_root in (
            (self.workspace / "ZDI").resolve(),
            (self.workspace / "ZDI_STAGING").resolve(),
            package,
        ):
            try:
                result_path.relative_to(external_root)
            except ValueError:
                continue
            raise MailboxError(
                "package preflight result must stay outside external package roots"
            )
        if not result_path.is_file():
            raise MailboxError(f"package preflight result does not exist: {result_path}")
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise MailboxError(f"cannot read package preflight result: {error}") from error
        if not isinstance(payload, dict) or payload.get("schema") != PREFLIGHT_SCHEMA:
            raise MailboxError("package preflight result schema is invalid")
        if payload.get("status") != "PASS":
            raise MailboxError("package preflight result status must be PASS")
        if payload.get("workspace") != str(self.workspace):
            raise MailboxError("package preflight workspace does not match")
        if payload.get("package_path") != str(package):
            raise MailboxError("package preflight path does not match current package")
        if payload.get("package_hash") != package_hash:
            raise MailboxError("package preflight package hash does not match current bytes")

        goal_value = payload.get("goal_path")
        if not isinstance(goal_value, str):
            raise MailboxError("package preflight goal path is missing")
        goal_path = Path(goal_value).resolve()
        try:
            goal_path.relative_to((self.workspace / "targets").resolve())
        except ValueError as error:
            raise MailboxError(
                "package preflight goal must be under targets"
            ) from error
        if goal_path.name != "GOAL.md" or not goal_path.is_file():
            raise MailboxError("package preflight goal is not a current GOAL.md")
        goal_hash = hashlib.sha256(goal_path.read_bytes()).hexdigest()
        if payload.get("goal_hash") != goal_hash:
            raise MailboxError("package preflight goal hash does not match current goal")
        with self._connect() as binding_connection:
            final_rework = self._claimed_final_rework_preflight_context(
                binding_connection,
                package,
                package_hash,
                product,
                goal_path,
                goal_hash,
            )
        self._validate_preflight_lifecycle_binding(
            goal_path,
            goal_hash,
            product,
            final_rework,
        )

        checks = payload.get("checks")
        if not isinstance(checks, dict):
            raise MailboxError("package preflight checks are missing")
        inventory = load_candidate_inventory(self.workspace, product, self.db_path)
        if payload.get("product") != product:
            raise MailboxError("package preflight product does not match")
        bound_inventory = payload.get("candidate_inventory")
        if (
            not isinstance(bound_inventory, dict)
            or bound_inventory.get("digest") != inventory["digest"]
        ):
            raise MailboxError("package preflight candidate inventory is stale")
        inventory_check = checks.get("candidate_inventory")
        if not isinstance(inventory_check, dict) or inventory_check.get("status") != "PASS":
            raise MailboxError("package preflight candidate inventory is not PASS")
        portfolio = payload.get("portfolio_admission")
        if (
            not isinstance(portfolio, dict)
            or portfolio.get("schema") != PORTFOLIO_ADMISSION_SCHEMA
            or portfolio.get("product") != product
            or portfolio.get("inventory_digest") != inventory["digest"]
            or portfolio.get("disposition") != "PROMOTE"
            or not isinstance(portfolio.get("file_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", portfolio["file_sha256"])
        ):
            raise MailboxError("package preflight portfolio admission is invalid")
        challenge = payload.get("candidate_challenge")
        package_number = int(self._package_number(package.name))
        with sqlite3.connect(self.db_path, timeout=5) as challenge_connection:
            challenge_connection.row_factory = sqlite3.Row
            build_row = challenge_connection.execute(
                """
                SELECT candidate_challenge_id
                FROM package_builds WHERE package_number = ?
                """,
                (package_number,),
            ).fetchone()
        bound_candidate_id = (
            int(final_rework["candidate_id"])
            if final_rework is not None
            else (
                int(build_row["candidate_challenge_id"])
                if build_row is not None
                and build_row["candidate_challenge_id"] is not None
                else None
            )
        )
        if bound_candidate_id is not None:
            challenge_check = checks.get("candidate_challenge")
            if (
                not isinstance(challenge, dict)
                or challenge.get("candidate_id") != bound_candidate_id
                or not isinstance(challenge.get("result_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", challenge["result_sha256"])
                or not isinstance(challenge_check, dict)
                or challenge_check.get("status") != "PASS"
                or challenge_check.get("candidate_id") != bound_candidate_id
            ):
                raise MailboxError(
                    "package preflight candidate challenge is invalid"
                )
        required_checks = (
            *PREFLIGHT_ADMISSION_GATE_IDS,
            *PREFLIGHT_MECHANICAL_GATE_IDS,
            *PREFLIGHT_FINAL_CHECK_IDS,
        )
        for check_id in required_checks:
            check = checks.get(check_id)
            if not isinstance(check, dict) or check.get("status") != "PASS":
                raise MailboxError(
                    f"package preflight check is not PASS: {check_id}"
                )
        unchanged = checks["package_unchanged"]
        if (
            unchanged.get("before") != package_hash
            or unchanged.get("after") != package_hash
        ):
            raise MailboxError("package preflight unchanged-byte proof is invalid")
        if checks["fresh_extraction"].get("root") != "folder_of_everything_necessary":
            raise MailboxError("package preflight fresh-extraction root is invalid")
        if checks["external_dependencies"].get("hits") != []:
            raise MailboxError("package preflight external-dependency proof is invalid")
        commands = checks["packaged_command"].get("commands")
        if not isinstance(commands, list) or not commands:
            raise MailboxError("package preflight packaged-command proof is missing")
        for command in commands:
            if (
                not isinstance(command, dict)
                or command.get("status") != "PASS"
                or command.get("kind") not in {"offline", "live"}
                or command.get("exit_code") != 0
                or not isinstance(command.get("command_file_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", command["command_file_sha256"])
            ):
                raise MailboxError("package preflight packaged command is not PASS")

        result_hash = hashlib.sha256(result_path.read_bytes()).hexdigest()
        return {
            "result_path": str(result_path),
            "result_sha256": result_hash,
            "goal_path": str(goal_path),
            "goal_hash": goal_hash,
            "final_rework": final_rework,
        }

    @staticmethod
    def _package_number(package_name: str) -> str:
        match = re.match(
            r"^(?:_(?:READY_TO_SUBMIT|SUBMITTED|ACCEPTED|REJECTED)_)?(\d+)_",
            package_name,
        )
        if match is None:
            raise MailboxError(f"cannot determine package number from {package_name}")
        return match.group(1)

    @staticmethod
    def _canonical_numbered_name(package_name: str) -> str:
        for prefix in (
            READY_PREFIX,
            SUBMITTED_PREFIX,
            ACCEPTED_PREFIX,
            REJECTED_PREFIX,
        ):
            if package_name.startswith(prefix):
                return package_name[len(prefix) :]
        if NUMBERED_PACKAGE.fullmatch(package_name):
            return package_name
        raise MailboxError(f"cannot determine canonical package name from {package_name}")

    @classmethod
    def _package_title(cls, package_name: str) -> str:
        numbered = cls._canonical_numbered_name(package_name)
        _, separator, title = numbered.partition("_")
        if not separator or not title:
            raise MailboxError(f"cannot determine package title from {package_name}")
        return title.replace("_", " ").strip()

    @staticmethod
    def _amount_cents(amount_usd: int) -> int:
        if isinstance(amount_usd, bool) or not isinstance(amount_usd, int):
            raise MailboxError("accepted amount must be a positive integer USD value")
        if amount_usd <= 0:
            raise MailboxError("accepted amount must be a positive integer USD value")
        return amount_usd * 100

    def _items_for_number(
        self, connection: sqlite3.Connection, package_name: str
    ) -> list[sqlite3.Row]:
        number = self._package_number(package_name)
        matches: list[sqlite3.Row] = []
        for row in connection.execute("SELECT * FROM work_items ORDER BY id"):
            try:
                row_number = self._package_number(Path(row["package_path"]).name)
            except MailboxError:
                continue
            if row_number == number:
                matches.append(row)
        return matches

    @staticmethod
    def _claimed_rework_request_id(
        connection: sqlite3.Connection, item_id: int
    ) -> int | None:
        row = connection.execute(
            """
            SELECT id FROM final_rework_requests
            WHERE work_item_id = ? AND state = 'CLAIMED'
            ORDER BY id DESC LIMIT 1
            """,
            (item_id,),
        ).fetchone()
        return int(row["id"]) if row is not None else None

    def _renamable_final_rework(
        self,
        connection: sqlite3.Connection,
        item: sqlite3.Row,
        candidate: Path,
    ) -> int | None:
        if item["state"] != "FINAL_REWORK":
            return None
        tracked = Path(item["package_path"]).resolve()
        if tracked == candidate or tracked.exists():
            return None
        return self._claimed_rework_request_id(connection, int(item["id"]))

    def _registration_identity(
        self,
        connection: sqlite3.Connection,
        candidate: Path,
    ) -> tuple[sqlite3.Row | None, int | None]:
        exact = connection.execute(
            "SELECT * FROM work_items WHERE package_path = ?", (str(candidate),)
        ).fetchone()
        numbered = self._items_for_number(connection, candidate.name)
        others = [row for row in numbered if exact is None or row["id"] != exact["id"]]
        number = self._package_number(candidate.name)
        if exact is not None:
            if others:
                ids = ", ".join(str(row["id"]) for row in others)
                raise MailboxError(
                    f"package number {number} has conflicting tracked items: "
                    f"{exact['id']}, {ids}; operator reconciliation is required"
                )
            return exact, None
        if not numbered:
            return None, None
        if len(numbered) == 1:
            request_id = self._renamable_final_rework(
                connection, numbered[0], candidate
            )
            if request_id is not None:
                return numbered[0], request_id
        ids = ", ".join(str(row["id"]) for row in numbered)
        raise MailboxError(
            f"package number {number} is already tracked as item(s) {ids}; "
            "use the tracked path or an explicit operator reconciliation"
        )

    @staticmethod
    def _plain_package_name(package_name: str) -> str:
        if package_name.startswith(READY_PREFIX):
            return package_name[len(READY_PREFIX) :]
        return package_name

    def _dead_archive_root(self) -> Path:
        return (self.workspace / "ZDI" / DEAD_ARCHIVE_DIR).resolve()

    def _validate_dead_archive_package(self, package_path: str | Path) -> Path:
        package = self._resolve_numbered_package(package_path)
        if package.parent != self._dead_archive_root():
            raise MailboxError("DEAD package is not under ZDI/_NUMBERED")
        return package

    def _submitted_candidates(self, package_name: str) -> list[Path]:
        number = self._package_number(package_name)
        submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
        if not submitted_root.is_dir():
            return []
        prefix = f"_SUBMITTED_{number}_"
        return sorted(
            [
                path.resolve()
                for path in submitted_root.iterdir()
                if path.is_dir() and path.name.startswith(prefix)
            ],
            key=lambda path: path.name,
        )

    @staticmethod
    def _item(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    @staticmethod
    def _rework_request(row: sqlite3.Row) -> dict[str, Any]:
        request = dict(row)
        request["issues"] = json.loads(request.pop("issues_json"))
        request["evidence_refs"] = json.loads(request.pop("evidence_refs_json"))
        return request

    def _verify_addressed_rework(
        self,
        connection: sqlite3.Connection,
        item: dict[str, Any],
        timestamp: str,
    ) -> int | None:
        row = connection.execute(
            """
            SELECT id, addressed_hash, addressed_revision
            FROM final_rework_requests
            WHERE work_item_id = ? AND state = 'ADDRESSED'
              AND addressed_revision <= ?
            ORDER BY id DESC LIMIT 1
            """,
            (item["id"], item["revision"]),
        ).fetchone()
        if row is None:
            return None
        if (
            int(row["addressed_revision"]) == int(item["revision"])
            and row["addressed_hash"] != item["package_hash"]
        ):
            return None
        request_id = int(row["id"])
        connection.execute(
            """
            UPDATE final_rework_requests
            SET state = 'VERIFIED', verified_at = ?, closed_at = ?
            WHERE id = ?
            """,
            (timestamp, timestamp, request_id),
        )
        superseded = supersede_older_addressed(
            connection,
            work_item_id=int(item["id"]),
            verified_request_id=request_id,
            timestamp=timestamp,
        )
        self._event(
            connection,
            int(item["id"]),
            "operator",
            "FINAL_REWORK_VERIFIED",
            {
                "request_id": request_id,
                "addressed_hash": row["addressed_hash"],
                "addressed_revision": int(row["addressed_revision"]),
                "package_hash": item["package_hash"],
                "revision": item["revision"],
                "superseded_requests": superseded,
            },
        )
        return request_id

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        item_id: int | None,
        actor: str,
        event_type: str,
        detail: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO events(work_item_id, actor, event_type, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (item_id, actor, event_type, json.dumps(detail, sort_keys=True), utc_now()),
        )

    def _workers(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        workers: list[dict[str, Any]] = []
        seen_workers: set[str] = set()
        activity_by_worker = {
            str(row["worker"]).casefold(): row
            for row in connection.execute(
                """
                SELECT worker, category, detail, source, session_hash, target,
                       updated_at
                FROM worker_activity
                """
            )
        }
        for row in connection.execute(
            """
            SELECT worker, state, task, detail, updated_at
            FROM worker_status
            ORDER BY lower(worker), updated_at DESC,
                     CASE WHEN worker = lower(worker) THEN 0 ELSE 1 END,
                     worker
            """
        ):
            worker = str(row["worker"]).casefold()
            if worker in seen_workers:
                continue
            seen_workers.add(worker)
            semantic_age = _age_fields(row["updated_at"], now)
            activity = activity_by_worker.get(worker)
            activity_age = (
                _age_fields(activity["updated_at"], now)
                if activity is not None
                else None
            )
            effective_updated_at = row["updated_at"]
            if activity is not None and datetime.fromisoformat(
                activity["updated_at"]
            ) > datetime.fromisoformat(row["updated_at"]):
                effective_updated_at = activity["updated_at"]
            age = _age_fields(effective_updated_at, now)
            age_seconds = int(age["age_seconds"])
            stale_after_seconds = WORKER_STALE_AFTER_SECONDS
            stale = row["state"] == "WORKING" and age_seconds > stale_after_seconds
            # Semantic check-ins are event-driven. Elapsed time may indicate
            # total inactivity, but it never makes a Hunter check-in due.
            checkin_due = False
            workers.append(
                {
                    "age": age["age"],
                    "age_seconds": age_seconds,
                    "activity_age": (
                        activity_age["age"] if activity_age is not None else None
                    ),
                    "activity_age_seconds": (
                        int(activity_age["age_seconds"])
                        if activity_age is not None
                        else None
                    ),
                    "activity_category": (
                        activity["category"] if activity is not None else ""
                    ),
                    "activity_detail": (
                        activity["detail"] if activity is not None else ""
                    ),
                    "activity_source": (
                        activity["source"] if activity is not None else ""
                    ),
                    "activity_target": (
                        activity["target"] if activity is not None else ""
                    ),
                    "activity_updated_at": (
                        activity["updated_at"] if activity is not None else None
                    ),
                    "detail": row["detail"],
                    "checkin_due": checkin_due,
                    "checkin_due_after_seconds": None,
                    "stale": stale,
                    "stale_after_seconds": stale_after_seconds,
                    "state": row["state"],
                    "semantic_age": semantic_age["age"],
                    "semantic_age_seconds": int(semantic_age["age_seconds"]),
                    "task": row["task"],
                    "updated_at": row["updated_at"],
                    "worker": worker,
                }
            )
        return workers

    def record_worker_activity(
        self,
        worker: str,
        *,
        category: str,
        detail: str,
        source: str,
        session_hash: str = "",
        target: str = "",
    ) -> dict[str, Any]:
        """Record sanitized tool-proven activity without changing semantic status."""
        if not isinstance(worker, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", worker
        ):
            raise MailboxError("invalid activity worker")
        if not isinstance(category, str) or not re.fullmatch(
            r"[A-Z0-9 _-]{1,64}", category
        ):
            raise MailboxError("invalid activity category")
        if (
            not isinstance(detail, str)
            or not detail
            or len(detail) > 240
            or any(ord(character) < 32 or ord(character) > 126 for character in detail)
        ):
            raise MailboxError("activity detail must be 1-240 printable ASCII characters")
        if not isinstance(source, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", source
        ):
            raise MailboxError("invalid activity source")
        if session_hash and not re.fullmatch(r"[0-9a-f]{64}", session_hash):
            raise MailboxError("activity session hash must be lowercase SHA-256")
        if target and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", target):
            raise MailboxError("invalid activity target")

        worker = worker.casefold()
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO worker_activity(
                    worker, category, detail, source, session_hash, target, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker) DO UPDATE SET
                    category = excluded.category,
                    detail = excluded.detail,
                    source = excluded.source,
                    session_hash = excluded.session_hash,
                    target = excluded.target,
                    updated_at = excluded.updated_at
                """,
                (
                    worker,
                    category,
                    detail,
                    source,
                    session_hash,
                    target,
                    timestamp,
                ),
            )
            row = connection.execute(
                """
                SELECT worker, category, detail, source, session_hash, target,
                       updated_at
                FROM worker_activity WHERE worker = ?
                """,
                (worker,),
            ).fetchone()
        return dict(row)

    def clear_worker_activity(
        self,
        worker: str,
        *,
        category: str,
        source: str,
        session_hash: str,
    ) -> dict[str, Any]:
        """Clear only the exact transient activity record owned by one caller."""
        if not isinstance(worker, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", worker
        ):
            raise MailboxError("invalid activity worker")
        if not isinstance(category, str) or not re.fullmatch(
            r"[A-Z0-9 _-]{1,64}", category
        ):
            raise MailboxError("invalid activity category")
        if not isinstance(source, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", source
        ):
            raise MailboxError("invalid activity source")
        if not re.fullmatch(r"[0-9a-f]{64}", session_hash):
            raise MailboxError("activity session hash must be lowercase SHA-256")

        worker = worker.casefold()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """
                SELECT category, source, session_hash
                FROM worker_activity WHERE worker = ?
                """,
                (worker,),
            ).fetchone()
            if current is None:
                return {"cleared": False, "reason": "NO_ACTIVITY"}
            if (
                current["category"] != category
                or current["source"] != source
                or current["session_hash"] != session_hash
            ):
                return {"cleared": False, "reason": "ACTIVITY_CHANGED"}
            connection.execute(
                "DELETE FROM worker_activity WHERE worker = ?",
                (worker,),
            )
        return {"cleared": True, "reason": "CLEARED"}

    @staticmethod
    def _operator_request(
        row: sqlite3.Row,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        request = dict(row)
        request.update(_age_fields(request["updated_at"], now))
        return request

    def _operator_requests(
        self,
        connection: sqlite3.Connection,
    ) -> list[dict[str, Any]]:
        return self._open_operator_attention_requests(connection, "operator_requests")

    def _operator_approval_requests(
        self,
        connection: sqlite3.Connection,
    ) -> list[dict[str, Any]]:
        return self._open_operator_attention_requests(
            connection, "operator_approval_requests"
        )

    def _open_operator_attention_requests(
        self,
        connection: sqlite3.Connection,
        table: str,
    ) -> list[dict[str, Any]]:
        self._validate_operator_attention_table(table)
        now = datetime.now(UTC)
        return [
            self._operator_request(row, now)
            for row in connection.execute(
                f"""
                SELECT worker, target, summary, detail, state, created_at,
                       updated_at, cleared_at, clear_note
                FROM {table}
                WHERE state = 'OPEN'
                ORDER BY updated_at DESC, lower(worker)
                """
            )
        ]

    @staticmethod
    def _validate_operator_attention_table(table: str) -> None:
        if table not in {"operator_requests", "operator_approval_requests"}:
            raise MailboxError("invalid operator-attention table")

    @staticmethod
    def _validate_operator_request_worker(worker: str) -> str:
        if (
            not isinstance(worker, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", worker)
        ):
            raise MailboxError(
                "worker must be 1-64 letters, numbers, dots, underscores, or hyphens"
            )
        return worker.casefold()

    def request_operator(
        self,
        worker: str,
        target: str,
        summary: str,
        detail: str = "",
    ) -> dict[str, Any]:
        return self._request_operator_attention(
            table="operator_requests",
            event_type="OPERATOR_REQUESTED",
            label="operator request",
            worker=worker,
            target=target,
            summary=summary,
            detail=detail,
        )

    def request_operator_approval(
        self,
        worker: str,
        target: str,
        summary: str,
        detail: str = "",
    ) -> dict[str, Any]:
        return self._request_operator_attention(
            table="operator_approval_requests",
            event_type="OPERATOR_APPROVAL_REQUESTED",
            label="operator approval request",
            worker=worker,
            target=target,
            summary=summary,
            detail=detail,
        )

    def _request_operator_attention(
        self,
        *,
        table: str,
        event_type: str,
        label: str,
        worker: str,
        target: str,
        summary: str,
        detail: str,
    ) -> dict[str, Any]:
        self._validate_operator_attention_table(table)
        worker = self._validate_operator_request_worker(worker)
        if (
            not isinstance(target, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", target)
        ):
            raise MailboxError(
                "target must be 1-128 letters, numbers, dots, underscores, or hyphens"
            )
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError(f"{label} summary is required")
        summary = summary.strip()
        if len(summary) > 160:
            raise MailboxError(f"{label} summary must be at most 160 characters")
        if "\n" in summary or "\r" in summary:
            raise MailboxError(f"{label} summary must be one line")
        if not isinstance(detail, str):
            raise MailboxError(f"{label} detail must be a string")
        detail = detail.strip()
        if len(detail) > 1000:
            raise MailboxError(f"{label} detail must be at most 1000 characters")

        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                f"""
                INSERT INTO {table}(
                    worker, target, summary, detail, state, created_at,
                    updated_at, cleared_at, clear_note
                ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, NULL, '')
                ON CONFLICT(worker) DO UPDATE SET
                    target = excluded.target,
                    summary = excluded.summary,
                    detail = excluded.detail,
                    state = 'OPEN',
                    created_at = CASE
                        WHEN {table}.state = 'OPEN'
                            THEN {table}.created_at
                        ELSE excluded.created_at
                    END,
                    updated_at = excluded.updated_at,
                    cleared_at = NULL,
                    clear_note = ''
                """,
                (worker, target, summary, detail, timestamp, timestamp),
            )
            self._event(
                connection,
                None,
                worker,
                event_type,
                {
                    "detail": detail,
                    "summary": summary,
                    "target": target,
                    "worker": worker,
                },
            )
            row = connection.execute(
                f"SELECT * FROM {table} WHERE worker = ?",
                (worker,),
            ).fetchone()
            if row is None:
                raise MailboxError(f"{label} was not persisted")
            return self._operator_request(row)

    def clear_operator_request(
        self,
        worker: str,
        note: str = "",
    ) -> dict[str, Any] | None:
        return self._clear_operator_attention(
            table="operator_requests",
            event_type="OPERATOR_REQUEST_CLEARED",
            label="operator request",
            worker=worker,
            note=note,
        )

    def clear_operator_approval(
        self,
        worker: str,
        note: str = "",
    ) -> dict[str, Any] | None:
        return self._clear_operator_attention(
            table="operator_approval_requests",
            event_type="OPERATOR_APPROVAL_REQUEST_CLEARED",
            label="operator approval request",
            worker=worker,
            note=note,
        )

    def _clear_operator_attention(
        self,
        *,
        table: str,
        event_type: str,
        label: str,
        worker: str,
        note: str,
    ) -> dict[str, Any] | None:
        self._validate_operator_attention_table(table)
        worker = self._validate_operator_request_worker(worker)
        if not isinstance(note, str):
            raise MailboxError(f"{label} clear note must be a string")
        note = note.strip()
        if len(note) > 500:
            raise MailboxError(f"{label} clear note must be at most 500 characters")

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                f"SELECT * FROM {table} WHERE worker = ?",
                (worker,),
            ).fetchone()
            if row is None:
                return None
            if row["state"] == "OPEN":
                timestamp = utc_now()
                connection.execute(
                    f"""
                    UPDATE {table}
                    SET state = 'CLEARED', updated_at = ?, cleared_at = ?,
                        clear_note = ?
                    WHERE worker = ?
                    """,
                    (timestamp, timestamp, note, worker),
                )
                self._event(
                    connection,
                    None,
                    worker,
                    event_type,
                    {
                        "note": note,
                        "summary": row["summary"],
                        "target": row["target"],
                        "worker": worker,
                    },
                )
                row = connection.execute(
                    f"SELECT * FROM {table} WHERE worker = ?",
                    (worker,),
                ).fetchone()
            return self._operator_request(row)

    def _clear_item_operator_requests(
        self,
        connection: sqlite3.Connection,
        item_id: int,
        timestamp: str,
    ) -> int:
        target = f"mailbox_item_{item_id}"
        rows = connection.execute(
            "SELECT worker, summary FROM operator_requests "
            "WHERE state = 'OPEN' AND target = ?",
            (target,),
        ).fetchall()
        note = f"Automatically cleared by DEAD item {item_id}."
        for row in rows:
            connection.execute(
                """
                UPDATE operator_requests
                SET state = 'CLEARED', updated_at = ?, cleared_at = ?, clear_note = ?
                WHERE worker = ? AND state = 'OPEN' AND target = ?
                """,
                (timestamp, timestamp, note, row["worker"], target),
            )
            self._event(
                connection,
                item_id,
                "operator",
                "OPERATOR_REQUEST_CLEARED",
                {
                    "note": note,
                    "summary": row["summary"],
                    "target": target,
                    "worker": row["worker"],
                },
            )
        return len(rows)

    def _active_target_slugs(self) -> list[str]:
        lifecycle_db = (
            self.workspace
            / "notes"
            / "target_lifecycle"
            / "target_lifecycle.sqlite3"
        )
        if not lifecycle_db.is_file():
            return []
        try:
            uri = lifecycle_db.resolve().as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as connection:
                rows = connection.execute(
                    "SELECT slug FROM targets WHERE status = 'ACTIVE' ORDER BY slug"
                ).fetchall()
        except sqlite3.Error as error:
            raise MailboxError(
                "cannot verify target lifecycle before Hunter IDLE check-in: "
                f"{error}"
            ) from error
        return [str(row[0]) for row in rows]

    def _target_lifecycle_status(self, slug: str) -> str:
        lifecycle_db = (
            self.workspace
            / "notes"
            / "target_lifecycle"
            / "target_lifecycle.sqlite3"
        )
        if not lifecycle_db.is_file():
            raise MailboxError("target lifecycle database is unavailable")
        try:
            uri = lifecycle_db.resolve().as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as connection:
                row = connection.execute(
                    "SELECT status FROM targets WHERE slug = ?", (slug,)
                ).fetchone()
        except sqlite3.Error as error:
            raise MailboxError(
                f"cannot verify target lifecycle transition: {error}"
            ) from error
        if row is None:
            raise MailboxError(f"unknown target lifecycle slug {slug!r}")
        return str(row[0]).upper()

    def _private_workspace_file(self, value: str | Path | None, label: str) -> Path:
        if value is None:
            raise MailboxError(f"{label} is required")
        path = Path(value).resolve()
        try:
            path.relative_to(self.workspace)
        except ValueError as error:
            raise MailboxError(f"{label} must be inside the workspace") from error
        for external_root in (
            (self.workspace / "ZDI").resolve(),
            (self.workspace / "ZDI_STAGING").resolve(),
        ):
            try:
                path.relative_to(external_root)
            except ValueError:
                continue
            raise MailboxError(f"{label} must remain outside external package roots")
        if not path.is_file():
            raise MailboxError(f"{label} does not exist: {path}")
        return path

    def target_transition(
        self,
        worker: str,
        slug: str,
        phase: str,
        detail: str,
        resume_capsule: str | Path | None = None,
        shutdown_check: str | Path | None = None,
    ) -> dict[str, Any]:
        """Record one validated Hunter stand-down or parked transition."""
        if not isinstance(worker, str) or worker.casefold() != "hunter":
            raise MailboxError("target transitions are reserved for Hunter")
        if not isinstance(slug, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,128}", slug
        ):
            raise MailboxError("target transition slug is invalid")
        phase = str(phase).upper()
        if phase not in {"STANDING_DOWN", "PARKED"}:
            raise MailboxError("target transition phase must be STANDING_DOWN or PARKED")
        if not isinstance(detail, str) or not detail.strip():
            raise MailboxError("target transition detail is required")

        lifecycle_status = self._target_lifecycle_status(slug)
        capsule_path: Path | None = None
        shutdown_path: Path | None = None
        if phase == "STANDING_DOWN":
            if lifecycle_status != "ACTIVE":
                raise MailboxError(
                    f"STANDING_DOWN requires ACTIVE, found {lifecycle_status}"
                )
            state = "WORKING"
            task = f"STANDING DOWN - {slug}"
            event_type = "TARGET_STAND_DOWN_STARTED"
        else:
            if lifecycle_status != "PARKED_REHYDRATABLE":
                raise MailboxError(
                    "PARKED requires PARKED_REHYDRATABLE, "
                    f"found {lifecycle_status}"
                )
            active_slugs = self._active_target_slugs()
            if active_slugs:
                raise MailboxError(
                    "PARKED cannot set Hunter IDLE while a target remains ACTIVE: "
                    + ", ".join(active_slugs)
                )
            capsule_path = self._private_workspace_file(
                resume_capsule, "resume capsule"
            )
            shutdown_path = self._private_workspace_file(
                shutdown_check, "shutdown check"
            )
            try:
                shutdown_payload = json.loads(
                    shutdown_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise MailboxError(f"cannot read shutdown check: {error}") from error
            if (
                not isinstance(shutdown_payload, dict)
                or shutdown_payload.get("ready") is not True
                or shutdown_payload.get("fatal") not in (None, [])
            ):
                raise MailboxError("shutdown check is not clean")
            state = "IDLE"
            task = f"PARKED - {slug}"
            event_type = "TARGET_PARKED"

        timestamp = utc_now()
        event_detail: dict[str, Any] = {
            "detail": detail.strip(),
            "phase": phase,
            "state": state,
            "summary": f"{task} - {detail.strip()}",
            "target": slug,
            "task": task,
            "worker": "hunter",
        }
        if capsule_path is not None and shutdown_path is not None:
            event_detail.update(
                {
                    "resume_capsule": capsule_path.relative_to(self.workspace).as_posix(),
                    "shutdown_check": shutdown_path.relative_to(self.workspace).as_posix(),
                }
            )

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO worker_status(worker, state, task, detail, updated_at)
                VALUES ('hunter', ?, ?, ?, ?)
                ON CONFLICT(worker) DO UPDATE SET
                    state = excluded.state,
                    task = excluded.task,
                    detail = excluded.detail,
                    updated_at = excluded.updated_at
                """,
                (state, task, detail.strip(), timestamp),
            )
            if phase == "PARKED":
                connection.execute(
                    "DELETE FROM worker_activity WHERE worker = 'hunter'"
                )
            self._event(connection, None, "hunter", event_type, event_detail)
            return next(
                status
                for status in self._workers(connection)
                if status["worker"] == "hunter"
            )

    def checkin(
        self,
        worker: str,
        state: str,
        task: str,
        detail: str = "",
        session_hash: str = "",
    ) -> dict[str, Any]:
        if (
            not isinstance(worker, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", worker)
        ):
            raise MailboxError(
                "worker must be 1-64 letters, numbers, dots, underscores, or hyphens"
            )
        worker = worker.casefold()
        state = state.upper()
        if state not in {"WORKING", "IDLE", "BLOCKED"}:
            raise MailboxError("check-in state must be WORKING, IDLE, or BLOCKED")
        if not isinstance(task, str) or not task.strip():
            raise MailboxError("check-in task is required")
        if not isinstance(detail, str):
            raise MailboxError("check-in detail must be a string")
        if worker == "hunter":
            authority_path = (
                self.workspace
                / "notes"
                / "review_mailbox"
                / "hunter_semantic_authority.json"
            )
            if authority_path.is_file():
                try:
                    authority = json.loads(
                        authority_path.read_text(encoding="utf-8")
                    )
                    expected_session_hash = str(authority["session_hash"])
                except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
                    raise MailboxError(
                        "Hunter semantic authority record is invalid"
                    ) from error
                if not re.fullmatch(r"[0-9a-f]{64}", expected_session_hash):
                    raise MailboxError("Hunter semantic authority record is invalid")
                if session_hash != expected_session_hash:
                    raise MailboxError(
                        "Hunter semantic check-in denied: caller is not the "
                        "active root Hunter session"
                    )
        if worker == "hunter" and state == "WORKING":
            lifecycle_db = (
                self.workspace
                / "notes"
                / "target_lifecycle"
                / "target_lifecycle.sqlite3"
            )
            if lifecycle_db.is_file():
                active_slugs = self._active_target_slugs()
                if len(active_slugs) != 1:
                    found = ", ".join(active_slugs) if active_slugs else "none"
                    raise MailboxError(
                        "Hunter WORKING check-in requires exactly one ACTIVE target; "
                        f"found {found}. Activate the exact goal before check-in."
                    )
        if worker == "hunter" and state == "IDLE":
            active_slugs = self._active_target_slugs()
            if active_slugs:
                raise MailboxError(
                    "Hunter cannot check in IDLE while target lifecycle is ACTIVE: "
                    + ", ".join(active_slugs)
                    + "; continue WORKING, use BLOCKED for a real blocker, or "
                    "have the operator park/switch the target"
                )
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if worker == "midlane" and state == "IDLE":
                candidate_table = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'candidate_challenges'"
                ).fetchone()
                if candidate_table is not None:
                    ready_candidate = connection.execute(
                        """
                        SELECT id
                        FROM candidate_challenges
                        WHERE state = 'PENDING'
                           OR (state = 'CLAIMED' AND reviewer = 'midlane')
                        ORDER BY updated_at, id
                        LIMIT 1
                        """
                    ).fetchone()
                    if ready_candidate is not None:
                        raise MailboxError(
                            "Midlane cannot check in IDLE: Candidate Challenge "
                            f"{int(ready_candidate['id'])} is ready; run "
                            "candidate_challenge.py claim-next --reviewer midlane "
                            "before waiting"
                        )
            existing = connection.execute(
                """
                SELECT state, task, detail, updated_at
                FROM worker_status WHERE worker = ?
                """,
                (worker,),
            ).fetchone()
            if (
                existing is not None
                and existing["state"] == state
                and existing["task"] == task.strip()
                and existing["detail"] == detail.strip()
            ):
                status = next(
                    status
                    for status in self._workers(connection)
                    if status["worker"] == worker
                )
                status["semantic_change"] = False
                return self._decorate_hunt_policy(status, worker)
            connection.execute(
                """
                INSERT INTO worker_status(worker, state, task, detail, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(worker) DO UPDATE SET
                    state = excluded.state,
                    task = excluded.task,
                    detail = excluded.detail,
                    updated_at = excluded.updated_at
                """,
                (worker, state, task.strip(), detail.strip(), timestamp),
            )
            self._event(
                connection,
                None,
                worker,
                "WORKER_CHECKIN",
                {
                    "detail": detail.strip(),
                    "state": state,
                    "task": task.strip(),
                    "worker": worker,
                },
            )
            status = next(
                status
                for status in self._workers(connection)
                if status["worker"] == worker
            )
            status["semantic_change"] = True
            return self._decorate_hunt_policy(status, worker)

    def _decorate_hunt_policy(
        self,
        status: dict[str, Any],
        worker: str,
    ) -> dict[str, Any]:
        if worker != "hunter":
            return status
        policy_dir = Path(__file__).resolve().parents[1] / "hunt_policy"
        if str(policy_dir) not in sys.path:
            sys.path.insert(0, str(policy_dir))
        try:
            from hunt_policy import HuntPolicyStore

            database = (
                self.workspace
                / "notes"
                / "hunt_policy"
                / "hunt_policy.sqlite3"
            )
            delta = HuntPolicyStore(database, self.workspace).pending_for("hunter")
        except Exception:
            status["hunt_policy_warning"] = "hunt profile unavailable"
            return status
        if delta is not None:
            status["hunt_policy_delta"] = delta
        return status

    @staticmethod
    def _set_worker_status(
        connection: sqlite3.Connection,
        worker: str,
        state: str,
        task: str,
        detail: str,
        timestamp: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO worker_status(worker, state, task, detail, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(worker) DO UPDATE SET
                state = excluded.state,
                task = excluded.task,
                detail = excluded.detail,
                updated_at = excluded.updated_at
            """,
            (worker, state, task, detail, timestamp),
        )

    def activity_heartbeat(
        self,
        worker: str,
        *,
        source: str,
        minimum_age_seconds: int = DEFAULT_ACTIVITY_HEARTBEAT_MINIMUM_SECONDS,
        expected_task_hash: str = "",
        expected_detail_hash: str = "",
    ) -> dict[str, Any]:
        """Record owned activity without changing the semantic check-in clock."""
        if not isinstance(worker, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", worker
        ):
            raise MailboxError("invalid heartbeat worker")
        if not isinstance(source, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", source
        ):
            raise MailboxError("invalid heartbeat source")
        if not isinstance(minimum_age_seconds, int) or minimum_age_seconds < 0:
            raise MailboxError("minimum heartbeat age must be a non-negative integer")
        for value, label in (
            (expected_task_hash, "task"),
            (expected_detail_hash, "detail"),
        ):
            if value and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise MailboxError(f"expected {label} hash must be lowercase SHA-256")

        worker = worker.casefold()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT worker, state, task, detail, updated_at
                FROM worker_status WHERE worker = ?
                """,
                (worker,),
            ).fetchone()
            if row is None:
                return {"reason": "NO_CHECKIN", "refreshed": False}
            if row["state"] != "WORKING":
                return {"reason": "NOT_WORKING", "refreshed": False}
            task_hash = hashlib.sha256(row["task"].encode("utf-8")).hexdigest()
            detail_hash = hashlib.sha256(row["detail"].encode("utf-8")).hexdigest()
            if expected_task_hash and task_hash != expected_task_hash:
                return {"reason": "TASK_CHANGED", "refreshed": False}
            if expected_detail_hash and detail_hash != expected_detail_hash:
                return {"reason": "DETAIL_CHANGED", "refreshed": False}
            activity = connection.execute(
                """
                SELECT session_hash, target, updated_at
                FROM worker_activity WHERE worker = ?
                """,
                (worker,),
            ).fetchone()
            effective_updated_at = row["updated_at"]
            if activity is not None and datetime.fromisoformat(
                activity["updated_at"]
            ) > datetime.fromisoformat(row["updated_at"]):
                effective_updated_at = activity["updated_at"]
            age_seconds = max(
                0,
                int(
                    (
                        datetime.now(UTC) - datetime.fromisoformat(effective_updated_at)
                    ).total_seconds()
                ),
            )
            if age_seconds < minimum_age_seconds:
                return {"reason": "NOT_DUE", "refreshed": False}

            timestamp = utc_now()
            connection.execute(
                """
                INSERT INTO worker_activity(
                    worker, category, detail, source, session_hash, target, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker) DO UPDATE SET
                    category = excluded.category,
                    detail = excluded.detail,
                    source = excluded.source,
                    session_hash = excluded.session_hash,
                    target = excluded.target,
                    updated_at = excluded.updated_at
                """,
                (
                    worker,
                    "AUTOMATIC ACTIVITY",
                    f"{activity['target'] if activity is not None and activity['target'] else 'active target'} - automatic activity heartbeat",
                    source,
                    activity["session_hash"] if activity is not None else "",
                    activity["target"] if activity is not None else "",
                    timestamp,
                ),
            )
            self._event(
                connection,
                None,
                worker,
                "WORKER_ACTIVITY_HEARTBEAT",
                {
                    "age_seconds_before_refresh": age_seconds,
                    "source": source,
                    "state": row["state"],
                    "task": row["task"],
                    "worker": worker,
                },
            )
            return {
                "refreshed": True,
                "worker": next(
                    status
                    for status in self._workers(connection)
                    if status["worker"] == worker
                ),
            }

    def _get_item(self, connection: sqlite3.Connection, item_id: int) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM work_items WHERE id = ?", (item_id,)
        ).fetchone()
        if row is None:
            raise MailboxError(f"unknown work item: {item_id}")
        return self._item(row)

    def begin_package_build(
        self,
        package_path: str | Path,
        product: str,
        version: str,
        detail: str = "",
        candidate_challenge_result: str | Path | None = None,
    ) -> dict[str, Any]:
        package = self._validate_staging_package(package_path)
        if not isinstance(product, str) or not product.strip():
            raise MailboxError("package build product is required")
        if not isinstance(version, str) or not version.strip():
            raise MailboxError("package build version is required")
        if not isinstance(detail, str):
            raise MailboxError("package build detail must be a string")
        package_number = int(self._package_number(package.name))
        challenge: dict[str, Any] | None = None
        if candidate_challenge_result is None:
            if self.require_candidate_challenge:
                raise MailboxError(
                    "admitted candidate challenge result is required before "
                    "assigning a package number"
                )
        else:
            try:
                challenge = validate_candidate_challenge_result(
                    workspace=self.workspace,
                    db_path=self.db_path,
                    result_path=candidate_challenge_result,
                    product=product.strip(),
                    version=version.strip(),
                )
            except CandidateChallengeError as error:
                raise MailboxError(str(error)) from error
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            tracked = self._items_for_number(connection, package.name)
            if tracked:
                ids = ", ".join(str(row["id"]) for row in tracked)
                raise MailboxError(
                    f"package number {package_number} is already tracked as "
                    f"item(s) {ids}"
                )
            existing = connection.execute(
                "SELECT * FROM package_builds WHERE package_number = ?",
                (package_number,),
            ).fetchone()
            if (
                existing is not None
                and Path(str(existing["package_path"])).resolve() != package
            ):
                raise MailboxError(
                    f"package number {package_number} already has an active "
                    "build at another path; cancel it first"
                )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO package_builds(
                        package_number, package_path, product, version,
                        candidate_challenge_id, detail, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        package_number,
                        str(package),
                        product.strip(),
                        version.strip(),
                        (
                            int(challenge["candidate_id"])
                            if challenge is not None
                            else None
                        ),
                        detail.strip(),
                        timestamp,
                        timestamp,
                    ),
                )
                event_type = "PACKAGE_BUILD_STARTED"
            else:
                connection.execute(
                    """
                    UPDATE package_builds
                    SET product = ?, version = ?, candidate_challenge_id = ?,
                        detail = ?, updated_at = ?
                    WHERE package_number = ?
                    """,
                    (
                        product.strip(),
                        version.strip(),
                        (
                            int(challenge["candidate_id"])
                            if challenge is not None
                            else existing["candidate_challenge_id"]
                        ),
                        detail.strip(),
                        timestamp,
                        package_number,
                    ),
                )
                event_type = "PACKAGE_BUILD_UPDATED"
            if challenge is not None:
                challenge_row = connection.execute(
                    """
                    SELECT disposition, package_number
                    FROM candidate_challenges WHERE id = ?
                    """,
                    (int(challenge["candidate_id"]),),
                ).fetchone()
                if challenge_row is None or challenge_row["disposition"] not in {
                    "ADMIT_PROOF",
                    "OPERATOR_EXCEPTION",
                }:
                    raise MailboxError(
                        "candidate challenge no longer authorizes package construction"
                    )
                if challenge_row["package_number"] not in (None, package_number):
                    raise MailboxError(
                        "candidate challenge is already bound to another package"
                    )
                connection.execute(
                    """
                    UPDATE candidate_challenges
                    SET package_number = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        package_number,
                        timestamp,
                        int(challenge["candidate_id"]),
                    ),
                )
            self._event(
                connection,
                None,
                "hunter",
                event_type,
                {
                    "package_number": package_number,
                    "summary": (
                        f"Package {package_number} build "
                        + ("started" if existing is None else "updated")
                    ),
                    **(
                        {"candidate_challenge_id": int(challenge["candidate_id"])}
                        if challenge is not None
                        else {}
                    ),
                },
            )
            row = connection.execute(
                "SELECT * FROM package_builds WHERE package_number = ?",
                (package_number,),
            ).fetchone()
            build = dict(row)
            build["state"] = "BUILDING_PACKAGE"
            return build

    def rebind_final_rework_candidate(
        self,
        item_id: int,
        candidate_challenge_result: str | Path,
        expected_package_hash: str,
    ) -> dict[str, Any]:
        if not isinstance(item_id, int) or item_id <= 0:
            raise MailboxError("work item id must be a positive integer")
        if not isinstance(expected_package_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_package_hash
        ):
            raise MailboxError("expected package hash must be lowercase SHA-256")
        with self._connect() as connection:
            item = self._get_item(connection, item_id)
            if item["state"] != "FINAL_REWORK":
                raise MailboxError(
                    "candidate rebind requires a claimed FINAL_REWORK item"
                )
            request_id = self._claimed_rework_request_id(connection, item_id)
            if request_id is None:
                raise MailboxError(
                    "candidate rebind requires a claimed final rework request"
                )
            prior_candidate_id = item.get("candidate_challenge_id")
            if prior_candidate_id is None:
                raise MailboxError(
                    "final rework item has no Candidate Challenge binding"
                )
        package = self._validate_tracked_package(item["package_path"])
        observed_hash = self._hash_package(package)
        if observed_hash != expected_package_hash:
            raise MailboxError("final rework package hash does not match expected hash")
        try:
            challenge = validate_candidate_challenge_result(
                workspace=self.workspace,
                db_path=self.db_path,
                result_path=candidate_challenge_result,
                product=item["product"],
                version=item["version"],
            )
        except CandidateChallengeError as error:
            raise MailboxError(str(error)) from error
        candidate_id = int(challenge["candidate_id"])
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM work_items WHERE id = ?", (item_id,)
            ).fetchone()
            if row is None or row["state"] != "FINAL_REWORK":
                raise MailboxError("candidate rebind lost FINAL_REWORK authority")
            current_request_id = self._claimed_rework_request_id(connection, item_id)
            if current_request_id != request_id or int(
                row["candidate_challenge_id"]
            ) != int(prior_candidate_id):
                raise MailboxError("candidate rebind authority changed during validation")
            prior = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (int(prior_candidate_id),),
            ).fetchone()
            replacement = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            if prior is None or replacement is None:
                raise MailboxError("Candidate Challenge binding is missing")
            for field in (
                "candidate_key",
                "product",
                "version",
                "target_slug",
                "root_family_id",
            ):
                if replacement[field] != prior[field]:
                    raise MailboxError(
                        f"refreshed candidate changes protected identity field: {field}"
                    )
            package_number = int(self._package_number(package.name))
            if replacement["package_number"] != package_number:
                raise MailboxError(
                    "refreshed candidate is not bound to this package number"
                )
            conflict = connection.execute(
                """
                SELECT id FROM work_items
                WHERE candidate_challenge_id = ? AND id != ?
                """,
                (candidate_id, item_id),
            ).fetchone()
            if conflict is not None:
                raise MailboxError(
                    "refreshed candidate is already bound to another work item"
                )
            observed_hash = self._hash_package(package)
            if observed_hash != expected_package_hash:
                raise MailboxError(
                    "final rework package changed during candidate rebind"
                )
            connection.execute(
                """
                UPDATE work_items
                SET candidate_challenge_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (candidate_id, timestamp, item_id),
            )
            self._event(
                connection,
                item_id,
                "hunter",
                "FINAL_REWORK_CANDIDATE_REBOUND",
                {
                    "candidate_id": candidate_id,
                    "candidate_key": replacement["candidate_key"],
                    "package_hash": observed_hash,
                    "package_number": package_number,
                    "prior_candidate_id": int(prior_candidate_id),
                    "request_id": request_id,
                    "summary": (
                        f"Package {package_number} final rework rebound to "
                        "a fresh admitted Candidate Challenge"
                    ),
                },
            )
            request_row = connection.execute(
                "SELECT * FROM final_rework_requests WHERE id = ?", (request_id,)
            ).fetchone()
            return {
                "item": self._get_item(connection, item_id),
                "request": self._rework_request(request_row),
                "binding": {
                    "candidate_id": candidate_id,
                    "candidate_key": replacement["candidate_key"],
                    "package_hash": observed_hash,
                    "prior_candidate_id": int(prior_candidate_id),
                },
            }

    def cancel_package_build(self, package_number: int) -> dict[str, Any]:
        if not isinstance(package_number, int) or package_number <= 0:
            raise MailboxError("package build number must be a positive integer")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM package_builds WHERE package_number = ?",
                (package_number,),
            ).fetchone()
            if row is None:
                raise MailboxError(f"package build {package_number} is not active")
            connection.execute(
                "DELETE FROM package_builds WHERE package_number = ?",
                (package_number,),
            )
            self._event(
                connection,
                None,
                "hunter",
                "PACKAGE_BUILD_CANCELLED",
                {
                    "package_number": package_number,
                    "summary": f"Package {package_number} build cancelled",
                },
            )
            build = dict(row)
            build["state"] = "CANCELLED"
            return build

    def rebind_final_rework_path(
        self,
        item_id: int,
        package_path: str | Path,
    ) -> dict[str, Any]:
        """Synchronize one claimed rework item after its staging folder is renamed."""
        package = self._validate_staging_package(package_path)
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "FINAL_REWORK":
                raise MailboxError(
                    "final-rework path rebind requires a claimed FINAL_REWORK item"
                )
            tracked = Path(item["package_path"]).resolve()
            if tracked == package:
                return item
            if tracked.exists():
                raise MailboxError(
                    "tracked final-rework path still exists; rename that exact folder first"
                )
            if self._package_number(tracked.name) != self._package_number(package.name):
                raise MailboxError(
                    "replacement final-rework path must retain the package number"
                )
            request_id = self._claimed_rework_request_id(connection, int(item["id"]))
            if request_id is None:
                raise MailboxError(
                    "final-rework path rebind requires one active claimed request"
                )
            authority = connection.execute(
                """
                SELECT * FROM package_mutation_authorities
                WHERE work_item_id = ? AND revision = ?
                """,
                (int(item["id"]), int(item["revision"])),
            ).fetchone()
            if (
                authority is None
                or authority["state"] != "CONSUMED"
                or authority["baseline_hash"] != item["package_hash"]
            ):
                raise MailboxError(
                    "final-rework path rebind requires current Hunter mutation authority"
                )
            same_number = []
            for child in package.parent.iterdir():
                if not child.is_dir():
                    continue
                try:
                    if self._package_number(child.name) == self._package_number(package.name):
                        same_number.append(child.resolve())
                except MailboxError:
                    continue
            if same_number != [package]:
                raise MailboxError(
                    "final-rework path rebind requires exactly one matching staging folder"
                )
            conflict = connection.execute(
                "SELECT id FROM work_items WHERE package_path = ? AND id <> ?",
                (str(package), int(item["id"])),
            ).fetchone()
            if conflict is not None:
                raise MailboxError("replacement path is tracked by another work item")
            connection.execute(
                "UPDATE work_items SET package_path = ?, updated_at = ? WHERE id = ?",
                (str(package), timestamp, int(item["id"])),
            )
            self._event(
                connection,
                int(item["id"]),
                "hunter",
                "FINAL_REWORK_PATH_REBOUND",
                {
                    "from": str(tracked),
                    "request_id": request_id,
                    "to": str(package),
                },
            )
            return self._get_item(connection, int(item["id"]))

    def register(
        self,
        package_path: str | Path,
        product: str,
        version: str,
        note: str = "",
        preflight_result: str | Path | None = None,
    ) -> dict[str, Any]:
        candidate = self._resolve_numbered_package(package_path)
        with self._connect() as connection:
            dead_item = self._dead_item_for_number(connection, candidate.name)
            if dead_item is not None:
                raise MailboxError(
                    "package number is terminal DEAD and cannot be registered; "
                    "a separate explicit operator reopen action is required"
                )
            existing, rename_request_id = self._registration_identity(
                connection, candidate
            )
            if existing is not None and existing["state"] == "HOLD":
                raise MailboxError(
                    "package is terminal HOLD and cannot be registered by Hunter; "
                    "an explicit operator transition is required"
                )
        package = (
            self._validate_tracked_package(candidate)
            if existing is not None
            else self._validate_staging_package(candidate)
        )
        self._validate_external_package(package)
        package_hash = self._hash_package(package)
        preflight = self._validate_preflight_result(
            package, package_hash, preflight_result, product
        )
        package_manifest_json = json.dumps(
            self._manifest_package(package), sort_keys=True
        )
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            locked_hash = self._hash_package(package)
            locked_manifest_json = json.dumps(
                self._manifest_package(package), sort_keys=True
            )
            if (
                locked_hash != package_hash
                or locked_manifest_json != package_manifest_json
            ):
                raise MailboxError(
                    "package changed during registration before the database transition"
                )
            if preflight is not None and preflight["final_rework"] is not None:
                goal_path = Path(preflight["goal_path"]).resolve()
                locked_goal_hash = hashlib.sha256(goal_path.read_bytes()).hexdigest()
                if locked_goal_hash != preflight["goal_hash"]:
                    raise MailboxError(
                        "final rework goal changed during registration"
                    )
                locked_rework = self._claimed_final_rework_preflight_context(
                    connection,
                    package,
                    locked_hash,
                    product,
                    goal_path,
                    locked_goal_hash,
                )
                if locked_rework != preflight["final_rework"]:
                    raise MailboxError(
                        "final rework lineage changed during registration"
                    )
                self._validate_preflight_lifecycle_binding(
                    goal_path,
                    locked_goal_hash,
                    product,
                    locked_rework,
                )
            dead_item = self._dead_item_for_number(connection, package.name)
            if dead_item is not None:
                raise MailboxError(
                    "package number is terminal DEAD and cannot be registered; "
                    "a separate explicit operator reopen action is required"
                )
            row = connection.execute(
                "SELECT * FROM work_items WHERE package_path = ?", (str(package),)
            ).fetchone()
            package_number = int(self._package_number(package.name))
            build_row = connection.execute(
                "SELECT * FROM package_builds WHERE package_number = ?",
                (package_number,),
            ).fetchone()
            identity, rename_request_id = self._registration_identity(
                connection, package
            )
            if row is None and identity is not None and rename_request_id is not None:
                prior_path = str(identity["package_path"])
                connection.execute(
                    "UPDATE work_items SET package_path = ?, updated_at = ? WHERE id = ?",
                    (str(package), timestamp, int(identity["id"])),
                )
                self._event(
                    connection,
                    int(identity["id"]),
                    "hunter",
                    "FINAL_REWORK_PATH_RENAMED",
                    {
                        "from": prior_path,
                        "request_id": rename_request_id,
                        "to": str(package),
                    },
                )
                row = connection.execute(
                    "SELECT * FROM work_items WHERE id = ?", (int(identity["id"]),)
                ).fetchone()
            if row is not None and row["state"] == "HOLD":
                raise MailboxError(
                    "package is terminal HOLD and cannot be registered by Hunter; "
                    "an explicit operator transition is required"
                )
            if row is None:
                if self.require_candidate_challenge and (
                    build_row is None
                    or build_row["candidate_challenge_id"] is None
                ):
                    raise MailboxError(
                        "new package registration requires an admitted, "
                        "package-bound Candidate Challenge"
                    )
                cursor = connection.execute(
                    """
                    INSERT INTO work_items(
                        package_path, product, version, package_hash, state,
                        hunter_note, package_manifest_json,
                        candidate_challenge_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'READY_FOR_MIDLANE', ?, ?, ?, ?, ?)
                    """,
                    (
                        str(package),
                        product,
                        version,
                        package_hash,
                        note,
                        package_manifest_json,
                        (
                            int(build_row["candidate_challenge_id"])
                            if build_row is not None
                            and build_row["candidate_challenge_id"] is not None
                            else None
                        ),
                        timestamp,
                        timestamp,
                    ),
                )
                item_id = int(cursor.lastrowid)
                self._event(
                    connection,
                    item_id,
                    "hunter",
                    "REGISTERED",
                    {
                        "package_hash": package_hash,
                        **(
                            {
                                "preflight_result_sha256": preflight[
                                    "result_sha256"
                                ],
                                "preflight_goal_hash": preflight["goal_hash"],
                            }
                            if preflight is not None
                            else {}
                        ),
                    },
                )
            else:
                item_id = int(row["id"])
                if row["package_hash"] != package_hash or row["state"] == "STALE":
                    prior_state = row["state"]
                    if prior_state in HUNTER_MUTABLE_STATES:
                        authority = connection.execute(
                            """
                            SELECT * FROM package_mutation_authorities
                            WHERE work_item_id = ? AND revision = ?
                              AND state = 'CONSUMED'
                            """,
                            (item_id, int(row["revision"])),
                        ).fetchone()
                        if authority is None:
                            raise MailboxError(
                                "package mutation authority was not obtained before "
                                "Hunter edited the package bytes"
                            )
                    if prior_state == "FINAL_REWORK" and self.require_candidate_challenge:
                        request_row = connection.execute(
                            """
                            SELECT review_scope, prior_candidate_challenge_id
                            FROM final_rework_requests
                            WHERE work_item_id = ? AND state = 'CLAIMED'
                            ORDER BY id DESC LIMIT 1
                            """,
                            (item_id,),
                        ).fetchone()
                        if (
                            request_row is not None
                            and request_row["review_scope"] == "SEMANTIC"
                            and request_row["prior_candidate_challenge_id"] is not None
                            and row["candidate_challenge_id"]
                            == request_row["prior_candidate_challenge_id"]
                        ):
                            raise MailboxError(
                                "semantic final rework requires a fresh admitted "
                                "Candidate Challenge binding"
                            )
                    new_revision = int(row["revision"]) + 1
                    connection.execute(
                        """
                        UPDATE work_items
                        SET product = ?, version = ?, package_hash = ?, reviewed_hash = NULL,
                            state = 'READY_FOR_MIDLANE', hunter_note = ?, review_summary = '',
                            hold_reason = '', revision = revision + 1,
                            closure_completed = 0, claimed_at = NULL,
                            package_manifest_json = ?, submitted_path = '',
                            submitted_hash = '', submitted_manifest_json = '[]',
                            submission_drift = 0, submission_note = '', submitted_at = NULL,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            product,
                            version,
                            package_hash,
                            note,
                            package_manifest_json,
                            timestamp,
                            item_id,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE questions SET status = 'SUPERSEDED', updated_at = ?
                        WHERE work_item_id = ? AND status != 'SUPERSEDED'
                        """,
                        (timestamp, item_id),
                    )
                    self._event(
                        connection,
                        item_id,
                        "hunter",
                        "REREGISTERED",
                        {
                            "package_hash": package_hash,
                            **(
                                {
                                    "preflight_result_sha256": preflight[
                                        "result_sha256"
                                    ],
                                    "preflight_goal_hash": preflight["goal_hash"],
                                }
                                if preflight is not None
                                else {}
                            ),
                        },
                    )
                    if prior_state in HUNTER_MUTABLE_STATES:
                        connection.execute(
                            """
                            UPDATE package_mutation_authorities
                            SET state = 'USED', used_at = ?
                            WHERE work_item_id = ? AND revision = ?
                              AND state = 'CONSUMED'
                            """,
                            (timestamp, item_id, int(row["revision"])),
                        )
                    if prior_state == "FINAL_REWORK":
                        request_row = connection.execute(
                            """
                            SELECT id FROM final_rework_requests
                            WHERE work_item_id = ? AND state = 'CLAIMED'
                            ORDER BY id DESC LIMIT 1
                            """,
                            (item_id,),
                        ).fetchone()
                        if request_row is not None:
                            request_id = int(request_row["id"])
                            connection.execute(
                                """
                                UPDATE final_rework_requests
                                SET state = 'ADDRESSED', addressed_hash = ?,
                                    addressed_revision = ?, addressed_at = ?
                                WHERE id = ?
                                """,
                                (package_hash, new_revision, timestamp, request_id),
                            )
                            self._event(
                                connection,
                                item_id,
                                "hunter",
                                "FINAL_REWORK_ADDRESSED",
                                {
                                    "request_id": request_id,
                                    "package_hash": package_hash,
                                    "revision": new_revision,
                                },
                            )
                else:
                    connection.execute(
                        """
                        UPDATE work_items
                        SET product = ?, version = ?, hunter_note = ?,
                            package_manifest_json = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            product,
                            version,
                            note,
                            package_manifest_json,
                            timestamp,
                            item_id,
                        ),
                    )
            if build_row is not None:
                connection.execute(
                    "DELETE FROM package_builds WHERE package_number = ?",
                    (package_number,),
                )
                self._event(
                    connection,
                    item_id,
                    "hunter",
                    "PACKAGE_BUILD_CONSUMED",
                    {
                        "package_number": package_number,
                        "summary": (
                            f"Package {package_number} build completed and "
                            "registered for Midlane"
                        ),
                    },
                )
            final_hash = self._hash_package(package)
            final_manifest_json = json.dumps(
                self._manifest_package(package), sort_keys=True
            )
            if (
                final_hash != package_hash
                or final_manifest_json != package_manifest_json
            ):
                raise MailboxError(
                    "package changed during registration before the database commit"
                )
            return self._get_item(connection, item_id)

    def candidate_inventory(self, product: str) -> dict[str, Any]:
        if not isinstance(product, str) or not product.strip():
            raise MailboxError("candidate inventory product is required")
        return load_candidate_inventory(self.workspace, product.strip(), self.db_path)

    def reconcile_duplicate_registration(
        self,
        keep_item_id: int,
        duplicate_item_id: int,
        operator: str,
    ) -> dict[str, Any]:
        if keep_item_id == duplicate_item_id:
            raise MailboxError("keep and duplicate item IDs must differ")
        if not isinstance(operator, str) or not operator.strip():
            raise MailboxError("operator is required")
        if len(operator.strip()) > 128:
            raise MailboxError("operator exceeds 128 characters")

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            keep = self._get_item(connection, keep_item_id)
            duplicate = self._get_item(connection, duplicate_item_id)
            keep_number = self._package_number(Path(keep["package_path"]).name)
            duplicate_number = self._package_number(
                Path(duplicate["package_path"]).name
            )
            if keep_number != duplicate_number:
                raise MailboxError("items do not share one package number")
            if keep["package_hash"] != duplicate["package_hash"]:
                raise MailboxError("duplicate reconciliation requires identical hashes")
            if keep["product"] != duplicate["product"] or keep["version"] != duplicate["version"]:
                raise MailboxError("duplicate reconciliation requires matching product/version")
            if duplicate["state"] not in {"READY_FOR_MIDLANE", "MIDLANE_REVIEWING"}:
                raise MailboxError(
                    "duplicate reconciliation requires an unreviewed Midlane state"
                )
            duplicate_path = Path(duplicate["package_path"]).resolve()
            if duplicate_path.exists():
                raise MailboxError("duplicate tracked path still exists")
            keep_package = self._validate_tracked_package(keep["package_path"])
            observed_hash = self._hash_package(keep_package)
            if observed_hash != keep["package_hash"]:
                raise MailboxError("kept package bytes do not match the frozen hash")
            for table in ("questions", "final_rework_requests"):
                count = connection.execute(
                    f"SELECT COUNT(*) AS count FROM {table} WHERE work_item_id = ?",
                    (duplicate_item_id,),
                ).fetchone()["count"]
                if int(count):
                    raise MailboxError(
                        f"duplicate item has dependent {table}; manual audit is required"
                    )
            event_rows = connection.execute(
                "SELECT id, event_type FROM events WHERE work_item_id = ? ORDER BY id",
                (duplicate_item_id,),
            ).fetchall()
            allowed_events = {"REGISTERED", "CLAIMED"}
            unexpected = [
                row["event_type"]
                for row in event_rows
                if row["event_type"] not in allowed_events
            ]
            if unexpected:
                raise MailboxError(
                    "duplicate item has substantive review history; manual audit is required"
                )
            connection.execute(
                "DELETE FROM events WHERE work_item_id = ?", (duplicate_item_id,)
            )
            connection.execute(
                "DELETE FROM work_items WHERE id = ?", (duplicate_item_id,)
            )
            self._event(
                connection,
                keep_item_id,
                "operator",
                "DUPLICATE_REGISTRATION_RECONCILED",
                {
                    "note": (
                        f"Removed phantom same-hash item {duplicate_item_id}; "
                        f"item {keep_item_id} remains authoritative"
                    ),
                    "operator": operator.strip(),
                    "package_hash": keep["package_hash"],
                    "removed_event_ids": [int(row["id"]) for row in event_rows],
                    "removed_event_types": [row["event_type"] for row in event_rows],
                    "removed_item_id": duplicate_item_id,
                    "removed_path": str(duplicate_path),
                },
            )
            return {
                "item": self._get_item(connection, keep_item_id),
                "removed_item_id": duplicate_item_id,
            }

    def _mark_stale(
        self,
        connection: sqlite3.Connection,
        item: dict[str, Any],
        observed_hash: str,
    ) -> None:
        connection.execute(
            "UPDATE work_items SET state = 'STALE', updated_at = ? WHERE id = ?",
            (utc_now(), item["id"]),
        )
        self._event(
            connection,
            int(item["id"]),
            "system",
            "PACKAGE_DRIFT",
            {"expected_hash": item["package_hash"], "observed_hash": observed_hash},
        )

    def claim_next_detailed(self) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            skipped: list[dict[str, Any]] = []
            rows = connection.execute(
                """
                SELECT * FROM work_items
                WHERE state IN ('HUNTER_REFINED', 'MIDLANE_REVIEWING', 'READY_FOR_MIDLANE')
                ORDER BY CASE state
                    WHEN 'HUNTER_REFINED' THEN 0
                    WHEN 'MIDLANE_REVIEWING' THEN 1
                    ELSE 2
                END, id
                """
            ).fetchall()
            for row in rows:
                item = self._item(row)
                package = self._validate_tracked_package(item["package_path"])
                observed_hash = self._hash_package(package)
                if observed_hash != item["package_hash"]:
                    self._mark_stale(connection, item, observed_hash)
                    skipped.append(
                        {
                            "expected_hash": item["package_hash"],
                            "item_id": int(item["id"]),
                            "observed_hash": observed_hash,
                            "package_path": item["package_path"],
                            "reason": "STALE_HASH_DRIFT",
                        }
                    )
                    continue
                if item["state"] in {"HUNTER_REFINED", "MIDLANE_REVIEWING"}:
                    timestamp = utc_now()
                    self._set_worker_status(
                        connection,
                        "midlane",
                        "WORKING",
                        f"Review mailbox item {item['id']}",
                        f"Package {Path(item['package_path']).name}; revision {item['revision']}; resumed {item['state']}",
                        timestamp,
                    )
                    return {
                        "attention": "RESUMED",
                        "display_time": local_display_time(),
                        "item": item,
                        "ready_items": [],
                        "skipped": skipped,
                    }
                timestamp = utc_now()
                connection.execute(
                    """
                    UPDATE work_items
                    SET state = 'MIDLANE_REVIEWING', reviewed_hash = package_hash,
                        claimed_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (timestamp, timestamp, item["id"]),
                )
                self._event(
                    connection,
                    int(item["id"]),
                    "midlane",
                    "CLAIMED",
                    {"package_hash": item["package_hash"]},
                )
                self._set_worker_status(
                    connection,
                    "midlane",
                    "WORKING",
                    f"Review mailbox item {item['id']}",
                    f"Package {Path(item['package_path']).name}; revision {item['revision']}; claimed",
                    timestamp,
                )
                return {
                    "attention": "CLAIMED",
                    "display_time": local_display_time(),
                    "item": self._get_item(connection, int(item["id"])),
                    "ready_items": [],
                    "skipped": skipped,
                }
            ready_rows = connection.execute(
                """
                SELECT id, package_path, product, version, state
                FROM work_items WHERE state = 'READY_FOR_MIDLANE' ORDER BY id
                """
            ).fetchall()
            ready_items = [dict(row) for row in ready_rows]
            if ready_items:
                attention = "VISIBLE_BUT_UNCLAIMED"
            elif skipped:
                attention = "STALE_SKIPPED"
            else:
                attention = "NO_CLAIMABLE_WORK"
            return {
                "attention": attention,
                "display_time": local_display_time(),
                "item": None,
                "ready_items": ready_items,
                "skipped": skipped,
            }

    def claim_next(self) -> dict[str, Any] | None:
        return self.claim_next_detailed()["item"]

    def get_item(self, item_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            return self._get_item(connection, item_id)

    def acknowledge_package_outcome(
        self,
        notification_id: int,
    ) -> dict[str, Any]:
        if (
            isinstance(notification_id, bool)
            or not isinstance(notification_id, int)
            or notification_id < 1
        ):
            raise MailboxError("notification_id must be a positive integer")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT id, work_item_id, outcome, package_path, product,
                       package_hash, revision, reason, state, created_at,
                       acknowledged_at
                FROM package_outcome_notifications
                WHERE id = ?
                """,
                (notification_id,),
            ).fetchone()
            if row is None:
                raise MailboxError("package outcome notification does not exist")
            if row["state"] == "OPEN":
                timestamp = utc_now()
                connection.execute(
                    """
                    UPDATE package_outcome_notifications
                    SET state = 'ACKNOWLEDGED', acknowledged_at = ?
                    WHERE id = ? AND state = 'OPEN'
                    """,
                    (timestamp, notification_id),
                )
                row = connection.execute(
                    """
                    SELECT id, work_item_id, outcome, package_path, product,
                           package_hash, revision, reason, state, created_at,
                           acknowledged_at
                    FROM package_outcome_notifications
                    WHERE id = ?
                    """,
                    (notification_id,),
                ).fetchone()
            assert row is not None
            return {
                "notification_id": int(row["id"]),
                "work_item_id": int(row["work_item_id"]),
                "outcome": str(row["outcome"]),
                "package_path": str(row["package_path"]),
                "product": str(row["product"]),
                "package_hash": str(row["package_hash"]),
                "revision": int(row["revision"]),
                "reason": str(row["reason"]),
                "state": str(row["state"]),
                "created_at": str(row["created_at"]),
                "acknowledged_at": (
                    str(row["acknowledged_at"])
                    if row["acknowledged_at"] is not None
                    else None
                ),
            }

    def assert_mutation_authority(self, item_id: int) -> dict[str, Any]:
        """Fail closed unless the mailbox has explicitly returned bytes to Hunter."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] not in HUNTER_MUTABLE_STATES:
                raise MailboxError(
                    "Hunter does not own package mutation while item state is "
                    f"{item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            staging_root = (self.workspace / "ZDI_STAGING").resolve()
            if package.parent != staging_root:
                raise MailboxError(
                    "Hunter mutation authority requires a direct ZDI_STAGING package"
                )
            observed_hash = self._hash_package(package)
            receipt = connection.execute(
                """
                SELECT * FROM package_mutation_authorities
                WHERE work_item_id = ? AND revision = ?
                """,
                (int(item["id"]), int(item["revision"])),
            ).fetchone()
            if receipt is None:
                if (
                    item["state"] != "STALE"
                    and observed_hash != item["package_hash"]
                ):
                    raise MailboxError(
                        "package changed before Hunter obtained mutation authority"
                    )
                timestamp = utc_now()
                connection.execute(
                    """
                    INSERT INTO package_mutation_authorities(
                        work_item_id, baseline_hash, revision, state, issued_at
                    ) VALUES (?, ?, ?, 'PENDING', ?)
                    """,
                    (
                        int(item["id"]),
                        observed_hash,
                        int(item["revision"]),
                        timestamp,
                    ),
                )
                receipt = connection.execute(
                    """
                    SELECT * FROM package_mutation_authorities
                    WHERE work_item_id = ? AND revision = ?
                    """,
                    (int(item["id"]), int(item["revision"])),
                ).fetchone()
            assert receipt is not None
            if (
                receipt["state"] == "PENDING"
                and receipt["baseline_hash"] != observed_hash
            ):
                raise MailboxError(
                    "package changed after Hunter mutation authority was issued"
                )
            if (
                receipt["state"] == "CONSUMED"
                and item["state"] != "STALE"
                and receipt["baseline_hash"] != item["package_hash"]
            ):
                raise MailboxError(
                    "package mutation authority baseline does not match the tracked revision"
                )
            if receipt["state"] == "PENDING":
                connection.execute(
                    """
                    UPDATE package_mutation_authorities
                    SET state = 'CONSUMED', consumed_at = ?
                    WHERE id = ? AND state = 'PENDING'
                    """,
                    (utc_now(), int(receipt["id"])),
                )
            elif receipt["state"] != "CONSUMED":
                raise MailboxError(
                    "package mutation authority is no longer available for this revision"
                )
            return {
                "id": int(item["id"]),
                "package_hash": item["package_hash"],
                "package_path": item["package_path"],
                "revision": int(item["revision"]),
                "state": item["state"],
            }

    @staticmethod
    def _string_list(value: Any, field: str) -> list[str]:
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(entry, str) or not entry.strip() for entry in value)
        ):
            raise MailboxError(f"{field} must be a non-empty list of strings")
        return [entry.strip() for entry in value]

    def _validate_questions(self, questions: Any) -> list[dict[str, Any]]:
        if not isinstance(questions, list) or not questions:
            raise MailboxError("QUESTIONS requires between 1 and 8 questions")
        if len(questions) > 8:
            raise MailboxError("Midlane may ask at most 8 questions")
        validated: list[dict[str, Any]] = []
        for index, question in enumerate(questions, start=1):
            if not isinstance(question, dict):
                raise MailboxError(f"question {index} must be an object")
            text = question.get("text")
            condition = question.get("closure_condition")
            if not isinstance(text, str) or not text.strip():
                raise MailboxError(f"question {index} requires text")
            if not isinstance(condition, str) or not condition.strip():
                raise MailboxError(f"question {index} requires closure_condition")
            if question_requires_private_content(text) or question_requires_private_content(
                condition
            ):
                raise MailboxError(
                    "Midlane questions cannot require private economics, payout, "
                    "or local workflow identifiers inside an external package"
                )
            validated.append(
                {
                    "text": text.strip(),
                    "evidence_refs": self._string_list(
                        question.get("evidence_refs"), "evidence_refs"
                    ),
                    "closure_condition": condition.strip(),
                }
            )
        return validated

    def record_review(
        self,
        item_id: int,
        verdict: str,
        summary: str,
        questions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        verdict = verdict.upper()
        if verdict not in {"PASS", "QUESTIONS", "HOLD"}:
            raise MailboxError("review verdict must be PASS, QUESTIONS, or HOLD")
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError("review summary is required")
        if verdict == "QUESTIONS":
            validated_questions = self._validate_questions(questions)
        else:
            if questions:
                raise MailboxError(f"{verdict} review cannot include questions")
            validated_questions = []

        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "MIDLANE_REVIEWING":
                raise MailboxError(
                    f"review requires MIDLANE_REVIEWING, found {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            observed_hash = self._hash_package(package)
            if observed_hash != item["reviewed_hash"]:
                self._mark_stale(connection, item, observed_hash)
                timestamp = utc_now()
                self._set_worker_status(
                    connection,
                    "midlane",
                    "IDLE",
                    f"Review mailbox item {item_id} stopped",
                    "Package hash drifted during review.",
                    timestamp,
                )
                drift_message = "package changed after Midlane claimed it; Hunter must register it again"
            else:
                timestamp = utc_now()
                if verdict == "QUESTIONS":
                    for question in validated_questions:
                        connection.execute(
                            """
                            INSERT INTO questions(
                                work_item_id, question_text, evidence_refs_json,
                                closure_condition, status, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?)
                            """,
                            (
                                item_id,
                                question["text"],
                                json.dumps(question["evidence_refs"]),
                                question["closure_condition"],
                                timestamp,
                                timestamp,
                            ),
                        )
                    state = "QUESTIONS_OPEN"
                    hold_reason = ""
                elif verdict == "PASS":
                    state = "MIDLANE_PASS"
                    hold_reason = ""
                else:
                    state = "HOLD"
                    hold_reason = summary.strip()
                connection.execute(
                    """
                    UPDATE work_items
                    SET state = ?, review_summary = ?, hold_reason = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (state, summary.strip(), hold_reason, timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "midlane",
                    f"REVIEW_{verdict}",
                    {"question_count": len(validated_questions), "summary": summary.strip()},
                )
                self._set_worker_status(
                    connection,
                    "midlane",
                    "IDLE",
                    f"Review mailbox item {item_id} complete",
                    f"Verdict {verdict}; resulting state {state}.",
                    timestamp,
                )
                result = self._get_item(connection, item_id)
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        if verdict == "PASS":
            return self.promote(item_id)
        return result

    @staticmethod
    def _question(row: sqlite3.Row) -> dict[str, Any]:
        question = dict(row)
        question["evidence_refs"] = json.loads(question.pop("evidence_refs_json"))
        question["answer_refs"] = json.loads(question.pop("answer_refs_json"))
        question["closure_refs"] = json.loads(question.pop("closure_refs_json"))
        return question

    def get_open_questions(self, item_id: int | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if item_id is None:
                rows = connection.execute(
                    "SELECT * FROM questions WHERE status = 'OPEN' ORDER BY id"
                ).fetchall()
            else:
                self._get_item(connection, item_id)
                rows = connection.execute(
                    """
                    SELECT * FROM questions
                    WHERE work_item_id = ? AND status = 'OPEN'
                    ORDER BY id
                    """,
                    (item_id,),
                ).fetchall()
            return [self._question(row) for row in rows]

    def answer_questions(
        self,
        item_id: int,
        answers: list[dict[str, Any]],
        note: str,
    ) -> dict[str, Any]:
        if not isinstance(answers, list):
            raise MailboxError("answers must be a list")
        parsed: dict[int, dict[str, Any]] = {}
        for answer in answers:
            if not isinstance(answer, dict) or not isinstance(answer.get("question_id"), int):
                raise MailboxError("every answer requires an integer question_id")
            question_id = int(answer["question_id"])
            if question_id in parsed:
                raise MailboxError(f"duplicate answer for question {question_id}")
            text = answer.get("answer")
            if not isinstance(text, str) or not text.strip():
                raise MailboxError(f"question {question_id} requires a non-empty answer")
            parsed[question_id] = {
                "answer": text.strip(),
                "evidence_refs": self._string_list(
                    answer.get("evidence_refs"), "evidence_refs"
                ),
            }

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "QUESTIONS_OPEN":
                raise MailboxError(
                    f"answer requires QUESTIONS_OPEN, found {item['state']}"
                )
            question_rows = connection.execute(
                """
                SELECT * FROM questions
                WHERE work_item_id = ? AND status = 'OPEN'
                ORDER BY id
                """,
                (item_id,),
            ).fetchall()
            expected_ids = {int(row["id"]) for row in question_rows}
            if set(parsed) != expected_ids:
                raise MailboxError("Hunter must answer every open question exactly once")

            package = self._validate_tracked_package(item["package_path"])
            self._validate_external_package(package)
            observed_hash = self._hash_package(package)
            package_manifest_json = json.dumps(
                self._manifest_package(package), sort_keys=True
            )
            timestamp = utc_now()
            for question_id, answer in parsed.items():
                connection.execute(
                    """
                    UPDATE questions
                    SET status = 'ANSWERED', answer_text = ?, answer_refs_json = ?,
                        updated_at = ?
                    WHERE id = ? AND work_item_id = ?
                    """,
                    (
                        answer["answer"],
                        json.dumps(answer["evidence_refs"]),
                        timestamp,
                        question_id,
                        item_id,
                    ),
                )
            revision_increment = 1 if observed_hash != item["package_hash"] else 0
            connection.execute(
                """
                UPDATE work_items
                SET state = 'HUNTER_REFINED', package_hash = ?, reviewed_hash = ?,
                    hunter_note = ?, revision = revision + ?,
                    package_manifest_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    observed_hash,
                    observed_hash,
                    note.strip(),
                    revision_increment,
                    package_manifest_json,
                    timestamp,
                    item_id,
                ),
            )
            self._event(
                connection,
                item_id,
                "hunter",
                "QUESTIONS_ANSWERED",
                {"answer_count": len(parsed), "package_hash": observed_hash},
            )
            return self._get_item(connection, item_id)

    def close_review(
        self,
        item_id: int,
        verdict: str,
        closures: list[dict[str, Any]],
        summary: str,
    ) -> dict[str, Any]:
        verdict = verdict.upper()
        if verdict not in {"PASS", "HOLD"}:
            raise MailboxError("closure verdict must be PASS or HOLD")
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError("closure summary is required")
        if not isinstance(closures, list):
            raise MailboxError("closures must be a list")
        parsed: dict[int, dict[str, Any]] = {}
        for closure in closures:
            if not isinstance(closure, dict) or not isinstance(
                closure.get("question_id"), int
            ):
                raise MailboxError("every closure requires an integer question_id")
            question_id = int(closure["question_id"])
            if question_id in parsed:
                raise MailboxError(f"duplicate closure for question {question_id}")
            status = str(closure.get("status", "")).upper()
            if status not in {"CLOSED", "UNRESOLVED"}:
                raise MailboxError("closure status must be CLOSED or UNRESOLVED")
            note = closure.get("note")
            if not isinstance(note, str) or not note.strip():
                raise MailboxError(f"question {question_id} requires a closure note")
            parsed[question_id] = {
                "status": status,
                "note": note.strip(),
                "evidence_refs": self._string_list(
                    closure.get("evidence_refs"), "evidence_refs"
                ),
            }

        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "HUNTER_REFINED":
                raise MailboxError(
                    f"closure requires HUNTER_REFINED, found {item['state']}"
                )
            question_rows = connection.execute(
                """
                SELECT * FROM questions
                WHERE work_item_id = ? AND status = 'ANSWERED'
                ORDER BY id
                """,
                (item_id,),
            ).fetchall()
            expected_ids = {int(row["id"]) for row in question_rows}
            if set(parsed) != expected_ids:
                raise MailboxError("closure must address every answered question exactly once")
            if verdict == "PASS" and any(
                closure["status"] != "CLOSED" for closure in parsed.values()
            ):
                raise MailboxError("PASS requires every question to be CLOSED")
            if verdict == "HOLD" and parsed and all(
                closure["status"] == "CLOSED" for closure in parsed.values()
            ):
                raise MailboxError("HOLD requires at least one UNRESOLVED question")

            package = self._validate_tracked_package(item["package_path"])
            self._validate_external_package(package)
            observed_hash = self._hash_package(package)
            if observed_hash != item["reviewed_hash"]:
                self._mark_stale(connection, item, observed_hash)
                timestamp = utc_now()
                self._set_worker_status(
                    connection,
                    "midlane",
                    "IDLE",
                    f"Review mailbox item {item_id} stopped",
                    "Package hash drifted during closure review.",
                    timestamp,
                )
                drift_message = "package changed after Hunter refinement; register it again"
            else:
                timestamp = utc_now()
                for question_id, closure in parsed.items():
                    connection.execute(
                        """
                        UPDATE questions
                        SET status = ?, closure_note = ?, closure_refs_json = ?,
                            updated_at = ?
                        WHERE id = ? AND work_item_id = ?
                        """,
                        (
                            closure["status"],
                            closure["note"],
                            json.dumps(closure["evidence_refs"]),
                            timestamp,
                            question_id,
                            item_id,
                        ),
                    )
                state = "MIDLANE_PASS" if verdict == "PASS" else "HOLD"
                hold_reason = "" if verdict == "PASS" else summary.strip()
                connection.execute(
                    """
                    UPDATE work_items
                    SET state = ?, review_summary = ?, hold_reason = ?,
                        closure_completed = 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (state, summary.strip(), hold_reason, timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "midlane",
                    f"CLOSURE_{verdict}",
                    {"closure_count": len(parsed), "summary": summary.strip()},
                )
                self._set_worker_status(
                    connection,
                    "midlane",
                    "IDLE",
                    f"Review mailbox item {item_id} complete",
                    f"Closure verdict {verdict}; resulting state {state}.",
                    timestamp,
                )
                result = self._get_item(connection, item_id)
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        if verdict == "PASS":
            return self.promote(item_id)
        return result

    def promote(self, item_id: int) -> dict[str, Any]:
        _phase("PROMOTION_START", item_id=item_id)
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "MIDLANE_PASS":
                raise MailboxError(
                    f"promotion requires MIDLANE_PASS, found {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            self._validate_external_package(package)
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed after Midlane pass; register it again"
            else:
                zdi_root = (self.workspace / "ZDI").resolve()
                staging_root = (self.workspace / "ZDI_STAGING").resolve()
                hold_root = (staging_root / "_HOLD").resolve()
                if package.parent == zdi_root:
                    destination = package
                    event_type = "LEGACY_MARKED_FOR_FINAL"
                elif package.parent in {staging_root, hold_root}:
                    zdi_root.mkdir(parents=True, exist_ok=True)
                    destination = zdi_root / package.name
                    if destination.exists():
                        raise MailboxError(
                            f"cannot promote because destination already exists: {destination}"
                        )
                    try:
                        self._journaled_move(
                            connection,
                            item_id,
                            "PROMOTE",
                            package,
                            destination,
                            observed_hash,
                        )
                    except OSError as error:
                        raise MailboxError(f"cannot promote package: {error}") from error
                    event_type = (
                        "PROMOTED_FROM_HOLD_TO_FINAL"
                        if package.parent == hold_root
                        else "PROMOTED_TO_FINAL"
                    )
                else:
                    raise MailboxError("package is not in the staging or final-review root")

                timestamp = utc_now()
                try:
                    connection.execute(
                        """
                        UPDATE work_items
                        SET package_path = ?, state = 'AWAITING_FINAL_REVIEW', updated_at = ?
                        WHERE id = ?
                        """,
                        (str(destination), timestamp, item_id),
                    )
                    self._event(
                        connection,
                        item_id,
                        "hunter",
                        event_type,
                        {
                            "from": item["package_path"],
                            "to": str(destination),
                            "package_hash": observed_hash,
                        },
                    )
                    result = self._get_item(connection, item_id)
                except Exception:
                    raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        _phase(
            "PROMOTION_COMPLETE",
            item_id=item_id,
            package_hash=result["package_hash"],
            state=result["state"],
        )
        return result

    def mark_ready(
        self,
        item_id: int,
        final_determination: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] not in {"AWAITING_FINAL_REVIEW", "READY"}:
                raise MailboxError(
                    "mark-ready requires AWAITING_FINAL_REVIEW or READY, "
                    f"found {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            zdi_root = (self.workspace / "ZDI").resolve()
            if package.parent != zdi_root:
                raise MailboxError("READY package is not in the direct ZDI root")
            self._validate_external_package(package)
            observed_hash = self._hash_package(package)
            determination_json = ""
            if final_determination is not None:
                determination_json = json.dumps(
                    _validate_final_determination(final_determination, item),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                existing = str(item.get("final_determination_json") or "{}")
                if existing not in {"", "{}"}:
                    try:
                        existing = json.dumps(
                            json.loads(existing),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    except json.JSONDecodeError as error:
                        raise MailboxError(
                            "stored final determination is invalid"
                        ) from error
                    if existing != determination_json:
                        raise MailboxError("final determination changed after recording")
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed before READY; return it for review"
            elif item["state"] == "READY":
                if not package.name.startswith(READY_PREFIX):
                    raise MailboxError("READY state requires a READY-prefixed package")
                timestamp = utc_now()
                if determination_json and str(
                    item.get("final_determination_json") or "{}"
                ) in {"", "{}"}:
                    connection.execute(
                        "UPDATE work_items SET final_determination_json = ?, "
                        "updated_at = ? WHERE id = ?",
                        (determination_json, timestamp, item_id),
                    )
                    self._event(
                        connection,
                        item_id,
                        "final-reviewer",
                        "FINAL_DETERMINATION_RECORDED",
                        {
                            "schema": FINAL_DETERMINATION_SCHEMA,
                            "reviewed_hash": observed_hash,
                            "reviewed_revision": int(item["revision"]),
                        },
                    )
                self._verify_addressed_rework(connection, item, timestamp)
                result = self._get_item(connection, item_id)
            else:
                if package.name.startswith(READY_PREFIX):
                    raise MailboxError(
                        "AWAITING_FINAL_REVIEW requires an unprefixed package"
                    )
                destination = zdi_root / f"{READY_PREFIX}{package.name}"
                if destination.exists():
                    raise MailboxError(
                        f"cannot mark READY because destination already exists: {destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "MARK_READY",
                        package,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(f"cannot mark package READY: {error}") from error

                timestamp = utc_now()
                try:
                    connection.execute(
                        "UPDATE work_items SET package_path = ?, state = 'READY', "
                        "final_determination_json = CASE WHEN ? = '' "
                        "THEN final_determination_json ELSE ? END, "
                        "updated_at = ? WHERE id = ?",
                        (
                            str(destination),
                            determination_json,
                            determination_json,
                            timestamp,
                            item_id,
                        ),
                    )
                    self._event(
                        connection,
                        item_id,
                        "operator",
                        "MARKED_READY_FOR_SUBMISSION",
                        {
                            "from": item["package_path"],
                            "to": str(destination),
                            "package_hash": observed_hash,
                        },
                    )
                    ready_item = self._get_item(connection, item_id)
                    self._verify_addressed_rework(connection, ready_item, timestamp)
                    result = self._get_item(connection, item_id)
                except Exception:
                    if destination.exists() and not package.exists():
                        destination.rename(package)
                    raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def restage(self, item_id: int) -> dict[str, Any]:
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] in {"MIDLANE_PASS", "AWAITING_FINAL_REVIEW", "READY"}:
                raise MailboxError(
                    f"cannot restage an item in {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            staging_root = (self.workspace / "ZDI_STAGING").resolve()
            zdi_root = (self.workspace / "ZDI").resolve()
            if package.parent == staging_root:
                return item
            if package.parent != zdi_root:
                raise MailboxError("only a tracked direct ZDI package can be restaged")
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed before restaging; register the current bytes"
            else:
                staging_root.mkdir(parents=True, exist_ok=True)
                destination = staging_root / package.name
                if destination.exists():
                    raise MailboxError(
                        f"cannot restage because destination already exists: {destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "RESTAGE",
                        package,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(f"cannot restage package: {error}") from error
                timestamp = utc_now()
                try:
                    connection.execute(
                        "UPDATE work_items SET package_path = ?, updated_at = ? WHERE id = ?",
                        (str(destination), timestamp, item_id),
                    )
                    self._event(
                        connection,
                        item_id,
                        "hunter",
                        "RESTAGED_FROM_FINAL_ROOT",
                        {
                            "from": item["package_path"],
                            "to": str(destination),
                            "package_hash": observed_hash,
                        },
                    )
                    result = self._get_item(connection, item_id)
                except Exception:
                    if destination.exists() and not package.exists():
                        destination.rename(package)
                    raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def _normalize_final_rework(
        self,
        summary: str,
        issues: list[Any],
        evidence_refs: list[str],
        reviewed_hash: str,
        reviewed_revision: int,
        review_scope: str,
    ) -> tuple[str, list[dict[str, str]], list[str], str, int, str, str]:
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError("final-review rework summary is required")
        if not isinstance(issues, list) or not issues:
            raise MailboxError("issues must be a non-empty list")
        validated_issues: list[dict[str, str]] = []
        for index, issue in enumerate(issues, start=1):
            if isinstance(issue, str) and issue.strip():
                validated_issues.append(
                    {"id": f"ISSUE_{index}", "action": issue.strip()}
                )
                continue
            if isinstance(issue, dict):
                issue_id = issue.get("id")
                action = issue.get("action")
                if (
                    isinstance(issue_id, str)
                    and issue_id.strip()
                    and isinstance(action, str)
                    and action.strip()
                ):
                    validated_issues.append(
                        {"id": issue_id.strip(), "action": action.strip()}
                    )
                    continue
            raise MailboxError(
                f"issue {index} must be a string or an object with non-empty id and action"
            )
        validated_refs = self._string_list(evidence_refs, "evidence_refs")

        if not isinstance(reviewed_hash, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", reviewed_hash
        ):
            raise MailboxError("reviewed_hash must be one SHA-256 hex digest")
        if (
            isinstance(reviewed_revision, bool)
            or not isinstance(reviewed_revision, int)
            or reviewed_revision < 1
        ):
            raise MailboxError("reviewed_revision must be a positive integer")
        normalized_summary = summary.strip()
        normalized_hash = reviewed_hash.lower()
        if not isinstance(review_scope, str):
            raise MailboxError("review_scope must be MECHANICAL, EVIDENCE_ONLY, or SEMANTIC")
        normalized_scope = review_scope.strip().upper()
        if normalized_scope not in FINAL_REWORK_SCOPES:
            raise MailboxError("review_scope must be MECHANICAL, EVIDENCE_ONLY, or SEMANTIC")
        mechanical_ids = [
            issue["id"].startswith("MECHANICAL_") for issue in validated_issues
        ]
        if normalized_scope == "MECHANICAL" and not all(mechanical_ids):
            raise MailboxError(
                "MECHANICAL review_scope requires only MECHANICAL_ issue IDs"
            )
        if normalized_scope != "MECHANICAL" and any(mechanical_ids):
            raise MailboxError(
                "MECHANICAL_ issue IDs require review_scope MECHANICAL"
            )
        canonical = json.dumps(
            {
                "summary": normalized_summary,
                "issues": validated_issues,
                "evidence_refs": validated_refs,
                "review_scope": normalized_scope,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return (
            normalized_summary,
            validated_issues,
            validated_refs,
            normalized_hash,
            reviewed_revision,
            normalized_scope,
            fingerprint,
        )

    def _queue_final_rework(
        self,
        item_id: int,
        summary: str,
        issues: list[Any],
        evidence_refs: list[str],
        reviewed_hash: str,
        reviewed_revision: int,
        review_scope: str,
        *,
        queued_by: str,
        allow_ready: bool,
    ) -> dict[str, Any]:
        (
            normalized_summary,
            validated_issues,
            validated_refs,
            normalized_hash,
            normalized_revision,
            normalized_scope,
            fingerprint,
        ) = self._normalize_final_rework(
            summary,
            issues,
            evidence_refs,
            reviewed_hash,
            reviewed_revision,
            review_scope,
        )

        drift_message: str | None = None
        result: dict[str, Any] | None = None
        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._get_item(connection, item_id)
                existing = connection.execute(
                """
                SELECT * FROM final_rework_requests
                WHERE work_item_id = ? AND reviewed_hash = ?
                  AND request_fingerprint = ?
                """,
                (item_id, normalized_hash, fingerprint),
                ).fetchone()
                if existing is not None:
                    request = self._rework_request(existing)
                    if (
                        request["state"] == "OPEN"
                        and item["state"] == "FINAL_REWORK_QUEUED"
                    ):
                        return {"item": item, "request": request}
                    raise MailboxError(
                        f"final-rework request {request['id']} was already "
                        f"{request['state'].lower()} and cannot be replayed"
                    )
                if not allow_ready and item["state"] == "READY":
                    raise MailboxError(
                        "READY package is locked; only the operator-only reopen-ready "
                        "command may create a new rework request"
                    )
                required_state = "READY" if allow_ready else "AWAITING_FINAL_REVIEW"
                if item["state"] != required_state:
                    raise MailboxError(
                        f"queue-final-rework requires {required_state}, "
                        f"found {item['state']}"
                    )
                if (
                    item["package_hash"] != normalized_hash
                    or int(item["revision"]) != normalized_revision
                ):
                    raise MailboxError(
                        "Final Reviewer payload does not match the current package hash and revision"
                    )
                package = self._validate_tracked_package(item["package_path"])
                zdi_root = (self.workspace / "ZDI").resolve()
                if package.parent != zdi_root:
                    raise MailboxError("final-review package is not in the direct ZDI root")
                ready_prefixed = package.name.startswith(READY_PREFIX)
                if ready_prefixed and not allow_ready:
                    raise MailboxError(
                        "READY package is locked; only the operator-only reopen-ready command "
                        "may create a new rework request"
                    )
                if allow_ready and not ready_prefixed:
                    raise MailboxError("reopen-ready requires a READY-prefixed package")
                self._validate_external_package(package)
                observed_hash = self._hash_package(package)
                if observed_hash != normalized_hash:
                    self._mark_stale(connection, item, observed_hash)
                    drift_message = "package changed while Final Review queued rework"
                else:
                    if normalized_scope == "MECHANICAL":
                        try:
                            validate_queued_mechanical_repair(
                                self.workspace,
                                package,
                                item,
                                validated_issues,
                            )
                        except BoundedRepairContractError as error:
                            raise MailboxError(str(error)) from error
                    staging_root = (self.workspace / "ZDI_STAGING").resolve()
                    staging_root.mkdir(parents=True, exist_ok=True)
                    destination = staging_root / self._plain_package_name(package.name)
                    if destination.exists():
                        raise MailboxError(
                            "cannot queue final rework because staging destination exists: "
                            f"{destination}"
                        )
                    try:
                        self._journaled_move(
                            connection,
                            item_id,
                            "QUEUE_FINAL_REWORK",
                            package,
                            destination,
                            observed_hash,
                        )
                    except OSError as error:
                        raise MailboxError(
                            f"cannot stage queued final rework package: {error}"
                        ) from error
                    moved_from = package
                    moved_to = destination
                    timestamp = utc_now()
                    cursor = connection.execute(
                    """
                    INSERT INTO final_rework_requests(
                        work_item_id, reviewed_hash, reviewed_revision,
                        request_fingerprint, summary, issues_json,
                        evidence_refs_json, review_scope,
                        prior_candidate_challenge_id, state, queued_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)
                    """,
                    (
                        item_id,
                        normalized_hash,
                        normalized_revision,
                        fingerprint,
                        normalized_summary,
                        json.dumps(validated_issues, sort_keys=True),
                        json.dumps(validated_refs),
                        normalized_scope,
                        item.get("candidate_challenge_id"),
                        queued_by,
                        timestamp,
                    ),
                    )
                    request_id = int(cursor.lastrowid)
                    connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, state = 'FINAL_REWORK_QUEUED',
                        review_summary = ?, updated_at = ?
                    WHERE id = ?
                    """,
                        (
                            str(destination),
                            f"FINAL_REWORK_QUEUED: {normalized_summary}",
                            timestamp,
                            item_id,
                        ),
                    )
                    self._event(
                        connection,
                        item_id,
                        queued_by,
                        "FINAL_REWORK_QUEUED",
                        {
                            "request_id": request_id,
                            "reviewed_hash": normalized_hash,
                            "reviewed_revision": normalized_revision,
                            "issue_ids": [issue["id"] for issue in validated_issues],
                            "review_scope": normalized_scope,
                            "from": item["package_path"],
                            "to": str(destination),
                        },
                    )
                    request_row = connection.execute(
                        "SELECT * FROM final_rework_requests WHERE id = ?",
                        (request_id,),
                    ).fetchone()
                    assert request_row is not None
                    result = {
                        "item": self._get_item(connection, item_id),
                        "request": self._rework_request(request_row),
                    }
                    connection.commit()
                    moved_from = None
                    moved_to = None
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "queue-final-rework failed and package rollback failed: "
                        f"{rollback_error}"
                    ) from error
            raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def queue_final_rework(
        self,
        item_id: int,
        summary: str,
        issues: list[Any],
        evidence_refs: list[str],
        reviewed_hash: str,
        reviewed_revision: int,
        review_scope: str = "SEMANTIC",
    ) -> dict[str, Any]:
        return self._queue_final_rework(
            item_id,
            summary,
            issues,
            evidence_refs,
            reviewed_hash,
            reviewed_revision,
            review_scope,
            queued_by="final-reviewer",
            allow_ready=False,
        )

    def reopen_ready(
        self,
        item_id: int,
        summary: str,
        issues: list[Any],
        evidence_refs: list[str],
        reviewed_hash: str,
        reviewed_revision: int,
        review_scope: str = "SEMANTIC",
    ) -> dict[str, Any]:
        return self._queue_final_rework(
            item_id,
            summary,
            issues,
            evidence_refs,
            reviewed_hash,
            reviewed_revision,
            review_scope,
            queued_by="operator",
            allow_ready=True,
        )

    def claim_final_rework(self) -> dict[str, Any] | None:
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT * FROM final_rework_requests "
                    "WHERE state = 'OPEN' ORDER BY id"
                ).fetchall()
                row = None
                reroute_invalid_mechanical = False
                for candidate in rows:
                    candidate_request = self._rework_request(candidate)
                    executable_mechanical = False
                    if candidate_request.get("review_scope") == "MECHANICAL":
                        candidate_item = self._get_item(
                            connection, int(candidate_request["work_item_id"])
                        )
                        try:
                            candidate_package = self._validate_tracked_package(
                                candidate_item["package_path"]
                            )
                            validate_queued_mechanical_repair(
                                self.workspace,
                                candidate_package,
                                candidate_item,
                                candidate_request.get("issues", []),
                            )
                        except (MailboxError, BoundedRepairContractError, OSError):
                            executable_mechanical = False
                        else:
                            executable_mechanical = True
                    if not executable_mechanical:
                        row = candidate
                        reroute_invalid_mechanical = (
                            candidate_request.get("review_scope") == "MECHANICAL"
                        )
                        break
                if row is None:
                    return None
                request = self._rework_request(row)
                item_id = int(request["work_item_id"])
                item = self._get_item(connection, item_id)
                if item["state"] != "FINAL_REWORK_QUEUED":
                    raise MailboxError(
                        f"rework request {request['id']} is OPEN but item state is {item['state']}"
                    )
                if (
                    item["package_hash"] != request["reviewed_hash"]
                    or int(item["revision"]) != int(request["reviewed_revision"])
                ):
                    raise MailboxError(
                        f"rework request {request['id']} no longer matches its reviewed hash/revision"
                    )
                package = self._validate_tracked_package(item["package_path"])
                zdi_root = (self.workspace / "ZDI").resolve()
                staging_root = (self.workspace / "ZDI_STAGING").resolve()
                if package.parent not in {zdi_root, staging_root}:
                    raise MailboxError(
                        "queued final-review package is not in direct ZDI or ZDI_STAGING"
                    )
                observed_hash = self._hash_package(package)
                if observed_hash != request["reviewed_hash"]:
                    self._mark_stale(connection, item, observed_hash)
                    connection.execute(
                    "UPDATE final_rework_requests SET state = 'CANCELLED', closed_at = ? WHERE id = ?",
                    (utc_now(), request["id"]),
                    )
                    drift_message = "package changed after Final Review queued rework"
                else:
                    if reroute_invalid_mechanical:
                        connection.execute(
                            "UPDATE final_rework_requests "
                            "SET review_scope = 'SEMANTIC' WHERE id = ?",
                            (request["id"],),
                        )
                        request["review_scope"] = "SEMANTIC"
                    destination = package
                    if package.parent == zdi_root:
                        staging_root.mkdir(parents=True, exist_ok=True)
                        destination = staging_root / self._plain_package_name(package.name)
                        if destination.exists():
                            raise MailboxError(
                                "cannot claim final rework because staging destination exists: "
                                f"{destination}"
                            )
                        try:
                            self._journaled_move(
                                connection,
                                item_id,
                                "CLAIM_FINAL_REWORK",
                                package,
                                destination,
                                observed_hash,
                            )
                        except OSError as error:
                            raise MailboxError(
                                f"cannot claim final rework package: {error}"
                            ) from error
                        moved_from = package
                        moved_to = destination
                    timestamp = utc_now()
                    connection.execute(
                        """
                        UPDATE work_items
                        SET package_path = ?, state = 'FINAL_REWORK', reviewed_hash = NULL,
                            review_summary = ?, hold_reason = '', closure_completed = 0,
                            claimed_at = NULL, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            str(destination),
                            f"FINAL_REWORK: {request['summary']}",
                            timestamp,
                            item_id,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE final_rework_requests
                        SET state = 'CLAIMED', claimed_at = ? WHERE id = ?
                        """,
                        (timestamp, request["id"]),
                    )
                    connection.execute(
                        """
                        INSERT INTO package_mutation_authorities(
                            work_item_id, baseline_hash, revision, state, issued_at
                        ) VALUES (?, ?, ?, 'CONSUMED', ?)
                        ON CONFLICT(work_item_id, revision) DO UPDATE SET
                            baseline_hash = excluded.baseline_hash,
                            state = 'CONSUMED',
                            issued_at = excluded.issued_at,
                            consumed_at = excluded.issued_at,
                            used_at = NULL
                        """,
                        (
                            item_id,
                            observed_hash,
                            int(item["revision"]),
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE package_mutation_authorities
                        SET consumed_at = ?
                        WHERE work_item_id = ? AND revision = ?
                          AND state = 'CONSUMED'
                        """,
                        (timestamp, item_id, int(item["revision"])),
                    )
                    self._event(
                        connection,
                        item_id,
                        "hunter",
                        "FINAL_REWORK_CLAIMED",
                        {
                            "request_id": request["id"],
                            "review_scope": request["review_scope"],
                            "routing_recovery": reroute_invalid_mechanical,
                            "from": item["package_path"],
                            "to": str(destination),
                            "package_hash": observed_hash,
                        },
                    )
                    claimed_row = connection.execute(
                        "SELECT * FROM final_rework_requests WHERE id = ?",
                        (request["id"],),
                    ).fetchone()
                    assert claimed_row is not None
                    result = {
                        "item": self._get_item(connection, item_id),
                        "request": self._rework_request(claimed_row),
                    }
                    connection.commit()
                    moved_from = None
                    moved_to = None
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "claim-final-rework failed and package rollback failed: "
                        f"{rollback_error}"
                    ) from error
            raise
        if drift_message:
            raise MailboxError(drift_message)
        return result

    def rework_details(self, item_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            self._get_item(connection, item_id)
            row = connection.execute(
                """
                SELECT * FROM final_rework_requests
                WHERE work_item_id = ? ORDER BY id DESC LIMIT 1
                """,
                (item_id,),
            ).fetchone()
            if row is None:
                raise MailboxError(f"item {item_id} has no final-rework request")
            return self._rework_request(row)

    def return_for_rework(
        self,
        item_id: int,
        summary: str,
        issues: list[Any],
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        del item_id, summary, issues, evidence_refs
        raise MailboxError(
            "direct chat-relay rework is disabled; Final Reviewer must use "
            "queue-final-rework and Hunter must use claim-final-rework"
        )

    def restore_stale_ready(self, item_id: int) -> dict[str, Any]:
        drift_message: str | None = None
        result: dict[str, Any] | None = None

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "FINAL_REWORK":
                raise MailboxError(
                    "restore-stale-ready requires FINAL_REWORK, "
                    f"found {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            zdi_root = (self.workspace / "ZDI").resolve()
            staging_root = (self.workspace / "ZDI_STAGING").resolve()
            if package.parent != staging_root:
                raise MailboxError("stale READY recovery package is not in ZDI_STAGING")
            latest_event = connection.execute(
                """
                SELECT id, event_type, detail_json FROM events
                WHERE work_item_id = ? ORDER BY id DESC LIMIT 1
                """,
                (item_id,),
            ).fetchone()
            if latest_event is None or latest_event["event_type"] != "RETURNED_FOR_FINAL_REWORK":
                raise MailboxError(
                    "stale READY recovery requires the legacy return to be the latest item event"
                )
            return_detail = json.loads(latest_event["detail_json"])
            ready_event = connection.execute(
                """
                SELECT id, detail_json FROM events
                WHERE work_item_id = ? AND event_type = 'MARKED_READY_FOR_SUBMISSION'
                  AND id < ?
                ORDER BY id DESC LIMIT 1
                """,
                (item_id, int(latest_event["id"])),
            ).fetchone()
            if ready_event is None:
                raise MailboxError("stale READY recovery found no preceding READY event")
            ready_detail = json.loads(ready_event["detail_json"])
            if (
                return_detail.get("expected_hash") != item["package_hash"]
                or return_detail.get("observed_hash") != item["package_hash"]
                or ready_detail.get("package_hash") != item["package_hash"]
            ):
                raise MailboxError("stale READY recovery event hashes do not match")
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed after READY; stale recovery refused"
            else:
                destination = zdi_root / f"{READY_PREFIX}{self._plain_package_name(package.name)}"
                if destination.exists():
                    raise MailboxError(
                        f"cannot restore READY because destination exists: {destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "RESTORE_STALE_READY",
                        package,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(f"cannot restore stale READY package: {error}") from error
                timestamp = utc_now()
                try:
                    connection.execute(
                        """
                        UPDATE work_items
                        SET package_path = ?, state = 'READY',
                            review_summary = 'READY_RESTORED_AFTER_STALE_REWORK',
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (str(destination), timestamp, item_id),
                    )
                    connection.execute(
                        """
                        UPDATE final_rework_requests
                        SET state = 'CANCELLED', closed_at = ?
                        WHERE work_item_id = ? AND state IN ('OPEN', 'CLAIMED')
                        """,
                        (timestamp, item_id),
                    )
                    self._event(
                        connection,
                        item_id,
                        "operator",
                        "RESTORED_READY_AFTER_STALE_REWORK",
                        {
                            "source_return_event": int(latest_event["id"]),
                            "from": item["package_path"],
                            "to": str(destination),
                            "package_hash": observed_hash,
                        },
                    )
                    result = self._get_item(connection, item_id)
                except Exception:
                    if destination.exists() and not package.exists():
                        destination.rename(package)
                    raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def hold_final_rework(
        self,
        item_id: int,
        summary: str,
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError("final HOLD summary is required")
        validated_refs = self._string_list(evidence_refs, "evidence_refs")

        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "FINAL_REWORK":
                raise MailboxError(
                    "hold-final-rework requires FINAL_REWORK, "
                    f"found {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            staging_root = (self.workspace / "ZDI_STAGING").resolve()
            if package.parent != staging_root:
                raise MailboxError("final-rework package is not in ZDI_STAGING")
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = (
                    "package changed before final HOLD; register changed bytes "
                    "for review instead"
                )
            else:
                timestamp = utc_now()
                reason = summary.strip()
                connection.execute(
                    """
                    UPDATE work_items
                    SET state = 'HOLD', reviewed_hash = ?, review_summary = ?,
                        hold_reason = ?, closure_completed = 1,
                        claimed_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        observed_hash,
                        f"FINAL_HOLD: {reason}",
                        reason,
                        timestamp,
                        item_id,
                    ),
                )
                request_row = connection.execute(
                    """
                    SELECT id FROM final_rework_requests
                    WHERE work_item_id = ? AND state = 'CLAIMED'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (item_id,),
                ).fetchone()
                request_id = int(request_row["id"]) if request_row is not None else None
                if request_id is not None:
                    connection.execute(
                        """
                        UPDATE final_rework_requests
                        SET state = 'CLOSED_HOLD', closed_at = ? WHERE id = ?
                        """,
                        (timestamp, request_id),
                    )
                close_item_addressed(
                    connection,
                    work_item_id=item_id,
                    timestamp=timestamp,
                )
                self._event(
                    connection,
                    item_id,
                    "hunter",
                    "FINAL_REWORK_HELD",
                    {
                        "summary": reason,
                        "evidence_refs": validated_refs,
                        "package_hash": observed_hash,
                        "request_id": request_id,
                    },
                )
                result = self._get_item(connection, item_id)
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def mark_final_hold(
        self,
        item_id: int,
        summary: str,
        evidence_refs: list[str],
        reviewed_hash: str,
        reviewed_revision: int,
    ) -> dict[str, Any]:
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError("final HOLD summary is required")
        validated_refs = self._string_list(evidence_refs, "evidence_refs")
        if not isinstance(reviewed_hash, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", reviewed_hash
        ):
            raise MailboxError("reviewed_hash must be one SHA-256 hex digest")
        if (
            isinstance(reviewed_revision, bool)
            or not isinstance(reviewed_revision, int)
            or reviewed_revision < 1
        ):
            raise MailboxError("reviewed_revision must be a positive integer")

        normalized_hash = reviewed_hash.lower()
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "AWAITING_FINAL_REVIEW":
                raise MailboxError(
                    "mark-final-hold requires AWAITING_FINAL_REVIEW, "
                    f"found {item['state']}"
                )
            if (
                item["package_hash"] != normalized_hash
                or int(item["revision"]) != reviewed_revision
            ):
                raise MailboxError(
                    "Final Reviewer HOLD does not match the reviewed hash and revision"
                )
            package = self._validate_tracked_package(item["package_path"])
            zdi_root = (self.workspace / "ZDI").resolve()
            if package.parent != zdi_root:
                raise MailboxError("final-review package is not in the direct ZDI root")
            if package.name.startswith(READY_PREFIX):
                raise MailboxError(
                    "READY package is locked; only the operator may reopen it"
                )
            observed_hash = self._hash_package(package)
            if observed_hash != normalized_hash:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed before final HOLD"
            else:
                timestamp = utc_now()
                reason = summary.strip()
                connection.execute(
                    """
                    UPDATE work_items
                    SET state = 'HOLD', reviewed_hash = ?, review_summary = ?,
                        hold_reason = ?, closure_completed = 1,
                        claimed_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        observed_hash,
                        f"FINAL_REVIEW_HOLD: {reason}",
                        reason,
                        timestamp,
                        item_id,
                    ),
                )
                close_item_addressed(
                    connection,
                    work_item_id=item_id,
                    timestamp=timestamp,
                )
                self._event(
                    connection,
                    item_id,
                    "final-reviewer",
                    "FINAL_REVIEW_HOLD",
                    {
                        "summary": reason,
                        "evidence_refs": validated_refs,
                        "package_hash": observed_hash,
                        "package_path": item["package_path"],
                        "reviewed_hash": normalized_hash,
                        "reviewed_revision": reviewed_revision,
                    },
                )
                result = self._get_item(connection, item_id)
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def withdraw_ready_hold(
        self,
        item_id: int,
        summary: str,
        evidence_refs: list[str],
        reviewed_hash: str,
        reviewed_revision: int,
    ) -> dict[str, Any]:
        if not isinstance(summary, str) or not summary.strip():
            raise MailboxError("operator HOLD summary is required")
        validated_refs = self._string_list(evidence_refs, "evidence_refs")
        if not isinstance(reviewed_hash, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", reviewed_hash
        ):
            raise MailboxError("reviewed_hash must be one SHA-256 hex digest")
        if (
            isinstance(reviewed_revision, bool)
            or not isinstance(reviewed_revision, int)
            or reviewed_revision < 1
        ):
            raise MailboxError("reviewed_revision must be a positive integer")

        normalized_hash = reviewed_hash.lower()
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "READY":
                raise MailboxError(
                    "withdraw-ready-hold requires READY, "
                    f"found {item['state']}"
                )
            if (
                item["package_hash"] != normalized_hash
                or int(item["revision"]) != reviewed_revision
            ):
                raise MailboxError(
                    "operator HOLD does not match the reviewed hash and revision"
                )
            package = self._validate_tracked_package(item["package_path"])
            zdi_root = (self.workspace / "ZDI").resolve()
            if package.parent != zdi_root or not package.name.startswith(READY_PREFIX):
                raise MailboxError(
                    "withdraw-ready-hold requires a direct READY-prefixed ZDI package"
                )
            observed_hash = self._hash_package(package)
            if observed_hash != normalized_hash:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed before operator HOLD"
            else:
                hold_root = (self.workspace / "ZDI_STAGING" / "_HOLD").resolve()
                hold_root.mkdir(parents=True, exist_ok=True)
                destination = hold_root / package.name[len(READY_PREFIX) :]
                if destination.exists():
                    raise MailboxError(
                        "cannot withdraw READY package because HOLD destination exists: "
                        f"{destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "WITHDRAW_READY_HOLD",
                        package,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot relocate operator HOLD package: {error}"
                    ) from error
                timestamp = utc_now()
                reason = summary.strip()
                try:
                    connection.execute(
                        """
                        UPDATE work_items
                        SET package_path = ?, state = 'HOLD', reviewed_hash = ?,
                            review_summary = ?, hold_reason = ?,
                            closure_completed = 1, claimed_at = NULL, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            str(destination),
                            observed_hash,
                            f"OPERATOR_WITHDREW_READY_TO_HOLD: {reason}",
                            reason,
                            timestamp,
                            item_id,
                        ),
                    )
                    self._event(
                        connection,
                        item_id,
                        "operator",
                        "OPERATOR_WITHDREW_READY_TO_HOLD",
                        {
                            "summary": reason,
                            "evidence_refs": validated_refs,
                            "from": item["package_path"],
                            "package_hash": observed_hash,
                            "reviewed_hash": normalized_hash,
                            "reviewed_revision": reviewed_revision,
                            "to": str(destination),
                        },
                    )
                    result = self._get_item(connection, item_id)
                except Exception:
                    if destination.exists() and not package.exists():
                        destination.rename(package)
                    raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def relocate_hold(self, item_id: int) -> dict[str, Any]:
        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "HOLD":
                raise MailboxError(
                    f"relocate-hold requires HOLD, found {item['state']}"
                )
            package = self._validate_tracked_package(item["package_path"])
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed before HOLD relocation"
            else:
                hold_root = (self.workspace / "ZDI_STAGING" / "_HOLD").resolve()
                if package.parent == hold_root:
                    result = item
                else:
                    staging_root = (self.workspace / "ZDI_STAGING").resolve()
                    zdi_root = (self.workspace / "ZDI").resolve()
                    if package.parent not in {staging_root, zdi_root}:
                        raise MailboxError(
                            "HOLD package is not in a supported direct review root"
                        )
                    hold_root.mkdir(parents=True, exist_ok=True)
                    destination = hold_root / package.name
                    if destination.exists():
                        raise MailboxError(
                            "cannot relocate HOLD because destination already exists: "
                            f"{destination}"
                        )
                    try:
                        self._journaled_move(
                            connection,
                            item_id,
                            "RELOCATE_HOLD",
                            package,
                            destination,
                            observed_hash,
                        )
                    except OSError as error:
                        raise MailboxError(
                            f"cannot relocate HOLD package: {error}"
                        ) from error
                    timestamp = utc_now()
                    try:
                        connection.execute(
                            "UPDATE work_items SET package_path = ?, updated_at = ? "
                            "WHERE id = ?",
                            (str(destination), timestamp, item_id),
                        )
                        self._event(
                            connection,
                            item_id,
                            "operator",
                            "HOLD_RELOCATED",
                            {
                                "from": item["package_path"],
                                "package_hash": observed_hash,
                                "revision": int(item["revision"]),
                                "to": str(destination),
                            },
                        )
                        result = self._get_item(connection, item_id)
                    except Exception:
                        if destination.exists() and not package.exists():
                            destination.rename(package)
                        raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def mark_dead(
        self,
        item_id: int,
        reason: str,
        operator: str,
    ) -> dict[str, Any]:
        if not isinstance(reason, str) or not reason.strip():
            raise MailboxError("DEAD reason is required")
        if not isinstance(operator, str) or not operator.strip():
            raise MailboxError("DEAD operator is required")
        if len(reason.strip()) > 4000:
            raise MailboxError("DEAD reason exceeds 4000 characters")
        if len(operator.strip()) > 128:
            raise MailboxError("DEAD operator exceeds 128 characters")

        drift_message: str | None = None
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] == "DEAD":
                if (
                    item["dead_reason"] == reason.strip()
                    and item["dead_operator"] == operator.strip()
                ):
                    self._clear_item_operator_requests(
                        connection, item_id, utc_now()
                    )
                    return item
                raise MailboxError("item is already terminal DEAD")
            if item["state"] == "SUBMITTED":
                raise MailboxError("a SUBMITTED item cannot be marked DEAD")

            package = self._validate_tracked_package(item["package_path"])
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                drift_message = "package changed before DEAD disposition"
            else:
                archive_root = self._dead_archive_root()
                archive_root.mkdir(parents=True, exist_ok=True)
                destination = archive_root / self._plain_package_name(package.name)
                if destination.exists():
                    raise MailboxError(
                        "cannot mark DEAD because destination already exists: "
                        f"{destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "MARK_DEAD",
                        package,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot archive DEAD package: {error}"
                    ) from error

                timestamp = utc_now()
                prior_state = item["state"]
                try:
                    connection.execute(
                        """
                        UPDATE work_items
                        SET package_path = ?, state = 'DEAD', dead_reason = ?,
                            dead_at = ?, dead_from_state = ?, dead_operator = ?,
                            claimed_at = NULL, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            str(destination),
                            reason.strip(),
                            timestamp,
                            prior_state,
                            operator.strip(),
                            timestamp,
                            item_id,
                        ),
                    )
                    self._event(
                        connection,
                        item_id,
                        "operator",
                        "MARKED_DEAD",
                        {
                            "from": item["package_path"],
                            "from_state": prior_state,
                            "operator": operator.strip(),
                            "package_hash": observed_hash,
                            "reason": reason.strip(),
                            "revision": int(item["revision"]),
                            "timestamp": timestamp,
                            "to": str(destination),
                        },
                    )
                    self._clear_item_operator_requests(
                        connection, item_id, timestamp
                    )
                    result = self._get_item(connection, item_id)
                except Exception:
                    if destination.exists() and not package.exists():
                        destination.rename(package)
                    raise
        if drift_message:
            raise MailboxError(drift_message)
        assert result is not None
        return result

    def relocate_dead(self, item_id: int) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "DEAD":
                raise MailboxError(
                    f"relocate-dead requires DEAD, found {item['state']}"
                )

            current = Path(item["package_path"]).resolve()
            archive_root = self._dead_archive_root()
            if current.parent == archive_root:
                package = self._validate_dead_archive_package(current)
                observed_hash = self._hash_package(package)
                if observed_hash != item["package_hash"]:
                    raise MailboxError("package changed after DEAD relocation")
                return item

            package = self._validate_tracked_package(current)
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                raise MailboxError("package changed before DEAD relocation")

            archive_root.mkdir(parents=True, exist_ok=True)
            destination = archive_root / self._plain_package_name(package.name)
            if destination.exists():
                raise MailboxError(
                    "cannot relocate DEAD because destination already exists: "
                    f"{destination}"
                )
            try:
                self._journaled_move(
                    connection,
                    item_id,
                    "RELOCATE_DEAD",
                    package,
                    destination,
                    observed_hash,
                )
            except OSError as error:
                raise MailboxError(f"cannot relocate DEAD package: {error}") from error

            timestamp = utc_now()
            try:
                connection.execute(
                    "UPDATE work_items SET package_path = ?, updated_at = ? WHERE id = ?",
                    (str(destination), timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "DEAD_RELOCATED",
                    {
                        "from": item["package_path"],
                        "package_hash": observed_hash,
                        "revision": int(item["revision"]),
                        "to": str(destination),
                    },
                )
                result = self._get_item(connection, item_id)
            except Exception:
                if destination.exists() and not package.exists():
                    destination.rename(package)
                raise
        assert result is not None
        return result

    @staticmethod
    def _manifest_diff(
        frozen: list[dict[str, Any]], observed: list[dict[str, Any]]
    ) -> dict[str, list[str]]:
        frozen_by_path = {entry["path"]: entry for entry in frozen}
        observed_by_path = {entry["path"]: entry for entry in observed}
        return {
            "added": sorted(set(observed_by_path) - set(frozen_by_path)),
            "changed": sorted(
                path
                for path in set(frozen_by_path) & set(observed_by_path)
                if frozen_by_path[path].get("sha256")
                != observed_by_path[path].get("sha256")
                or frozen_by_path[path].get("size")
                != observed_by_path[path].get("size")
            ),
            "removed": sorted(set(frozen_by_path) - set(observed_by_path)),
        }

    def mark_submitted(
        self,
        item_id: int,
        accept_drift: bool = False,
        note: str = "",
    ) -> dict[str, Any]:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._get_item(connection, item_id)
                if item["state"] == "SUBMITTED":
                    archive = Path(item["package_path"])
                    if not archive.is_dir():
                        raise MailboxError(
                            "submitted package path is missing; manual audit is required"
                        )
                    observed_hash = self._hash_package(archive)
                    if observed_hash != item["submitted_hash"]:
                        raise MailboxError(
                            "submitted package changed after reconciliation; manual audit is required"
                        )
                    ready_rows = connection.execute(
                        """
                        SELECT detail_json FROM events
                        WHERE work_item_id = ?
                          AND event_type = 'MARKED_READY_FOR_SUBMISSION'
                        ORDER BY id DESC
                        """,
                        (item_id,),
                    ).fetchall()
                    has_matching_ready = False
                    for ready_row in ready_rows:
                        try:
                            ready_detail = json.loads(ready_row["detail_json"] or "{}")
                        except json.JSONDecodeError:
                            continue
                        if ready_detail.get("package_hash") == item["package_hash"]:
                            has_matching_ready = True
                            break
                    if has_matching_ready:
                        self._verify_addressed_rework(connection, item, utc_now())
                    return self._get_item(connection, item_id)
                if item["state"] != "READY":
                    raise MailboxError(
                        "mark-submitted requires READY, "
                        f"found {item['state']}"
                    )

                tracked_path = Path(item["package_path"]).resolve()
                moved_ready_package = tracked_path.exists()
                if moved_ready_package:
                    package = self._validate_tracked_package(tracked_path)
                    zdi_root = (self.workspace / "ZDI").resolve()
                    if package.parent != zdi_root:
                        raise MailboxError(
                            "submitted READY package is not in the direct ZDI root"
                        )
                    if not package.name.startswith(READY_PREFIX):
                        raise MailboxError(
                            "mark-submitted requires a READY-prefixed direct package"
                        )
                    self._validate_external_package(package)
                    observed_hash = self._hash_package(package)
                    if observed_hash != item["package_hash"]:
                        raise MailboxError(
                            "READY package differs from the frozen review hash; re-review is required"
                        )
                    observed_manifest = self._manifest_package(package)
                    candidates = self._submitted_candidates(package.name)
                    if candidates:
                        raise MailboxError(
                            "submitted archive already exists for this package number; "
                            "manual audit is required"
                        )
                    submitted_root = (zdi_root / "_SUBMITTED").resolve()
                    submitted_root.mkdir(parents=True, exist_ok=True)
                    archive = submitted_root / (
                        f"_SUBMITTED_{self._plain_package_name(package.name)}"
                    )
                    if archive.exists():
                        raise MailboxError(
                            f"submitted archive already exists: {archive}"
                        )
                    try:
                        self._journaled_move(
                            connection,
                            item_id,
                            "MARK_SUBMITTED",
                            package,
                            archive,
                            observed_hash,
                        )
                    except OSError as error:
                        raise MailboxError(
                            f"cannot archive submitted package: {error}"
                        ) from error
                    if self._hash_package(archive) != observed_hash:
                        raise MailboxError(
                            "submitted package hash changed during archive move"
                        )
                    drifted = False
                else:
                    candidates = self._submitted_candidates(tracked_path.name)
                    if not candidates:
                        raise MailboxError(
                            "no exact-numbered submitted archive was found under ZDI/_SUBMITTED"
                        )
                    if len(candidates) != 1:
                        raise MailboxError(
                            "multiple exact-numbered submitted archives were found; manual audit is required"
                        )
                    archive = candidates[0]
                    observed_hash = self._hash_package(archive)
                    observed_manifest = self._manifest_package(archive)
                    drifted = observed_hash != item["package_hash"]
                    if drifted and not accept_drift:
                        raise MailboxError(
                            "submitted archive differs from the frozen review hash; rerun with "
                            "--accept-drift and an audit note only after the operator confirms it"
                        )
                    if drifted and not note.strip():
                        raise MailboxError(
                            "--accept-drift requires a non-empty audit note"
                        )

                try:
                    frozen_manifest = json.loads(
                        item["package_manifest_json"] or "[]"
                    )
                except json.JSONDecodeError:
                    frozen_manifest = []
                timestamp = utc_now()
                connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, state = 'SUBMITTED', submitted_path = ?,
                        submitted_hash = ?, submitted_manifest_json = ?,
                        submission_drift = ?, submission_note = ?, submitted_at = ?,
                        claimed_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        str(archive),
                        str(archive),
                        observed_hash,
                        json.dumps(observed_manifest, sort_keys=True),
                        int(drifted),
                        note.strip(),
                        timestamp,
                        timestamp,
                        item_id,
                    ),
                )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "SUBMISSION_RECONCILED",
                    {
                        "accepted_drift": drifted,
                        "archived_hash": observed_hash,
                        "archived_path": str(archive),
                        "frozen_hash": item["package_hash"],
                        "from": item["package_path"],
                        "manifest_diff": self._manifest_diff(
                            frozen_manifest, observed_manifest
                        ),
                        "moved_ready_package": moved_ready_package,
                        "note": note.strip(),
                    },
                )
                result = self._get_item(connection, item_id)
                connection.commit()
                return result
        except Exception:
            raise

    def mark_rejected(
        self,
        item_id: int,
        reason_code: str,
        reason: str,
        *,
        case_id: str = "",
        public_reference: str = "",
    ) -> dict[str, Any]:
        normalized_code = reason_code.strip().upper()
        normalized_reason = reason.strip()
        normalized_case_id = case_id.strip()
        normalized_reference = public_reference.strip()
        if normalized_code not in REJECTION_REASON_CODES:
            allowed = ", ".join(sorted(REJECTION_REASON_CODES))
            raise MailboxError(
                f"unsupported rejection reason code; expected one of: {allowed}"
            )
        if not normalized_reason:
            raise MailboxError("rejection reason is required")
        if len(normalized_reason) > 4000:
            raise MailboxError("rejection reason exceeds 4000 characters")
        if len(normalized_case_id) > 256:
            raise MailboxError("rejection case ID exceeds 256 characters")
        if len(normalized_reference) > 2048:
            raise MailboxError("rejection public reference exceeds 2048 characters")

        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._get_item(connection, item_id)
                if item["state"] == "REJECTED":
                    rejected = Path(item["package_path"]).resolve()
                    rejected_root = (
                        self.workspace / "ZDI" / "_REJECTED"
                    ).resolve()
                    if (
                        not rejected.is_dir()
                        or rejected.parent != rejected_root
                        or not rejected.name.startswith(REJECTED_PREFIX)
                    ):
                        raise MailboxError(
                            "rejected item is not in canonical ZDI/_REJECTED placement"
                        )
                    observed_hash = self._hash_package(rejected)
                    record = connection.execute(
                        "SELECT * FROM rejections WHERE work_item_id = ?",
                        (item_id,),
                    ).fetchone()
                    exact_repeat = (
                        record is not None
                        and record["package_path"] == str(rejected)
                        and record["rejected_hash"] == observed_hash
                        and record["reason_code"] == normalized_code
                        and record["reason"] == normalized_reason
                        and record["case_id"] == normalized_case_id
                        and record["public_reference"] == normalized_reference
                    )
                    if exact_repeat:
                        return item
                    raise MailboxError(
                        "mark-rejected conflicts with the rejection record"
                    )
                if item["state"] != "SUBMITTED":
                    raise MailboxError(
                        f"mark-rejected requires SUBMITTED, found {item['state']}"
                    )

                archive = Path(item["package_path"]).resolve()
                submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
                if (
                    not archive.is_dir()
                    or archive.parent != submitted_root
                    or not archive.name.startswith(SUBMITTED_PREFIX)
                ):
                    raise MailboxError(
                        "mark-rejected requires a canonical ZDI/_SUBMITTED package"
                    )
                observed_hash = self._hash_package(archive)
                if (
                    not item["submitted_hash"]
                    or observed_hash != item["submitted_hash"]
                ):
                    raise MailboxError(
                        "submitted package changed after submission; rejection is blocked"
                    )

                package_number = int(self._package_number(archive.name))
                existing = connection.execute(
                    """
                    SELECT id FROM rejections
                    WHERE work_item_id = ? OR package_number = ?
                    """,
                    (item_id, package_number),
                ).fetchone()
                if existing is not None:
                    raise MailboxError(
                        "a rejection record already exists for this package"
                    )

                rejected_root = (self.workspace / "ZDI" / "_REJECTED").resolve()
                rejected_root.mkdir(parents=True, exist_ok=True)
                destination = rejected_root / (
                    f"{REJECTED_PREFIX}{self._canonical_numbered_name(archive.name)}"
                )
                if destination.exists():
                    raise MailboxError(
                        f"rejected archive already exists: {destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "MARK_REJECTED",
                        archive,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot archive rejected package: {error}"
                    ) from error
                moved_from = archive
                moved_to = destination
                if self._hash_package(destination) != observed_hash:
                    raise MailboxError(
                        "rejected package hash changed during archive move"
                    )

                timestamp = utc_now()
                title = self._package_title(destination.name)
                connection.execute(
                    """
                    INSERT INTO rejections(
                        work_item_id, package_number, product, title,
                        package_path, rejected_hash, rejected_revision,
                        reason_code, reason, case_id, public_reference, rejected_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item_id,
                        package_number,
                        item["product"],
                        title,
                        str(destination),
                        observed_hash,
                        int(item["revision"]),
                        normalized_code,
                        normalized_reason,
                        normalized_case_id,
                        normalized_reference,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, state = 'REJECTED', claimed_at = NULL,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (str(destination), timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "OPERATOR_REJECTED",
                    {
                        "case_id": normalized_case_id,
                        "from": str(archive),
                        "package_hash": observed_hash,
                        "package_number": package_number,
                        "public_reference": normalized_reference,
                        "reason": normalized_reason,
                        "reason_code": normalized_code,
                        "to": str(destination),
                    },
                )
                result = self._get_item(connection, item_id)
            moved_from = None
            moved_to = None
            return result
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "mark-rejected failed and submitted package rollback failed: "
                        f"{rollback_error}"
                    ) from error
            raise

    def reconcile_rejected(
        self,
        package_path: str | Path,
        product: str,
        reason_code: str,
        reason: str,
        *,
        case_id: str = "",
        public_reference: str = "",
    ) -> dict[str, Any]:
        normalized_product = product.strip()
        normalized_code = reason_code.strip().upper()
        normalized_reason = reason.strip()
        normalized_case_id = case_id.strip()
        normalized_reference = public_reference.strip()
        if not normalized_product:
            raise MailboxError("rejected product is required")
        if normalized_code not in REJECTION_REASON_CODES:
            allowed = ", ".join(sorted(REJECTION_REASON_CODES))
            raise MailboxError(
                f"unsupported rejection reason code; expected one of: {allowed}"
            )
        if not normalized_reason:
            raise MailboxError("rejection reason is required")
        if len(normalized_reason) > 4000:
            raise MailboxError("rejection reason exceeds 4000 characters")
        if len(normalized_case_id) > 256:
            raise MailboxError("rejection case ID exceeds 256 characters")
        if len(normalized_reference) > 2048:
            raise MailboxError("rejection public reference exceeds 2048 characters")

        package = Path(package_path).resolve()
        submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
        rejected_root = (self.workspace / "ZDI" / "_REJECTED").resolve()
        is_submitted = (
            package.is_dir()
            and package.parent == submitted_root
            and re.fullmatch(r"_SUBMITTED_\d+_.+", package.name) is not None
        )
        is_rejected = (
            package.is_dir()
            and package.parent == rejected_root
            and re.fullmatch(r"_REJECTED_\d+_.+", package.name) is not None
        )
        if not is_submitted and not is_rejected:
            raise MailboxError(
                "reconcile-rejected requires a canonical ZDI/_SUBMITTED or "
                "ZDI/_REJECTED package"
            )

        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                package_number = int(self._package_number(package.name))
                tracked = self._items_for_number(connection, package.name)
                if tracked:
                    ids = ", ".join(str(row["id"]) for row in tracked)
                    raise MailboxError(
                        "legacy rejection package is already tracked as mailbox "
                        f"item(s) {ids}; use mark-rejected"
                    )
                observed_hash = self._hash_package(package)
                existing = connection.execute(
                    "SELECT * FROM rejections WHERE package_number = ?",
                    (package_number,),
                ).fetchone()
                if is_rejected:
                    exact_repeat = (
                        existing is not None
                        and existing["work_item_id"] is None
                        and existing["product"] == normalized_product
                        and existing["package_path"] == str(package)
                        and existing["rejected_hash"] == observed_hash
                        and existing["reason_code"] == normalized_code
                        and existing["reason"] == normalized_reason
                        and existing["case_id"] == normalized_case_id
                        and existing["public_reference"] == normalized_reference
                    )
                    if exact_repeat:
                        return dict(existing)
                    raise MailboxError(
                        "reconcile-rejected conflicts with the rejection record"
                    )
                if existing is not None:
                    raise MailboxError(
                        "a rejection record already exists for this package number"
                    )

                rejected_root.mkdir(parents=True, exist_ok=True)
                destination = rejected_root / (
                    f"{REJECTED_PREFIX}{self._canonical_numbered_name(package.name)}"
                )
                if destination.exists():
                    raise MailboxError(
                        f"rejected archive already exists: {destination}"
                    )
                try:
                    transition_id = self._journaled_move(
                        connection,
                        None,
                        "RECONCILE_REJECTED",
                        package,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot archive rejected package: {error}"
                    ) from error
                moved_from = package
                moved_to = destination
                if self._hash_package(destination) != observed_hash:
                    raise MailboxError(
                        "rejected package hash changed during archive move"
                    )

                timestamp = utc_now()
                title = self._package_title(destination.name)
                cursor = connection.execute(
                    """
                    INSERT INTO rejections(
                        work_item_id, package_number, product, title,
                        package_path, rejected_hash, rejected_revision,
                        reason_code, reason, case_id, public_reference, rejected_at
                    )
                    VALUES (NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
                    """,
                    (
                        package_number,
                        normalized_product,
                        title,
                        str(destination),
                        observed_hash,
                        normalized_code,
                        normalized_reason,
                        normalized_case_id,
                        normalized_reference,
                        timestamp,
                    ),
                )
                self._event(
                    connection,
                    None,
                    "operator",
                    "LEGACY_REJECTION_RECONCILED",
                    {
                        "case_id": normalized_case_id,
                        "from": str(package),
                        "package_hash": observed_hash,
                        "package_number": package_number,
                        "product": normalized_product,
                        "public_reference": normalized_reference,
                        "reason": normalized_reason,
                        "reason_code": normalized_code,
                        "to": str(destination),
                    },
                )
                rejection = connection.execute(
                    "SELECT * FROM rejections WHERE id = ?",
                    (int(cursor.lastrowid),),
                ).fetchone()
                assert rejection is not None
                self._complete_package_transition(connection, transition_id)
                result = dict(rejection)
            moved_from = None
            moved_to = None
            return result
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "reconcile-rejected failed and submitted package rollback "
                        f"failed: {rollback_error}"
                    ) from error
            raise

    def mark_accepted(
        self,
        item_id: int,
        amount_usd: int,
        *,
        case_id: str = "",
        vulnerability_family: str = "",
        attacker_position: str = "",
    ) -> dict[str, Any]:
        amount_cents = self._amount_cents(amount_usd)
        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._get_item(connection, item_id)
                if item["state"] == "ACCEPTED":
                    accepted = Path(item["package_path"]).resolve()
                    accepted_root = (
                        self.workspace / "ZDI" / "_ACCEPTED"
                    ).resolve()
                    if (
                        not accepted.is_dir()
                        or accepted.parent != accepted_root
                        or not accepted.name.startswith(ACCEPTED_PREFIX)
                    ):
                        raise MailboxError(
                            "accepted item is not in canonical ZDI/_ACCEPTED "
                            "placement"
                        )
                    observed_hash = self._hash_package(accepted)
                    package_number = int(self._package_number(accepted.name))
                    active = connection.execute(
                        """
                        SELECT * FROM accepted_acquisitions
                        WHERE status = 'ACTIVE'
                          AND (work_item_id = ? OR package_number = ?)
                        """,
                        (item_id, package_number),
                    ).fetchone()
                    exact_repeat = (
                        active is not None
                        and active["work_item_id"] is not None
                        and int(active["work_item_id"]) == item_id
                        and int(active["package_number"]) == package_number
                        and active["product"] == item["product"]
                        and active["package_path"] == str(accepted)
                        and active["accepted_hash"] == observed_hash
                        and active["accepted_revision"] is not None
                        and int(active["accepted_revision"]) == int(item["revision"])
                        and int(active["amount_cents"]) == amount_cents
                        and (not case_id.strip() or active["case_id"] == case_id.strip())
                        and (
                            not vulnerability_family.strip()
                            or active["vulnerability_family"]
                            == vulnerability_family.strip()
                        )
                        and (
                            not attacker_position.strip()
                            or active["attacker_position"]
                            == attacker_position.strip()
                        )
                    )
                    if exact_repeat:
                        return item
                    raise MailboxError(
                        "mark-accepted conflicts with the active acceptance record"
                    )
                if item["state"] != "SUBMITTED":
                    raise MailboxError(
                        f"mark-accepted requires SUBMITTED, found {item['state']}"
                    )

                archive = Path(item["package_path"]).resolve()
                submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
                if (
                    not archive.is_dir()
                    or archive.parent != submitted_root
                    or not archive.name.startswith(SUBMITTED_PREFIX)
                ):
                    raise MailboxError(
                        "mark-accepted requires a canonical ZDI/_SUBMITTED package"
                    )
                observed_hash = self._hash_package(archive)
                if (
                    not item["submitted_hash"]
                    or observed_hash != item["submitted_hash"]
                ):
                    raise MailboxError(
                        "submitted package changed after submission; "
                        "acceptance is blocked"
                    )

                package_number = int(self._package_number(archive.name))
                active = connection.execute(
                    """
                    SELECT id FROM accepted_acquisitions
                    WHERE status = 'ACTIVE'
                      AND (work_item_id = ? OR package_number = ?)
                    """,
                    (item_id, package_number),
                ).fetchone()
                if active is not None:
                    raise MailboxError(
                        "an active acceptance record already exists for this package"
                    )

                accepted_root = (self.workspace / "ZDI" / "_ACCEPTED").resolve()
                accepted_root.mkdir(parents=True, exist_ok=True)
                destination = accepted_root / (
                    f"{ACCEPTED_PREFIX}{self._canonical_numbered_name(archive.name)}"
                )
                if destination.exists():
                    raise MailboxError(
                        f"accepted archive already exists: {destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "MARK_ACCEPTED",
                        archive,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot archive accepted package: {error}"
                    ) from error
                moved_from = archive
                moved_to = destination
                if self._hash_package(destination) != observed_hash:
                    raise MailboxError(
                        "accepted package hash changed during archive move"
                    )

                timestamp = utc_now()
                title = self._package_title(destination.name)
                connection.execute(
                    """
                    INSERT INTO accepted_acquisitions(
                        work_item_id, package_number, product, title,
                        package_path, accepted_hash, accepted_revision,
                        amount_cents, currency, case_id, vulnerability_family,
                        attacker_position, status, accepted_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'USD', ?, ?, ?, 'ACTIVE', ?)
                    """,
                    (
                        item_id,
                        package_number,
                        item["product"],
                        title,
                        str(destination),
                        observed_hash,
                        int(item["revision"]),
                        amount_cents,
                        case_id.strip(),
                        vulnerability_family.strip(),
                        attacker_position.strip(),
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, state = 'ACCEPTED', claimed_at = NULL,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (str(destination), timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "OPERATOR_ACCEPTED",
                    {
                        "accepted_hash": observed_hash,
                        "accepted_path": str(destination),
                        "amount_cents": amount_cents,
                        "currency": "USD",
                        "package_number": package_number,
                    },
                )
                result = self._get_item(connection, item_id)
            moved_from = None
            moved_to = None
            return result
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "mark-accepted failed and submitted package rollback failed: "
                        f"{rollback_error}"
                    ) from error
            raise

    def restore_accepted_submitted(
        self,
        item_id: int,
        reason: str,
    ) -> dict[str, Any]:
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise MailboxError(
                "restore-accepted-submitted requires a correction reason"
            )

        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._get_item(connection, item_id)
                if item["state"] != "ACCEPTED":
                    raise MailboxError(
                        "restore-accepted-submitted requires ACCEPTED, "
                        f"found {item['state']}"
                    )
                acquisition = connection.execute(
                    """
                    SELECT * FROM accepted_acquisitions
                    WHERE work_item_id = ? AND status = 'ACTIVE'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (item_id,),
                ).fetchone()
                if acquisition is None:
                    raise MailboxError(
                        "accepted item has no active acquisition record"
                    )

                accepted = Path(item["package_path"]).resolve()
                accepted_root = (self.workspace / "ZDI" / "_ACCEPTED").resolve()
                if (
                    not accepted.is_dir()
                    or accepted.parent != accepted_root
                    or not accepted.name.startswith(ACCEPTED_PREFIX)
                ):
                    raise MailboxError(
                        "accepted package is not in canonical ZDI/_ACCEPTED placement"
                    )
                observed_hash = self._hash_package(accepted)
                if observed_hash != acquisition["accepted_hash"]:
                    raise MailboxError(
                        "accepted package changed after acceptance; "
                        "manual audit is required"
                    )

                submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
                submitted_root.mkdir(parents=True, exist_ok=True)
                destination = submitted_root / (
                    f"{SUBMITTED_PREFIX}{self._canonical_numbered_name(accepted.name)}"
                )
                if destination.exists():
                    raise MailboxError(
                        f"submitted archive already exists: {destination}"
                    )
                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "RESTORE_ACCEPTED_SUBMITTED",
                        accepted,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot restore accepted package to submitted: {error}"
                    ) from error
                moved_from = accepted
                moved_to = destination
                if self._hash_package(destination) != observed_hash:
                    raise MailboxError(
                        "submitted package hash changed during acceptance reversal"
                    )

                timestamp = utc_now()
                connection.execute(
                    """
                    UPDATE accepted_acquisitions
                    SET status = 'REVERSED', reversed_at = ?, reversal_reason = ?
                    WHERE id = ?
                    """,
                    (timestamp, normalized_reason, int(acquisition["id"])),
                )
                connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, state = 'SUBMITTED',
                        submitted_path = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (str(destination), str(destination), timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "ACCEPTANCE_REVERSED",
                    {
                        "accepted_hash": observed_hash,
                        "amount_cents": int(acquisition["amount_cents"]),
                        "currency": acquisition["currency"],
                        "reason": normalized_reason,
                        "submitted_path": str(destination),
                    },
                )
                result = self._get_item(connection, item_id)
            moved_from = None
            moved_to = None
            return result
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "restore-accepted-submitted failed and accepted package "
                        f"rollback failed: {rollback_error}"
                    ) from error
            raise

    def reconcile_accepted(
        self,
        package_path: str | Path,
        amount_usd: int,
        product: str,
        *,
        case_id: str = "",
        vulnerability_family: str = "",
        attacker_position: str = "",
    ) -> dict[str, Any]:
        amount_cents = self._amount_cents(amount_usd)
        normalized_product = product.strip()
        if not normalized_product:
            raise MailboxError("reconcile-accepted requires a product")
        package = Path(package_path).resolve()
        accepted_root = (self.workspace / "ZDI" / "_ACCEPTED").resolve()
        submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
        is_accepted = (
            package.is_dir()
            and package.parent == accepted_root
            and re.fullmatch(r"_ACCEPTED_\d+_.+", package.name) is not None
        )
        is_submitted = (
            package.is_dir()
            and package.parent == submitted_root
            and re.fullmatch(r"_SUBMITTED_\d+_.+", package.name) is not None
        )
        if not is_accepted and not is_submitted:
            raise MailboxError(
                "reconcile-accepted requires a canonical ZDI/_SUBMITTED or "
                "ZDI/_ACCEPTED package"
            )
        package_number = int(self._package_number(package.name))
        accepted_hash = self._hash_package(package)
        timestamp = utc_now()
        moved_from: Path | None = None
        moved_to: Path | None = None

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                active = connection.execute(
                    """
                    SELECT * FROM accepted_acquisitions
                    WHERE package_number = ? AND status = 'ACTIVE'
                    """,
                    (package_number,),
                ).fetchone()
                if active is not None:
                    exact_repeat = (
                        is_accepted
                        and int(active["package_number"]) == package_number
                        and active["product"] == normalized_product
                        and active["package_path"] == str(package)
                        and active["accepted_hash"] == accepted_hash
                        and int(active["amount_cents"]) == amount_cents
                        and (not case_id.strip() or active["case_id"] == case_id.strip())
                        and (
                            not vulnerability_family.strip()
                            or active["vulnerability_family"]
                            == vulnerability_family.strip()
                        )
                        and (
                            not attacker_position.strip()
                            or active["attacker_position"]
                            == attacker_position.strip()
                        )
                    )
                    if exact_repeat:
                        return dict(active)
                    raise MailboxError(
                        "reconcile-accepted conflicts with the active acceptance "
                        "record"
                    )
                matching_items = self._items_for_number(connection, package.name)
                if len(matching_items) > 1:
                    raise MailboxError(
                        "multiple mailbox items match this accepted package number"
                    )
                item = matching_items[0] if matching_items else None
                if item is not None:
                    allowed_states = {"SUBMITTED"} if is_submitted else {
                        "SUBMITTED",
                        "ACCEPTED",
                    }
                    if item["state"] not in allowed_states:
                        raise MailboxError(
                            "legacy acceptance can bind only to SUBMITTED or ACCEPTED"
                        )
                    if (
                        item["submitted_hash"]
                        and item["submitted_hash"] != accepted_hash
                    ):
                        raise MailboxError(
                            "legacy accepted package differs from the submitted hash"
                        )

                if is_submitted:
                    accepted_root.mkdir(parents=True, exist_ok=True)
                    destination = (
                        accepted_root
                        / f"{ACCEPTED_PREFIX}{self._canonical_numbered_name(package.name)}"
                    )
                    if destination.exists():
                        raise MailboxError(
                            f"accepted archive already exists: {destination}"
                        )
                    moved_from = package
                    moved_to = destination
                    transition_id = self._journaled_move(
                        connection,
                        int(item["id"]) if item is not None else None,
                        "RECONCILE_ACCEPTED",
                        package,
                        destination,
                        accepted_hash,
                    )
                    package = destination
                else:
                    transition_id = None

                cursor = connection.execute(
                    """
                    INSERT INTO accepted_acquisitions(
                        work_item_id, package_number, product, title, package_path,
                        accepted_hash, accepted_revision, amount_cents, currency,
                        case_id, vulnerability_family, attacker_position, status,
                        accepted_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'USD', ?, ?, ?, 'ACTIVE', ?)
                    """,
                    (
                        int(item["id"]) if item is not None else None,
                        package_number,
                        normalized_product,
                        self._package_title(package.name),
                        str(package),
                        accepted_hash,
                        int(item["revision"]) if item is not None else None,
                        amount_cents,
                        case_id.strip(),
                        vulnerability_family.strip(),
                        attacker_position.strip(),
                        timestamp,
                    ),
                )
                item_id = int(item["id"]) if item is not None else None
                if item_id is not None:
                    connection.execute(
                        """
                        UPDATE work_items
                        SET package_path = ?, state = 'ACCEPTED', updated_at = ?
                        WHERE id = ?
                        """,
                        (str(package), timestamp, item_id),
                    )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "LEGACY_ACCEPTANCE_RECONCILED",
                    {
                        "accepted_hash": accepted_hash,
                        "accepted_path": str(package),
                        "amount_cents": amount_cents,
                        "currency": "USD",
                        "package_number": package_number,
                    },
                )
                row = connection.execute(
                    "SELECT * FROM accepted_acquisitions WHERE id = ?",
                    (int(cursor.lastrowid),),
                ).fetchone()
                assert row is not None
                if transition_id is not None:
                    self._complete_package_transition(connection, transition_id)
                return dict(row)
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "reconcile-accepted failed and legacy submitted package "
                        f"rollback failed: {rollback_error}"
                    ) from error
            raise

    def accepted_comps(
        self,
        *,
        product: str = "",
        vulnerability_family: str = "",
        attacker_position: str = "",
    ) -> dict[str, Any]:
        normalized_product = product.strip().casefold()
        normalized_family = vulnerability_family.strip().casefold()
        normalized_position = attacker_position.strip().casefold()
        with self._connect() as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT package_number, product, title, amount_cents, currency,
                           accepted_at, vulnerability_family, attacker_position
                    FROM accepted_acquisitions
                    WHERE status = 'ACTIVE'
                    ORDER BY accepted_at DESC, id DESC
                    """
                )
            ]

        def relevance(row: dict[str, Any]) -> list[str]:
            matched: list[str] = []
            if normalized_product and row["product"].strip().casefold() == normalized_product:
                matched.append("product")
            if (
                normalized_family
                and row["vulnerability_family"].strip().casefold()
                == normalized_family
            ):
                matched.append("vulnerability_family")
            if (
                normalized_position
                and row["attacker_position"].strip().casefold()
                == normalized_position
            ):
                matched.append("attacker_position")
            return matched

        for row in rows:
            row["relevance"] = relevance(row)
        rows.sort(
            key=lambda row: (
                "product" in row["relevance"],
                "vulnerability_family" in row["relevance"],
                "attacker_position" in row["relevance"],
                row["accepted_at"],
            ),
            reverse=True,
        )

        if normalized_product:
            cohort = [row for row in rows if "product" in row["relevance"]]
        elif normalized_family:
            cohort = [
                row for row in rows if "vulnerability_family" in row["relevance"]
            ]
        elif normalized_position:
            cohort = [
                row for row in rows if "attacker_position" in row["relevance"]
            ]
        else:
            cohort = rows
        aggregate: dict[str, int] = {}
        if len(cohort) >= 2:
            amounts = sorted(int(row["amount_cents"]) for row in cohort)
            midpoint = len(amounts) // 2
            median_cents = (
                amounts[midpoint]
                if len(amounts) % 2
                else (amounts[midpoint - 1] + amounts[midpoint]) // 2
            )
            aggregate = {
                "count": len(amounts),
                "maximum_cents": amounts[-1],
                "median_cents": median_cents,
                "minimum_cents": amounts[0],
            }
        return {
            "aggregate": aggregate,
            "comparables": rows,
            "filters": {
                "attacker_position": attacker_position.strip(),
                "product": product.strip(),
                "vulnerability_family": vulnerability_family.strip(),
            },
        }

    def restore_submitted_ready(
        self,
        item_id: int,
        reason: str,
    ) -> dict[str, Any]:
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise MailboxError("restore-submitted-ready requires a correction reason")

        moved_from: Path | None = None
        moved_to: Path | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._get_item(connection, item_id)
                if item["state"] != "SUBMITTED":
                    raise MailboxError(
                        "restore-submitted-ready requires SUBMITTED, "
                        f"found {item['state']}"
                    )
                if int(item["submission_drift"]):
                    raise MailboxError(
                        "cannot restore a drifted submitted package to READY"
                    )

                archive = Path(item["package_path"]).resolve()
                submitted_root = (self.workspace / "ZDI" / "_SUBMITTED").resolve()
                if not archive.is_dir() or archive.parent != submitted_root:
                    raise MailboxError(
                        "submitted package is not in canonical ZDI/_SUBMITTED placement"
                    )
                expected_prefix = f"_SUBMITTED_{self._package_number(archive.name)}_"
                if not archive.name.startswith(expected_prefix):
                    raise MailboxError("submitted package name is not canonical")

                self._validate_external_package(archive)
                observed_hash = self._hash_package(archive)
                if (
                    observed_hash != item["package_hash"]
                    or observed_hash != item["submitted_hash"]
                ):
                    raise MailboxError(
                        "submitted package differs from the frozen READY hash"
                    )

                ready_rows = connection.execute(
                    """
                    SELECT detail_json FROM events
                    WHERE work_item_id = ?
                      AND event_type = 'MARKED_READY_FOR_SUBMISSION'
                    ORDER BY id DESC
                    """,
                    (item_id,),
                ).fetchall()
                has_matching_ready = False
                for ready_row in ready_rows:
                    try:
                        detail = json.loads(ready_row["detail_json"] or "{}")
                    except json.JSONDecodeError:
                        continue
                    if detail.get("package_hash") == observed_hash:
                        has_matching_ready = True
                        break
                if not has_matching_ready:
                    raise MailboxError(
                        "no matching READY event exists for the submitted hash"
                    )

                plain_name = archive.name[len("_SUBMITTED_") :]
                zdi_root = (self.workspace / "ZDI").resolve()
                destination = zdi_root / f"{READY_PREFIX}{plain_name}"
                if destination.exists():
                    raise MailboxError(
                        "cannot restore submitted package because READY destination exists: "
                        f"{destination}"
                    )

                try:
                    self._journaled_move(
                        connection,
                        item_id,
                        "RESTORE_SUBMITTED_READY",
                        archive,
                        destination,
                        observed_hash,
                    )
                except OSError as error:
                    raise MailboxError(
                        f"cannot restore submitted package to READY: {error}"
                    ) from error
                moved_from = archive
                moved_to = destination
                if self._hash_package(destination) != observed_hash:
                    raise MailboxError(
                        "package hash changed while restoring submitted package to READY"
                    )

                timestamp = utc_now()
                connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, state = 'READY',
                        submitted_path = '', submitted_hash = '',
                        submitted_manifest_json = '[]', submission_drift = 0,
                        submission_note = '', submitted_at = NULL,
                        claimed_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (str(destination), timestamp, item_id),
                )
                self._event(
                    connection,
                    item_id,
                    "operator",
                    "SUBMISSION_RETRACTED_TO_READY",
                    {
                        "from": str(archive),
                        "package_hash": observed_hash,
                        "reason": normalized_reason,
                        "revision": int(item["revision"]),
                        "to": str(destination),
                    },
                )
                result = self._get_item(connection, item_id)
                connection.commit()
                moved_from = None
                moved_to = None
                return result
        except Exception as error:
            if (
                moved_from is not None
                and moved_to is not None
                and moved_to.exists()
                and not moved_from.exists()
            ):
                try:
                    moved_to.rename(moved_from)
                except OSError as rollback_error:
                    raise MailboxError(
                        "restore-submitted-ready failed and archive rollback failed: "
                        f"{rollback_error}"
                    ) from error
            raise

    def resolve_private_question_hold(self, item_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get_item(connection, item_id)
            if item["state"] != "HOLD":
                raise MailboxError(
                    "resolve-policy-hold requires HOLD, "
                    f"found {item['state']}"
                )
            rows = connection.execute(
                """
                SELECT * FROM questions
                WHERE work_item_id = ? AND status != 'SUPERSEDED'
                ORDER BY id
                """,
                (item_id,),
            ).fetchall()
            invalid_ids = [
                int(row["id"])
                for row in rows
                if row["status"] == "UNRESOLVED"
                and (
                    question_requires_private_content(row["question_text"])
                    or question_requires_private_content(row["closure_condition"])
                )
            ]
            direct_policy_hold = direct_hold_is_private_policy_conflict(
                item["hold_reason"]
            )
            if not invalid_ids and not direct_policy_hold:
                raise MailboxError(
                    "HOLD does not match the bounded private-content policy waiver"
                )
            remaining = [
                int(row["id"])
                for row in rows
                if row["status"] not in {"CLOSED", "WAIVED"}
                and int(row["id"]) not in invalid_ids
            ]
            if remaining:
                raise MailboxError(
                    "HOLD still has genuine unresolved technical questions: "
                    + ", ".join(str(value) for value in remaining)
                )
            package = self._validate_tracked_package(item["package_path"])
            self._validate_external_package(package)
            observed_hash = self._hash_package(package)
            if observed_hash != item["package_hash"]:
                self._mark_stale(connection, item, observed_hash)
                raise MailboxError(
                    "package changed during policy-HOLD recovery; Hunter must register it again"
                )
            timestamp = utc_now()
            if invalid_ids:
                placeholders = ",".join("?" for _ in invalid_ids)
                connection.execute(
                    f"""
                    UPDATE questions
                    SET status = 'WAIVED',
                        closure_note = closure_note || ' [Operator waived private-package policy conflict.]',
                        updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    (timestamp, *invalid_ids),
                )
            connection.execute(
                """
                UPDATE work_items
                SET state = 'MIDLANE_PASS', hold_reason = '',
                    review_summary = ?,
                    closure_completed = 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    "POLICY_HOLD_RESOLVED: private economics and local workflow "
                    "identifiers remain outside the package.",
                    timestamp,
                    item_id,
                ),
            )
            self._event(
                connection,
                item_id,
                "operator",
                "PRIVATE_QUESTION_POLICY_WAIVED",
                {
                    "direct_hold_reason_waived": direct_policy_hold,
                    "package_hash": observed_hash,
                    "waived_question_ids": invalid_ids,
                },
            )
        return self.promote(item_id)

    def get_questions(self, item_id: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            self._get_item(connection, item_id)
            rows = connection.execute(
                """
                SELECT * FROM questions
                WHERE work_item_id = ? AND status != 'SUPERSEDED'
                ORDER BY id
                """,
                (item_id,),
            ).fetchall()
            return [self._question(row) for row in rows]

    def monitor(self, consumer: str) -> dict[str, Any]:
        if (
            not isinstance(consumer, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", consumer)
        ):
            raise MailboxError(
                "consumer must be 1-64 letters, numbers, dots, underscores, or hyphens"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = datetime.now(UTC)
            max_event_id = int(
                connection.execute(
                    "SELECT COALESCE(MAX(id), 0) FROM events"
                ).fetchone()[0]
            )
            offset = connection.execute(
                "SELECT last_event_id FROM consumer_offsets WHERE consumer = ?",
                (consumer,),
            ).fetchone()
            timestamp = utc_now()
            if offset is None:
                item_rows = connection.execute(
                    """
                    SELECT id, package_path, product, version, state, hold_reason,
                           updated_at
                    FROM work_items WHERE state != 'DEAD' ORDER BY id
                    """
                ).fetchall()
                changes = [
                    {
                        **_age_fields(row["updated_at"], now),
                        "event_type": "CURRENT_STATE",
                        "hold_reason": row["hold_reason"],
                        "item_id": int(row["id"]),
                        "package_path": row["package_path"],
                        "product": row["product"],
                        "state": row["state"],
                        "updated_at": row["updated_at"],
                        "version": row["version"],
                    }
                    for row in item_rows
                ]
                connection.execute(
                    """
                    INSERT INTO consumer_offsets(
                        consumer, last_event_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (consumer, max_event_id, timestamp, timestamp),
                )
                return {
                    "changes": changes,
                    "consumer": consumer,
                    "cursor": max_event_id,
                    "display_time": local_display_time(),
                    "initial": True,
                    "workers": self._workers(connection),
                }

            last_event_id = int(offset["last_event_id"])
            rows = connection.execute(
                """
                SELECT e.id AS event_id, e.actor, e.event_type, e.detail_json,
                       e.created_at, w.id AS item_id, w.package_path, w.product,
                       w.version, w.state, w.hold_reason
                FROM events e
                LEFT JOIN work_items w ON w.id = e.work_item_id
                WHERE e.id > ? AND (w.id IS NULL OR w.state != 'DEAD')
                ORDER BY e.id
                """,
                (last_event_id,),
            ).fetchall()
            changes = [
                {
                    **_age_fields(row["created_at"], now),
                    "actor": row["actor"],
                    "created_at": row["created_at"],
                    "detail": json.loads(row["detail_json"]),
                    "event_id": int(row["event_id"]),
                    "event_type": row["event_type"],
                    "hold_reason": row["hold_reason"] or "",
                    "item_id": int(row["item_id"]) if row["item_id"] is not None else None,
                    "package_path": row["package_path"],
                    "product": row["product"],
                    "state": row["state"],
                    "version": row["version"],
                }
                for row in rows
            ]
            connection.execute(
                """
                UPDATE consumer_offsets
                SET last_event_id = ?, updated_at = ?
                WHERE consumer = ?
                """,
                (max_event_id, timestamp, consumer),
            )
            return {
                "changes": changes,
                "consumer": consumer,
                "cursor": max_event_id,
                "display_time": local_display_time(),
                "initial": False,
                "workers": self._workers(connection),
            }

    def status(self, include_dead: bool = False) -> dict[str, Any]:
        with self._connect() as connection:
            now = datetime.now(UTC)
            state_filter = "" if include_dead else "WHERE state != 'DEAD'"
            count_rows = connection.execute(
                "SELECT state, COUNT(*) AS count FROM work_items "
                f"{state_filter} GROUP BY state ORDER BY state"
            ).fetchall()
            item_rows = connection.execute(
                f"""
                SELECT id, package_path, product, version, package_hash, state,
                       revision, updated_at, hold_reason, submitted_hash,
                       submission_drift, submission_note, submitted_at,
                       dead_reason, dead_at, dead_from_state, dead_operator
                FROM work_items {state_filter} ORDER BY id
                """
            ).fetchall()
            latest_rework = latest_rework_by_item(connection)
            items: list[dict[str, Any]] = []
            for row in item_rows:
                item = dict(row)
                item.update(_age_fields(item["updated_at"], now))
                item["final_rework_request"] = latest_rework.get(int(item["id"]))
                tracked_path = Path(item["package_path"])
                item["path_exists"] = tracked_path.is_dir()
                item["archive_candidates"] = []
                item["attention"] = ""
                resolved_path = tracked_path.resolve()
                zdi_root = (self.workspace / "ZDI").resolve()
                ready_path = (
                    resolved_path.parent == zdi_root
                    and resolved_path.name.startswith(READY_PREFIX)
                )
                final_review_path = (
                    resolved_path.parent == zdi_root
                    and NUMBERED_PACKAGE.fullmatch(resolved_path.name) is not None
                )
                state_path_mismatch = (
                    item["state"] == "READY" and not ready_path
                ) or (
                    item["state"] == "AWAITING_FINAL_REVIEW"
                    and not final_review_path
                )
                if state_path_mismatch:
                    item["attention"] = "STATE_PATH_MISMATCH"
                elif item["state"] in {"AWAITING_FINAL_REVIEW", "READY"} and not item["path_exists"]:
                    try:
                        candidates = self._submitted_candidates(tracked_path.name)
                    except MailboxError:
                        candidates = []
                    item["archive_candidates"] = [str(path) for path in candidates]
                    item["attention"] = (
                        "SUBMISSION_RECONCILIATION_REQUIRED"
                        if candidates
                        else "TRACKED_PATH_MISSING"
                    )
                elif item["state"] == "SUBMITTED" and not item["path_exists"]:
                    item["attention"] = "SUBMITTED_ARCHIVE_MISSING"
                items.append(item)
            return {
                "counts": {row["state"]: int(row["count"]) for row in count_rows},
                "display_time": local_display_time(),
                "items": items,
                "operator_requests": self._operator_requests(connection),
                "approval_requests": self._operator_approval_requests(connection),
                "workers": self._workers(connection),
            }


def _read_json(path: str | Path) -> dict[str, Any]:
    _phase("INPUT_READ_START", input=str(path))
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MailboxError(f"cannot read JSON input {path}: {error}") from error
    if not isinstance(value, dict):
        raise MailboxError("JSON input must contain one object")
    _phase("INPUT_READ_COMPLETE", input=str(path))
    return value


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Small SQLite mailbox for the existing Hunter and Midlane chats."
    )
    parser.add_argument("--workspace", type=Path, default=workspace)
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help=(
            "mailbox database path; defaults to "
            "<workspace>/notes/review_mailbox/review_mailbox.sqlite3"
        ),
    )
    parser.add_argument(
        "--phase-file",
        type=Path,
        help="optional private JSONL phase trace for guarded diagnostics",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="create or update the mailbox schema")

    begin_build = commands.add_parser(
        "begin-package-build",
        help="record or refresh one Hunter package build before registration",
    )
    begin_build.add_argument("--package", type=Path, required=True)
    begin_build.add_argument("--product", required=True)
    begin_build.add_argument("--version", required=True)
    begin_build.add_argument("--detail", default="")
    begin_build.add_argument("--candidate-challenge", type=Path)

    cancel_build = commands.add_parser(
        "cancel-package-build",
        help="cancel one active pre-registration package build",
    )
    cancel_build.add_argument("--number", type=int, required=True)

    register = commands.add_parser("register", help="freeze and queue a numbered package")
    register.add_argument("--package", type=Path, required=True)
    register.add_argument("--product", required=True)
    register.add_argument("--version", required=True)
    register.add_argument("--note", default="")
    register.add_argument("--preflight-result", type=Path)

    mutation_authority = commands.add_parser(
        "assert-mutation-authority",
        help="fail closed unless Hunter currently owns one staged package's bytes",
    )
    mutation_authority.add_argument("--item", type=int, required=True)

    rebind_rework_path = commands.add_parser(
        "rebind-final-rework-path",
        help="synchronize a claimed rework item after its staging folder is renamed",
    )
    rebind_rework_path.add_argument("--item", type=int, required=True)
    rebind_rework_path.add_argument("--package", type=Path, required=True)

    commands.add_parser("claim-next", help="claim or resume one Midlane review")

    inventory = commands.add_parser(
        "candidate-inventory",
        help="show the hash-bound same-product package inventory",
    )
    inventory.add_argument("--product", required=True)

    review = commands.add_parser("review", help="record PASS, QUESTIONS, or HOLD")
    review.add_argument("--item", type=int, required=True)
    review.add_argument("--input", type=Path, required=True)

    questions = commands.add_parser("questions", help="show an item's current questions")
    questions.add_argument("--item", type=int, required=True)

    answer = commands.add_parser("answer", help="record one complete Hunter answer batch")
    answer.add_argument("--item", type=int, required=True)
    answer.add_argument("--input", type=Path, required=True)

    close = commands.add_parser("close", help="perform the one bounded closure pass")
    close.add_argument("--item", type=int, required=True)
    close.add_argument("--input", type=Path, required=True)

    promote = commands.add_parser(
        "promote", help="Hunter moves one passed package into ZDI for manual review"
    )
    promote.add_argument("--item", type=int, required=True)

    restage = commands.add_parser(
        "restage", help="Hunter moves a legacy in-progress ZDI package back to staging"
    )
    restage.add_argument("--item", type=int, required=True)

    queue_rework = commands.add_parser(
        "queue-final-rework",
        help="Final Reviewer stores one hash-bound NEEDS WORK request",
    )
    queue_rework.add_argument("--item", type=int, required=True)
    queue_rework.add_argument("--input", type=Path, required=True)

    commands.add_parser(
        "claim-final-rework",
        help="Hunter atomically claims the oldest open Final Reviewer request",
    )

    rebind_rework_candidate = commands.add_parser(
        "rebind-final-rework-candidate",
        help="bind claimed final rework to a fresh same-family Candidate Challenge",
    )
    rebind_rework_candidate.add_argument("--item", type=int, required=True)
    rebind_rework_candidate.add_argument(
        "--candidate-challenge", type=Path, required=True
    )
    rebind_rework_candidate.add_argument(
        "--expected-package-hash", required=True
    )

    rework_details = commands.add_parser(
        "rework-details",
        help="show the latest durable Final Reviewer request for one item",
    )
    rework_details.add_argument("--item", type=int, required=True)

    rework = commands.add_parser(
        "return-for-rework",
        help="disabled legacy chat relay; use queue-final-rework and claim-final-rework",
    )
    rework.add_argument("--item", type=int, required=True)
    rework.add_argument("--input", type=Path, required=True)

    final_hold = commands.add_parser(
        "hold-final-rework",
        help="terminally hold an unchanged FINAL_REWORK package in staging",
    )
    final_hold.add_argument("--item", type=int, required=True)
    final_hold.add_argument("--input", type=Path, required=True)

    reviewed_hold = commands.add_parser(
        "mark-final-hold",
        help="Final Reviewer records one hash-bound terminal HOLD",
    )
    reviewed_hold.add_argument("--item", type=int, required=True)
    reviewed_hold.add_argument("--input", type=Path, required=True)

    ready = commands.add_parser(
        "mark-ready",
        help="record a complete Final Reviewer determination and mark READY",
    )
    ready.add_argument("--item", type=int, required=True)
    ready.add_argument("--input", type=Path, required=True)

    reopen_ready = commands.add_parser(
        "reopen-ready",
        help="operator explicitly queues a new request against a READY package",
    )
    reopen_ready.add_argument("--item", type=int, required=True)
    reopen_ready.add_argument("--input", type=Path, required=True)

    withdraw_ready = commands.add_parser(
        "withdraw-ready-hold",
        help="operator atomically withdraws an unchanged READY package to terminal HOLD",
    )
    withdraw_ready.add_argument("--item", type=int, required=True)
    withdraw_ready.add_argument("--input", type=Path, required=True)

    restore_ready = commands.add_parser(
        "restore-stale-ready",
        help="operator restores unchanged READY bytes after a legacy stale replay",
    )
    restore_ready.add_argument("--item", type=int, required=True)

    submitted = commands.add_parser(
        "mark-submitted",
        help="operator archives one explicitly confirmed READY package as SUBMITTED",
    )
    submitted.add_argument("--item", type=int, required=True)
    submitted.add_argument("--accept-drift", action="store_true")
    submitted.add_argument("--note", default="")

    rejected = commands.add_parser(
        "mark-rejected",
        help="operator records one unchanged submitted package as REJECTED",
    )
    rejected.add_argument("--item", type=int, required=True)
    rejected.add_argument(
        "--reason-code",
        required=True,
        choices=sorted(REJECTION_REASON_CODES),
    )
    rejected.add_argument("--reason", required=True)
    rejected.add_argument("--case-id", default="")
    rejected.add_argument("--public-reference", default="")

    reconcile_rejected = commands.add_parser(
        "reconcile-rejected",
        help="operator indexes one canonical legacy submitted package as REJECTED",
    )
    reconcile_rejected.add_argument("--package", type=Path, required=True)
    reconcile_rejected.add_argument("--product", required=True)
    reconcile_rejected.add_argument(
        "--reason-code",
        required=True,
        choices=sorted(REJECTION_REASON_CODES),
    )
    reconcile_rejected.add_argument("--reason", required=True)
    reconcile_rejected.add_argument("--case-id", default="")
    reconcile_rejected.add_argument("--public-reference", default="")

    restore_submitted = commands.add_parser(
        "restore-submitted-ready",
        help="operator reverses a false SUBMITTED event for unchanged READY bytes",
    )
    restore_submitted.add_argument("--item", type=int, required=True)
    restore_submitted.add_argument("--reason", required=True)

    accepted = commands.add_parser(
        "mark-accepted",
        help="operator records one unchanged submitted package as ACCEPTED",
    )
    accepted.add_argument("--item", type=int, required=True)
    accepted.add_argument("--amount-usd", type=int, required=True)
    accepted.add_argument("--case-id", default="")
    accepted.add_argument("--vulnerability-family", default="")
    accepted.add_argument("--attacker-position", default="")

    restore_accepted = commands.add_parser(
        "restore-accepted-submitted",
        help="operator reverses an erroneous ACCEPTED transition",
    )
    restore_accepted.add_argument("--item", type=int, required=True)
    restore_accepted.add_argument("--reason", required=True)

    reconcile_accepted = commands.add_parser(
        "reconcile-accepted",
        help="operator indexes one canonical legacy ACCEPTED package",
    )
    reconcile_accepted.add_argument("--package", type=Path, required=True)
    reconcile_accepted.add_argument("--amount-usd", type=int, required=True)
    reconcile_accepted.add_argument("--product", required=True)
    reconcile_accepted.add_argument("--case-id", default="")
    reconcile_accepted.add_argument("--vulnerability-family", default="")
    reconcile_accepted.add_argument("--attacker-position", default="")

    accepted_comps = commands.add_parser(
        "accepted-comps",
        help="query private accepted payout comparables",
    )
    accepted_comps.add_argument("--product", default="")
    accepted_comps.add_argument("--vulnerability-family", default="")
    accepted_comps.add_argument("--attacker-position", default="")

    policy_hold = commands.add_parser(
        "resolve-policy-hold",
        help="operator waives only legacy private-content questions in a HOLD",
    )
    policy_hold.add_argument("--item", type=int, required=True)

    monitor = commands.add_parser(
        "monitor", help="return each mailbox transition once for a named consumer"
    )
    monitor.add_argument("--consumer", required=True)

    checkin = commands.add_parser(
        "checkin", help="record Hunter working, idle, or blocked status"
    )
    checkin.add_argument("--worker", required=True)
    checkin.add_argument("--state", required=True)
    checkin.add_argument("--task", required=True)
    checkin.add_argument("--detail", default="")

    transition = commands.add_parser(
        "target-transition",
        help="record a validated Hunter STANDING_DOWN or PARKED transition",
    )
    transition.add_argument("--worker", required=True)
    transition.add_argument("--slug", required=True)
    transition.add_argument(
        "--phase", required=True, choices=("STANDING_DOWN", "PARKED")
    )
    transition.add_argument("--detail", required=True)
    transition.add_argument("--resume-capsule", type=Path)
    transition.add_argument("--shutdown-check", type=Path)

    heartbeat = commands.add_parser(
        "activity-heartbeat",
        help="refresh unchanged WORKING activity after proven owned tool execution",
    )
    heartbeat.add_argument("--worker", required=True)
    heartbeat.add_argument("--source", required=True)
    heartbeat.add_argument(
        "--minimum-age-seconds",
        type=int,
        default=DEFAULT_ACTIVITY_HEARTBEAT_MINIMUM_SECONDS,
    )
    heartbeat.add_argument("--expected-task-hash", default="")
    heartbeat.add_argument("--expected-detail-hash", default="")

    operator_request = commands.add_parser(
        "request-operator",
        help="create or update one durable operator-help request for a worker",
    )
    operator_request.add_argument("--worker", required=True)
    operator_request.add_argument("--target", required=True)
    operator_request.add_argument("--summary", required=True)
    operator_request.add_argument("--detail", default="")

    clear_operator_request = commands.add_parser(
        "clear-operator-request",
        help="explicitly clear one worker's current operator-help request",
    )
    clear_operator_request.add_argument("--worker", required=True)
    clear_operator_request.add_argument("--note", default="")

    operator_approval = commands.add_parser(
        "request-operator-approval",
        help="create or update one durable nonblocking approval request for a worker",
    )
    operator_approval.add_argument("--worker", required=True)
    operator_approval.add_argument("--target", required=True)
    operator_approval.add_argument("--summary", required=True)
    operator_approval.add_argument("--detail", default="")

    clear_operator_approval = commands.add_parser(
        "clear-operator-approval",
        help="explicitly clear one worker's current nonblocking approval request",
    )
    clear_operator_approval.add_argument("--worker", required=True)
    clear_operator_approval.add_argument("--note", default="")

    dead = commands.add_parser(
        "mark-dead",
        help="operator records an immutable terminal DEAD disposition",
    )
    dead.add_argument("--item", type=int, required=True)
    dead.add_argument("--reason", required=True)
    dead.add_argument("--operator", required=True)

    relocate_dead = commands.add_parser(
        "relocate-dead",
        help="operator reconciles an unchanged legacy DEAD package into ZDI/_NUMBERED",
    )
    relocate_dead.add_argument("--item", type=int, required=True)

    relocate_hold = commands.add_parser(
        "relocate-hold",
        help="operator moves an unchanged HOLD package into ZDI_STAGING/_HOLD",
    )
    relocate_hold.add_argument("--item", type=int, required=True)

    reconcile_duplicate = commands.add_parser(
        "reconcile-duplicate-registration",
        help="operator removes one missing-path same-hash phantom registration",
    )
    reconcile_duplicate.add_argument("--keep-item", type=int, required=True)
    reconcile_duplicate.add_argument("--duplicate-item", type=int, required=True)
    reconcile_duplicate.add_argument("--operator", required=True)

    status = commands.add_parser("status", help="show compact mailbox status")
    status.add_argument("--include-dead", action="store_true")
    return parser


def main(arguments: list[str] | None = None) -> int:
    global _PHASE_FILE
    args = _parser().parse_args(arguments)
    args.workspace = args.workspace.resolve()
    database_was_explicit = args.db is not None
    args.db = (
        args.db.resolve()
        if args.db is not None
        else (
            args.workspace
            / "notes"
            / "review_mailbox"
            / "review_mailbox.sqlite3"
        ).resolve()
    )
    _PHASE_FILE = args.phase_file.resolve() if args.phase_file else None
    _phase("ARGUMENTS_PARSED", command=args.command)
    try:
        enforce_production_gates = (
            not database_was_explicit or _is_canonical_mailbox_database(args.db)
        )
        mailbox = (
            Mailbox.open_read_only(args.db, args.workspace)
            if args.command in READ_ONLY_COMMANDS
            else Mailbox(
                args.db,
                args.workspace,
                require_preflight=enforce_production_gates,
                require_candidate_challenge=enforce_production_gates,
            )
        )
        if args.command == "init":
            output: dict[str, Any] = {
                "status": "initialized",
                "db": str(mailbox.db_path),
            }
        elif args.command == "begin-package-build":
            output = {
                "build": mailbox.begin_package_build(
                    args.package,
                    args.product,
                    args.version,
                    args.detail,
                    args.candidate_challenge,
                )
            }
        elif args.command == "cancel-package-build":
            output = {"build": mailbox.cancel_package_build(args.number)}
        elif args.command == "register":
            output = {
                "item": mailbox.register(
                    args.package,
                    args.product,
                    args.version,
                    args.note,
                    args.preflight_result,
                )
            }
        elif args.command == "assert-mutation-authority":
            output = {
                "mutation_authority": mailbox.assert_mutation_authority(args.item)
            }
        elif args.command == "rebind-final-rework-path":
            output = {
                "item": mailbox.rebind_final_rework_path(args.item, args.package)
            }
        elif args.command == "claim-next":
            output = mailbox.claim_next_detailed()
        elif args.command == "candidate-inventory":
            output = {"candidate_inventory": mailbox.candidate_inventory(args.product)}
        elif args.command == "review":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.record_review(
                    args.item,
                    str(payload.get("verdict", "")),
                    str(payload.get("summary", "")),
                    payload.get("questions", []),
                )
            }
        elif args.command == "questions":
            output = {"questions": mailbox.get_questions(args.item)}
        elif args.command == "answer":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.answer_questions(
                    args.item,
                    payload.get("answers", []),
                    str(payload.get("note", "")),
                )
            }
        elif args.command == "close":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.close_review(
                    args.item,
                    str(payload.get("verdict", "")),
                    payload.get("closures", []),
                    str(payload.get("summary", "")),
                )
            }
        elif args.command == "promote":
            output = {"item": mailbox.promote(args.item)}
        elif args.command == "restage":
            output = {"item": mailbox.restage(args.item)}
        elif args.command == "queue-final-rework":
            payload = _read_json(args.input)
            output = mailbox.queue_final_rework(
                args.item,
                str(payload.get("summary", "")),
                payload.get("issues", []),
                payload.get("evidence_refs", []),
                payload.get("reviewed_hash", ""),
                payload.get("reviewed_revision", 0),
                payload.get("review_scope", "SEMANTIC"),
            )
        elif args.command == "claim-final-rework":
            claimed = mailbox.claim_final_rework()
            output = claimed if claimed is not None else {"item": None, "request": None}
        elif args.command == "rebind-final-rework-candidate":
            output = mailbox.rebind_final_rework_candidate(
                args.item,
                args.candidate_challenge,
                args.expected_package_hash,
            )
        elif args.command == "rework-details":
            output = {"request": mailbox.rework_details(args.item)}
        elif args.command == "return-for-rework":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.return_for_rework(
                    args.item,
                    str(payload.get("summary", "")),
                    payload.get("issues", []),
                    payload.get("evidence_refs", []),
                )
            }
        elif args.command == "hold-final-rework":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.hold_final_rework(
                    args.item,
                    str(payload.get("summary", "")),
                    payload.get("evidence_refs", []),
                )
            }
        elif args.command == "mark-final-hold":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.mark_final_hold(
                    args.item,
                    str(payload.get("summary", "")),
                    payload.get("evidence_refs", []),
                    payload.get("reviewed_hash", ""),
                    payload.get("reviewed_revision", 0),
                )
            }
        elif args.command == "mark-ready":
            output = {
                "item": mailbox.mark_ready(args.item, _read_json(args.input))
            }
        elif args.command == "reopen-ready":
            payload = _read_json(args.input)
            output = mailbox.reopen_ready(
                args.item,
                str(payload.get("summary", "")),
                payload.get("issues", []),
                payload.get("evidence_refs", []),
                payload.get("reviewed_hash", ""),
                payload.get("reviewed_revision", 0),
                payload.get("review_scope", "SEMANTIC"),
            )
        elif args.command == "withdraw-ready-hold":
            payload = _read_json(args.input)
            output = {
                "item": mailbox.withdraw_ready_hold(
                    args.item,
                    str(payload.get("summary", "")),
                    payload.get("evidence_refs", []),
                    payload.get("reviewed_hash", ""),
                    payload.get("reviewed_revision", 0),
                )
            }
        elif args.command == "restore-stale-ready":
            output = {"item": mailbox.restore_stale_ready(args.item)}
        elif args.command == "mark-submitted":
            output = {
                "item": mailbox.mark_submitted(
                    args.item,
                    accept_drift=args.accept_drift,
                    note=args.note,
                )
            }
        elif args.command == "mark-rejected":
            output = {
                "item": mailbox.mark_rejected(
                    args.item,
                    args.reason_code,
                    args.reason,
                    case_id=args.case_id,
                    public_reference=args.public_reference,
                )
            }
        elif args.command == "reconcile-rejected":
            output = {
                "rejection": mailbox.reconcile_rejected(
                    args.package,
                    args.product,
                    args.reason_code,
                    args.reason,
                    case_id=args.case_id,
                    public_reference=args.public_reference,
                )
            }
        elif args.command == "restore-submitted-ready":
            output = {
                "item": mailbox.restore_submitted_ready(args.item, args.reason)
            }
        elif args.command == "mark-accepted":
            output = {
                "item": mailbox.mark_accepted(
                    args.item,
                    args.amount_usd,
                    case_id=args.case_id,
                    vulnerability_family=args.vulnerability_family,
                    attacker_position=args.attacker_position,
                )
            }
        elif args.command == "restore-accepted-submitted":
            output = {
                "item": mailbox.restore_accepted_submitted(args.item, args.reason)
            }
        elif args.command == "reconcile-accepted":
            output = {
                "acquisition": mailbox.reconcile_accepted(
                    args.package,
                    args.amount_usd,
                    args.product,
                    case_id=args.case_id,
                    vulnerability_family=args.vulnerability_family,
                    attacker_position=args.attacker_position,
                )
            }
        elif args.command == "accepted-comps":
            output = mailbox.accepted_comps(
                product=args.product,
                vulnerability_family=args.vulnerability_family,
                attacker_position=args.attacker_position,
            )
        elif args.command == "resolve-policy-hold":
            output = {"item": mailbox.resolve_private_question_hold(args.item)}
        elif args.command == "mark-dead":
            output = {
                "item": mailbox.mark_dead(args.item, args.reason, args.operator)
            }
        elif args.command == "relocate-dead":
            output = {"item": mailbox.relocate_dead(args.item)}
        elif args.command == "relocate-hold":
            output = {"item": mailbox.relocate_hold(args.item)}
        elif args.command == "reconcile-duplicate-registration":
            output = mailbox.reconcile_duplicate_registration(
                args.keep_item, args.duplicate_item, args.operator
            )
        elif args.command == "monitor":
            output = mailbox.monitor(args.consumer)
        elif args.command == "checkin":
            codex_thread_id = os.environ.get("CODEX_THREAD_ID", "").strip()
            session_hash = (
                hashlib.sha256(codex_thread_id.encode("utf-8")).hexdigest()
                if codex_thread_id
                else ""
            )
            worker_status = mailbox.checkin(
                args.worker,
                args.state,
                args.task,
                args.detail,
                session_hash=session_hash,
            )
            output = {"worker": worker_status}
            if "hunt_policy_delta" in worker_status:
                output["hunt_policy_delta"] = worker_status["hunt_policy_delta"]
        elif args.command == "target-transition":
            output = {
                "worker": mailbox.target_transition(
                    args.worker,
                    args.slug,
                    args.phase,
                    args.detail,
                    args.resume_capsule,
                    args.shutdown_check,
                )
            }
        elif args.command == "activity-heartbeat":
            output = {
                "heartbeat": mailbox.activity_heartbeat(
                    args.worker,
                    source=args.source,
                    minimum_age_seconds=args.minimum_age_seconds,
                    expected_task_hash=args.expected_task_hash,
                    expected_detail_hash=args.expected_detail_hash,
                )
            }
        elif args.command == "request-operator":
            output = {
                "operator_request": mailbox.request_operator(
                    args.worker, args.target, args.summary, args.detail
                )
            }
        elif args.command == "clear-operator-request":
            output = {
                "operator_request": mailbox.clear_operator_request(
                    args.worker, args.note
                )
            }
        elif args.command == "request-operator-approval":
            if args.worker.strip().casefold() != "hunter":
                raise MailboxError(
                    "legacy approval compatibility route is Hunter-only"
                )
            try:
                approval = CoordinationInbox(
                    mailbox.workspace
                    / "notes"
                    / "coordination_inbox"
                    / "coordination.sqlite3"
                ).post(
                    message_type="ACTION_REQUEST",
                    sender="hunter",
                    recipient="hunter",
                    scope_kind="TARGET",
                    scope_ref=args.target,
                    body=args.detail or args.summary,
                    requested_action=args.summary,
                )
            except CoordinationInboxError as error:
                raise MailboxError(str(error)) from error
            output = {"approval_request": approval}
        elif args.command == "clear-operator-approval":
            output = {
                "approval_request": mailbox.clear_operator_approval(
                    args.worker, args.note
                )
            }
        else:
            output = mailbox.status(include_dead=args.include_dead)
    except MailboxError as error:
        _phase("COMMAND_ERROR", command=args.command, error=str(error))
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    _phase("OUTPUT_START", command=args.command)
    print(json.dumps(output, indent=2, sort_keys=True))
    _phase("OUTPUT_COMPLETE", command=args.command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
