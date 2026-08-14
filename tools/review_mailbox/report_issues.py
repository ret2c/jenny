from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCHEMA = "jenny.workflow-issue.v1"
EXPORT_SCHEMA = "jenny.workflow-issues-export.v1"
STATUSES = {"OPEN", "RESOLVED_AWAITING_OPERATOR_GREENLIGHT", "CLOSED"}
PRIORITIES = {"P0", "P1", "P2"}
_WRITE_LOCK = threading.RLock()


class ReportIssuesError(RuntimeError):
    pass


def _paths(workspace: Path) -> tuple[Path, Path, Path]:
    root = Path(workspace).resolve()
    return (
        root / "ZDI" / "REPORT_ISSUES.txt",
        root / "notes" / "report_issues" / "report_issues.sqlite3",
        root / "notes" / "report_issues" / "legacy",
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _ascii(value: object, field: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ReportIssuesError(f"{field} must be text")
    text = value.strip()
    if required and not text:
        raise ReportIssuesError(f"{field} is required")
    if "\x00" in text:
        raise ReportIssuesError(f"{field} contains a NUL byte")
    try:
        text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ReportIssuesError(f"{field} must contain ASCII text only") from error
    return text


def _goal_binding_evidence(
    workspace: Path,
    payload: dict[str, object],
    category: str,
) -> str:
    if category != "GOAL-INTEGRITY":
        return ""
    binding = payload.get("goal_binding")
    if not isinstance(binding, dict):
        raise ReportIssuesError(
            "GOAL-INTEGRITY issue requires a current goal_binding"
        )
    target_slug = _ascii(binding.get("target_slug"), "goal_binding.target_slug")
    expected_hash = _ascii(
        binding.get("goal_sha256"), "goal_binding.goal_sha256"
    ).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ReportIssuesError("goal_binding.goal_sha256 must be lowercase SHA-256")
    assertion = _ascii(binding.get("assertion"), "goal_binding.assertion").upper()
    if assertion not in {"TEXT_PRESENT", "TEXT_ABSENT"}:
        raise ReportIssuesError(
            "goal_binding.assertion must be TEXT_PRESENT or TEXT_ABSENT"
        )
    needle = _ascii(binding.get("needle"), "goal_binding.needle")
    line = binding.get("line")
    if assertion == "TEXT_PRESENT" and (not isinstance(line, int) or line < 1):
        raise ReportIssuesError(
            "TEXT_PRESENT goal binding requires a positive exact line"
        )

    database = (
        Path(workspace).resolve()
        / "notes"
        / "target_lifecycle"
        / "target_lifecycle.sqlite3"
    )
    if not database.is_file():
        raise ReportIssuesError("goal binding requires the target lifecycle database")
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT slug, status, goal_path, goal_sha256 FROM targets WHERE slug = ?",
            (target_slug,),
        ).fetchone()
    if row is None:
        raise ReportIssuesError(f"goal binding target is not recorded: {target_slug}")
    recorded_hash = str(row["goal_sha256"] or "").lower()
    if recorded_hash != expected_hash:
        raise ReportIssuesError("goal binding hash does not match lifecycle state")
    raw_goal_path = Path(str(row["goal_path"] or ""))
    goal_path = (
        raw_goal_path
        if raw_goal_path.is_absolute()
        else Path(workspace).resolve() / raw_goal_path
    )
    try:
        goal_bytes = goal_path.read_bytes()
        goal_text = goal_bytes.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ReportIssuesError(f"cannot read recorded goal bytes: {error}") from error
    actual_hash = _sha256(goal_bytes)
    if actual_hash != recorded_hash:
        raise ReportIssuesError("recorded goal bytes do not match lifecycle hash")
    lines = goal_text.splitlines()
    if assertion == "TEXT_PRESENT":
        assert isinstance(line, int)
        if line > len(lines) or needle not in lines[line - 1]:
            raise ReportIssuesError(
                "goal binding text is not present on the claimed current goal line"
            )
        line_text = str(line)
    else:
        if needle in goal_text:
            raise ReportIssuesError("goal binding text is present in current goal bytes")
        line_text = "n/a"
    return (
        f"Goal binding: target={target_slug}; sha256={actual_hash}; "
        f"assertion={assertion}; line={line_text}; needle={needle}"
    )


def _validate_payload(
    payload: dict[str, object], *, workspace: Path | None = None
) -> dict[str, str]:
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ReportIssuesError(f"issue payload schema must be {SCHEMA}")
    issue_key = _ascii(payload.get("issue_key"), "issue_key")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", issue_key):
        raise ReportIssuesError("issue_key must be a stable lowercase identifier")
    priority = _ascii(payload.get("priority"), "priority").upper()
    if priority not in PRIORITIES:
        raise ReportIssuesError("priority must be P0, P1, or P2")
    category = _ascii(payload.get("category"), "category").upper()
    binding_evidence = (
        _goal_binding_evidence(workspace, payload, category)
        if workspace is not None
        else ""
    )
    evidence = _ascii(payload.get("evidence"), "evidence")
    if binding_evidence:
        evidence = f"{evidence} {binding_evidence}"
    return {
        "issue_key": issue_key,
        "title": _ascii(payload.get("title"), "title"),
        "priority": priority,
        "category": category,
        "observed": _ascii(payload.get("observed"), "observed"),
        "impact": _ascii(payload.get("impact"), "impact"),
        "evidence": evidence,
        "next_action": _ascii(payload.get("next_action"), "next_action"),
        "owner": _ascii(payload.get("owner"), "owner"),
    }


def _connect(workspace: Path) -> sqlite3.Connection:
    _, database, _ = _paths(workspace)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS workflow_issues (
            id INTEGER PRIMARY KEY,
            issue_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            priority TEXT NOT NULL CHECK(priority IN ('P0','P1','P2')),
            category TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN (
                'OPEN','RESOLVED_AWAITING_OPERATOR_GREENLIGHT','CLOSED'
            )),
            observed TEXT NOT NULL,
            impact TEXT NOT NULL,
            evidence TEXT NOT NULL,
            next_action TEXT NOT NULL,
            owner TEXT NOT NULL,
            resolution TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            closed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS workflow_issue_events (
            id INTEGER PRIMARY KEY,
            issue_id INTEGER NOT NULL REFERENCES workflow_issues(id),
            actor TEXT NOT NULL,
            event_type TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS workflow_issue_events_issue_id
            ON workflow_issue_events(issue_id, id);
        """
    )
    columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(workflow_issues)").fetchall()
    }
    if "operator_acknowledged_at" not in columns:
        connection.execute(
            "ALTER TABLE workflow_issues ADD COLUMN operator_acknowledged_at TEXT"
        )
    return connection


@contextmanager
def _database(workspace: Path):
    connection = _connect(workspace)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _row(row: sqlite3.Row) -> dict[str, object]:
    return {key: row[key] for key in row.keys()}


def _event(
    connection: sqlite3.Connection,
    issue_id: int,
    actor: str,
    event_type: str,
    detail: str,
    timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO workflow_issue_events(issue_id, actor, event_type, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            issue_id,
            _ascii(actor, "actor"),
            _ascii(event_type, "event_type"),
            _ascii(detail, "detail", required=False),
            timestamp,
        ),
    )


def list_issues(
    *, workspace: Path, include_closed: bool = True
) -> list[dict[str, object]]:
    with _database(workspace) as connection:
        where = "" if include_closed else "WHERE status != 'CLOSED'"
        rows = connection.execute(
            f"""
            SELECT workflow_issues.*,
                   (
                       SELECT actor FROM workflow_issue_events
                       WHERE issue_id = workflow_issues.id
                         AND event_type = 'OPENED'
                       ORDER BY id LIMIT 1
                   ) AS reported_by
            FROM workflow_issues {where}
            ORDER BY CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 ELSE 2 END,
                     updated_at DESC, id DESC
            """
        ).fetchall()
    return [_row(row) for row in rows]


def issue_events(*, workspace: Path, issue_key: str) -> list[dict[str, object]]:
    with _database(workspace) as connection:
        rows = connection.execute(
            """
            SELECT e.* FROM workflow_issue_events e
            JOIN workflow_issues i ON i.id = e.issue_id
            WHERE i.issue_key = ? ORDER BY e.id
            """,
            (issue_key,),
        ).fetchall()
    return [_row(row) for row in rows]


def _export_bytes(workspace: Path) -> bytes:
    issues = list_issues(workspace=workspace, include_closed=False)
    lines = [
        "REPORT_ISSUES.txt - GENERATED BACKUP",
        "",
        "Source of truth: notes/report_issues/report_issues.sqlite3",
        "Do not edit this file directly. Use report_issues.py.",
        "",
    ]
    if not issues:
        lines.append("No open or awaiting-greenlight workflow issues.")
    for issue in issues:
        lines.extend(
            [
                f"{issue['title']}",
                "",
                f"Issue key: {issue['issue_key']}",
                f"Status: {issue['status']}",
                f"Priority: {issue['priority']}",
                f"Category: {issue['category']}",
                f"Observed: {issue['observed']}",
                f"Impact: {issue['impact']}",
                f"Evidence: {issue['evidence']}",
                f"Next action: {issue['next_action']}",
                f"Owner: {issue['owner']}",
            ]
        )
        if issue["resolution"]:
            lines.append(f"Resolution: {issue['resolution']}")
        lines.extend(
            [
                f"Created at: {issue['created_at']}",
                f"Updated at: {issue['updated_at']}",
                "",
            ]
        )
    return ("\n".join(lines).rstrip() + "\n").encode("ascii")


def export_ledger(*, workspace: Path) -> dict[str, object]:
    ledger, _, _ = _paths(workspace)
    data = _export_bytes(workspace)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    temporary = ledger.with_name(
        f"{ledger.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.write_bytes(data)
    os.replace(temporary, ledger)
    return {"bytes": len(data), "sha256": _sha256(data), "path": str(ledger)}


def verify_export(*, workspace: Path) -> dict[str, object]:
    ledger, _, _ = _paths(workspace)
    expected = _export_bytes(workspace)
    actual = ledger.read_bytes() if ledger.is_file() else b""
    return {
        "matches": actual == expected,
        "expected_bytes": len(expected),
        "expected_sha256": _sha256(expected),
        "actual_bytes": len(actual),
        "actual_sha256": _sha256(actual),
    }


def record_issue(
    *, workspace: Path, payload: dict[str, object], actor: str
) -> dict[str, object]:
    issue = _validate_payload(payload, workspace=workspace)
    timestamp = _now()
    with _WRITE_LOCK:
        with _database(workspace) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM workflow_issues WHERE issue_key = ?",
                (issue["issue_key"],),
            ).fetchone()
            created = existing is None
            if created:
                cursor = connection.execute(
                    """
                    INSERT INTO workflow_issues(
                        issue_key, title, priority, category, status, observed,
                        impact, evidence, next_action, owner, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        issue["issue_key"], issue["title"], issue["priority"],
                        issue["category"], issue["observed"], issue["impact"],
                        issue["evidence"], issue["next_action"], issue["owner"],
                        timestamp, timestamp,
                    ),
                )
                issue_id = int(cursor.lastrowid)
                event_type = "OPENED"
            else:
                issue_id = int(existing["id"])
                material_change = existing["status"] != "OPEN" or any(
                    existing[field] != issue[field]
                    for field in (
                        "title", "priority", "category", "observed", "impact",
                        "evidence", "next_action", "owner",
                    )
                )
                if material_change:
                    connection.execute(
                        """
                        UPDATE workflow_issues SET
                            title = ?, priority = ?, category = ?, status = 'OPEN',
                            observed = ?, impact = ?, evidence = ?, next_action = ?,
                            owner = ?, resolution = '', resolved_at = NULL,
                            closed_at = NULL, operator_acknowledged_at = NULL,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            issue["title"], issue["priority"], issue["category"],
                            issue["observed"], issue["impact"], issue["evidence"],
                            issue["next_action"], issue["owner"], timestamp, issue_id,
                        ),
                    )
                    event_type = "UPDATED"
                else:
                    event_type = ""
            if event_type:
                _event(
                    connection, issue_id, actor, event_type,
                    issue["next_action"], timestamp,
                )
            row = connection.execute(
                "SELECT * FROM workflow_issues WHERE id = ?", (issue_id,)
            ).fetchone()
        export_ledger(workspace=workspace)
    result = _row(row)
    result["created"] = created
    return result


def resolve_issue(
    *, workspace: Path, issue_key: str, resolution: str, actor: str
) -> dict[str, object]:
    resolution = _ascii(resolution, "resolution")
    timestamp = _now()
    with _WRITE_LOCK:
        with _database(workspace) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT id, status FROM workflow_issues WHERE issue_key = ?",
                (issue_key,),
            ).fetchone()
            if row is None:
                raise ReportIssuesError(f"unknown issue_key: {issue_key}")
            if row["status"] == "CLOSED":
                raise ReportIssuesError("closed issue cannot be resolved again")
            connection.execute(
                """
                UPDATE workflow_issues SET
                    status = 'RESOLVED_AWAITING_OPERATOR_GREENLIGHT',
                    resolution = ?, resolved_at = ?, updated_at = ?,
                    operator_acknowledged_at = NULL
                WHERE id = ?
                """,
                (resolution, timestamp, timestamp, row["id"]),
            )
            _event(connection, int(row["id"]), actor, "RESOLVED", resolution, timestamp)
            updated = connection.execute(
                "SELECT * FROM workflow_issues WHERE id = ?", (row["id"],)
            ).fetchone()
        export_ledger(workspace=workspace)
    return _row(updated)


def acknowledge_issues(
    *,
    workspace: Path,
    issue_snapshots: list[dict[str, object]],
    actor: str = "operator",
) -> dict[str, object]:
    if not issue_snapshots:
        raise ReportIssuesError("at least one issue snapshot is required")
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, snapshot in enumerate(issue_snapshots):
        if not isinstance(snapshot, dict):
            raise ReportIssuesError(f"issue snapshot {index} must be an object")
        issue_key = _ascii(snapshot.get("issue_key"), f"issues[{index}].issue_key")
        updated_at = _ascii(snapshot.get("updated_at"), f"issues[{index}].updated_at")
        if issue_key in seen:
            raise ReportIssuesError(f"duplicate issue snapshot: {issue_key}")
        seen.add(issue_key)
        normalized.append((issue_key, updated_at))

    timestamp = _now()
    with _WRITE_LOCK:
        with _database(workspace) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows: list[sqlite3.Row] = []
            for issue_key, expected_updated_at in normalized:
                row = connection.execute(
                    "SELECT * FROM workflow_issues WHERE issue_key = ?",
                    (issue_key,),
                ).fetchone()
                if row is None or row["status"] == "CLOSED":
                    raise ReportIssuesError(f"active issue snapshot no longer exists: {issue_key}")
                if row["updated_at"] != expected_updated_at:
                    raise ReportIssuesError(f"issue snapshot changed before acknowledgement: {issue_key}")
                rows.append(row)
            for row in rows:
                connection.execute(
                    "UPDATE workflow_issues SET operator_acknowledged_at = ? WHERE id = ?",
                    (timestamp, row["id"]),
                )
                _event(
                    connection,
                    int(row["id"]),
                    actor,
                    "ACKNOWLEDGED",
                    "Operator acknowledged dashboard visibility.",
                    timestamp,
                )
    return {
        "acknowledged": len(normalized),
        "acknowledged_at": timestamp,
        "issue_keys": [issue_key for issue_key, _ in normalized],
    }


def greenlight_issue(
    *, workspace: Path, issue_key: str, actor: str
) -> dict[str, object]:
    timestamp = _now()
    with _WRITE_LOCK:
        with _database(workspace) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT id, status FROM workflow_issues WHERE issue_key = ?",
                (issue_key,),
            ).fetchone()
            if row is None:
                raise ReportIssuesError(f"unknown issue_key: {issue_key}")
            if row["status"] != "RESOLVED_AWAITING_OPERATOR_GREENLIGHT":
                raise ReportIssuesError("only an awaiting-greenlight issue may close")
            connection.execute(
                """
                UPDATE workflow_issues SET status = 'CLOSED', closed_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (timestamp, timestamp, row["id"]),
            )
            _event(
                connection, int(row["id"]), actor, "GREENLIT_CLOSED",
                "Operator greenlight recorded.", timestamp,
            )
            updated = connection.execute(
                "SELECT * FROM workflow_issues WHERE id = ?", (row["id"],)
            ).fetchone()
        export_ledger(workspace=workspace)
    return _row(updated)


def _slug(value: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:96]
    return base or "legacy-workflow-issue"


def _legacy_next_action(entry: dict[str, str], default: str) -> str:
    action = entry.get("next action", entry.get("required repair", default))
    direction = entry.get("operator direction", "").strip()
    if direction:
        action = f"{action} Operator direction: {direction}"
    return action


def _legacy_entries(text: str) -> list[dict[str, str]]:
    # Legacy entries always began with a timestamped heading.  Restrict the
    # split to that shape so ordinary field/value lines are not mistaken for
    # entry boundaries.
    header = re.compile(
        r"(?m)^\d{4}-\d{2}-\d{2}[^\n]*?\s+-\s+([^\n]+?)\s*$"
    )
    starts = list(header.finditer(text))
    parsed: list[dict[str, str]] = []
    for index, match in enumerate(starts):
        body_start = match.end()
        body_end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        body = text[body_start:body_end]
        fields: dict[str, str] = {}
        current = ""
        for raw_line in body.splitlines():
            field_match = re.match(r"^([A-Za-z][A-Za-z _-]+):\s*(.*)$", raw_line)
            if field_match:
                current = field_match.group(1).strip().lower()
                fields[current] = field_match.group(2).strip()
            elif current and raw_line.strip():
                fields[current] += " " + raw_line.strip()
        if "status" in fields or "observed" in fields:
            parsed.append({"title": match.group(1).strip(), **fields})
    return parsed


def migrate_legacy(*, workspace: Path, actor: str) -> dict[str, object]:
    ledger, database, archive_dir = _paths(workspace)
    if database.is_file() and list_issues(workspace=workspace):
        raise ReportIssuesError("SQLite issue ledger already contains records")
    source = ledger.read_bytes() if ledger.is_file() else b""
    try:
        text = source.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReportIssuesError("legacy REPORT_ISSUES must be ASCII") from error
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    archive = archive_dir / f"REPORT_ISSUES.{stamp}.{_sha256(source)[:12]}.txt"
    archive.write_bytes(source)
    entries = _legacy_entries(text)
    if source and not entries:
        entries = [{
            "title": "Legacy REPORT_ISSUES content",
            "priority": "P1",
            "observed": "Legacy content could not be split into structured entries.",
            "impact": "The historical workflow issue remains preserved for manual review.",
            "evidence": str(archive),
            "next action": "Workflow owner must review the archived legacy text.",
        }]
    imported = 0
    for entry in entries:
        title = entry["title"]
        key = f"{_slug(title)}-{_sha256(title.encode('ascii'))[:8]}"
        record_issue(
            workspace=workspace,
            actor=actor,
            payload={
                "schema": SCHEMA,
                "issue_key": key,
                "title": title,
                "priority": entry.get("priority", "P1"),
                "category": "LEGACY_MIGRATION",
                "observed": entry.get("observed", "Legacy workflow issue."),
                "impact": entry.get("impact", "Legacy impact requires review."),
                "evidence": entry.get("evidence", str(archive)),
                "next_action": _legacy_next_action(
                    entry, "Workflow owner must review this issue."
                ),
                "owner": "workflow-owner",
            },
        )
        imported += 1
    export = export_ledger(workspace=workspace)
    return {
        "imported": imported,
        "archive_path": str(archive),
        "archive_sha256": _sha256(source),
        "export": export,
    }


def _payload_from_legacy_entry(entry: str) -> dict[str, str]:
    entries = _legacy_entries(entry.strip() + "\n")
    if not entries:
        raise ReportIssuesError("legacy entry does not match the documented format")
    item = entries[0]
    title = item["title"]
    return {
        "schema": SCHEMA,
        "issue_key": f"{_slug(title)}-{_sha256(title.encode('ascii'))[:8]}",
        "title": title,
        "priority": item.get("priority", "P1"),
        "category": "WORKFLOW_STATE",
        "observed": item.get("observed", "Legacy workflow issue."),
        "impact": item.get("impact", "Workflow integrity may be affected."),
        "evidence": item.get("evidence", "Legacy entry."),
        "next_action": _legacy_next_action(item, "Workflow owner must review."),
        "owner": "workflow-owner",
    }


def append_entry(*, workspace: Path, entry: str) -> dict[str, object]:
    """Compatibility shim: parse an old entry and upsert it into SQLite."""
    return record_issue(
        workspace=workspace,
        payload=_payload_from_legacy_entry(entry),
        actor="legacy-append-compatibility",
    )


def initialize_guard(*, workspace: Path, expected_sha256: str) -> dict[str, object]:
    ledger, database, _ = _paths(workspace)
    if database.is_file():
        return verify_export(workspace=workspace)
    if not ledger.is_file() or _sha256(ledger.read_bytes()) != expected_sha256.lower():
        raise ReportIssuesError("ledger does not match the authorized baseline hash")
    return migrate_legacy(workspace=workspace, actor="legacy-initialize")


def verify_guard(*, workspace: Path) -> dict[str, object]:
    """Compatibility alias for the old guard verifier."""
    result = verify_export(workspace=workspace)
    if not result["matches"]:
        raise ReportIssuesError("generated REPORT_ISSUES export does not match SQLite")
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportIssuesError(f"cannot read JSON input: {error}") from error
    if not isinstance(payload, dict):
        raise ReportIssuesError("JSON input must be an object")
    return payload


def main() -> int:
    workspace_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="SQLite-first workflow issue ledger")
    parser.add_argument("--workspace", type=Path, default=workspace_default)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    record.add_argument("--issue-file", type=Path, required=True)
    record.add_argument("--actor", required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--issue-key", required=True)
    resolve.add_argument("--resolution-file", type=Path, required=True)
    resolve.add_argument("--actor", required=True)
    greenlight = commands.add_parser("greenlight")
    greenlight.add_argument("--issue-key", required=True)
    greenlight.add_argument("--actor", default="operator")
    acknowledge = commands.add_parser("acknowledge")
    acknowledge.add_argument("--issues-file", type=Path, required=True)
    acknowledge.add_argument("--actor", default="operator")
    listing = commands.add_parser("list")
    listing.add_argument("--include-closed", action="store_true")
    commands.add_parser("export")
    commands.add_parser("verify")
    migrate = commands.add_parser("migrate")
    migrate.add_argument("--actor", default="workflow-owner")
    initialize = commands.add_parser("initialize")
    initialize.add_argument("--expected-sha256", required=True)
    append = commands.add_parser("append")
    append.add_argument("--entry-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "record":
            result = record_issue(
                workspace=args.workspace,
                payload=_read_json(args.issue_file),
                actor=args.actor,
            )
        elif args.command == "resolve":
            result = resolve_issue(
                workspace=args.workspace,
                issue_key=args.issue_key,
                resolution=args.resolution_file.read_text(encoding="ascii"),
                actor=args.actor,
            )
        elif args.command == "greenlight":
            result = greenlight_issue(
                workspace=args.workspace,
                issue_key=args.issue_key,
                actor=args.actor,
            )
        elif args.command == "acknowledge":
            payload = _read_json(args.issues_file)
            issue_snapshots = payload.get("issues")
            if not isinstance(issue_snapshots, list):
                raise ReportIssuesError("acknowledgement JSON must contain an issues list")
            result = acknowledge_issues(
                workspace=args.workspace,
                issue_snapshots=issue_snapshots,
                actor=args.actor,
            )
        elif args.command == "list":
            result = list_issues(
                workspace=args.workspace, include_closed=args.include_closed
            )
        elif args.command == "export":
            result = export_ledger(workspace=args.workspace)
        elif args.command == "verify":
            result = verify_export(workspace=args.workspace)
            if not result["matches"]:
                raise ReportIssuesError("generated export does not match SQLite")
        elif args.command == "migrate":
            result = migrate_legacy(workspace=args.workspace, actor=args.actor)
        elif args.command == "initialize":
            result = initialize_guard(
                workspace=args.workspace, expected_sha256=args.expected_sha256
            )
        else:
            result = append_entry(
                workspace=args.workspace,
                entry=args.entry_file.read_text(encoding="ascii"),
            )
    except (OSError, UnicodeError, sqlite3.Error, ReportIssuesError) as error:
        parser.exit(2, f"error: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
