from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_DB = (
    Path(__file__).resolve().parents[2]
    / "notes"
    / "coordination_inbox"
    / "coordination.sqlite3"
)
MESSAGE_TYPES = {"INFORMATION", "ACTION_REQUEST"}
SCOPE_KINDS = {"TARGET", "PACKAGE"}
DECISIONS = {"APPROVED", "DECLINED"}
OUTCOMES = {"ACKNOWLEDGED", "COMPLETED", "BLOCKED"}
OPEN_STATUSES = {"OPEN", "APPROVED"}
ROLE_LIMIT = 64
SCOPE_LIMIT = 256
TEXT_LIMIT = 2000
TEXT_FILE_BYTE_LIMIT = TEXT_LIMIT * 4
CHAT_ROUTES = {("operator", "midlane"), ("midlane", "operator")}


class CoordinationInboxError(RuntimeError):
    """A compact, operator-safe coordination error."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: object, field: str, limit: int, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise CoordinationInboxError(f"{field} must be text")
    normalized = value.strip()
    if not normalized:
        if optional:
            return None
        raise CoordinationInboxError(f"{field} is required")
    if len(normalized) > limit:
        raise CoordinationInboxError(f"{field} is too long")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in normalized):
        raise CoordinationInboxError(f"{field} contains control characters")
    return normalized


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise CoordinationInboxError(f"{field} must be a positive integer")
    return value


def _text_file(path: Path, field: str) -> str:
    resolved = path.resolve()
    if not resolved.is_file():
        raise CoordinationInboxError(f"{field} file is not a regular file")
    if resolved.stat().st_size > TEXT_FILE_BYTE_LIMIT:
        raise CoordinationInboxError(f"{field} file is too large")
    try:
        value = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise CoordinationInboxError(f"{field} file must be UTF-8 text") from error
    return _text(value, field, TEXT_LIMIT)


class CoordinationInbox:
    def __init__(self, database: str | Path = DEFAULT_DB) -> None:
        self.database = Path(database).resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS coordination_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    revision INTEGER NOT NULL DEFAULT 1,
                    message_type TEXT NOT NULL
                        CHECK (message_type IN ('INFORMATION','ACTION_REQUEST')),
                    sender TEXT NOT NULL DEFAULT 'midlane',
                    recipient TEXT NOT NULL DEFAULT 'hunter',
                    scope_kind TEXT NOT NULL
                        CHECK (scope_kind IN ('TARGET','PACKAGE')),
                    scope_ref TEXT NOT NULL,
                    body TEXT NOT NULL,
                    requested_action TEXT,
                    reply_to_id INTEGER REFERENCES coordination_messages(id),
                    operator_reply TEXT,
                    operator_decision TEXT
                        CHECK (operator_decision IS NULL OR operator_decision IN ('APPROVED','DECLINED')),
                    decision_reason TEXT,
                    hunter_outcome TEXT
                        CHECK (hunter_outcome IS NULL OR hunter_outcome IN ('ACKNOWLEDGED','COMPLETED','BLOCKED')),
                    hunter_detail TEXT,
                    status TEXT NOT NULL DEFAULT 'OPEN'
                        CHECK (status IN ('OPEN','APPROVED','DECLINED','ACKNOWLEDGED','COMPLETED','BLOCKED')),
                    delivered_revision INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    consumed_at TEXT,
                    decided_at TEXT,
                    resolved_at TEXT,
                    operator_dismissed_at TEXT
                )
                """
            )
            message_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(coordination_messages)"
                ).fetchall()
            }
            if "decided_at" not in message_columns:
                connection.execute(
                    "ALTER TABLE coordination_messages ADD COLUMN decided_at TEXT"
                )
                connection.execute(
                    """
                    UPDATE coordination_messages
                    SET decided_at = updated_at
                    WHERE operator_decision IS NOT NULL AND decided_at IS NULL
                    """
                )
            if "reply_to_id" not in message_columns:
                connection.execute(
                    "ALTER TABLE coordination_messages ADD COLUMN reply_to_id INTEGER "
                    "REFERENCES coordination_messages(id)"
                )
            if "operator_dismissed_at" not in message_columns:
                connection.execute(
                    "ALTER TABLE coordination_messages ADD COLUMN operator_dismissed_at TEXT"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS coordination_chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    revision INTEGER NOT NULL DEFAULT 1,
                    sender TEXT NOT NULL
                        CHECK (sender IN ('operator','midlane')),
                    recipient TEXT NOT NULL
                        CHECK (recipient IN ('operator','midlane')),
                    context_ref TEXT NOT NULL,
                    body TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('OPEN','ANSWERED','SENT')),
                    reply_to_id INTEGER REFERENCES coordination_chat_messages(id),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    answered_at TEXT
                )
                """
            )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            raise CoordinationInboxError("message not found")
        return dict(row)

    def _get_in(self, connection: sqlite3.Connection, message_id: int) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM coordination_messages WHERE id = ?", (message_id,)
        ).fetchone()
        return self._row(row)

    def get(self, message_id: int) -> dict[str, Any]:
        message_id = _positive_int(message_id, "message id")
        with closing(self._connect()) as connection, connection:
            return self._get_in(connection, message_id)

    def post(
        self,
        *,
        message_type: str,
        scope_kind: str,
        scope_ref: str,
        body: str,
        requested_action: str | None = None,
        sender: str = "midlane",
        recipient: str = "hunter",
        reply_to_id: int | None = None,
    ) -> dict[str, Any]:
        if message_type not in MESSAGE_TYPES:
            raise CoordinationInboxError("invalid message type")
        if scope_kind not in SCOPE_KINDS:
            raise CoordinationInboxError("invalid scope kind")
        sender_value = _text(sender, "sender", ROLE_LIMIT)
        recipient_value = _text(recipient, "recipient", ROLE_LIMIT)
        scope_value = _text(scope_ref, "scope reference", SCOPE_LIMIT)
        body_value = _text(body, "body", TEXT_LIMIT)
        action_value = _text(
            requested_action, "requested action", TEXT_LIMIT, optional=True
        )
        if message_type == "ACTION_REQUEST" and action_value is None:
            raise CoordinationInboxError("requested action is required")
        if message_type == "INFORMATION" and action_value is not None:
            raise CoordinationInboxError("information cannot request an action")
        timestamp = _now()
        with closing(self._connect()) as connection, connection:
            if reply_to_id is not None:
                reply_to_id = _positive_int(reply_to_id, "reply-to id")
                parent = self._get_in(connection, reply_to_id)
                if (
                    str(parent["scope_kind"]) != scope_kind
                    or str(parent["scope_ref"]) != scope_value
                ):
                    raise CoordinationInboxError("reply scope does not match parent")
            cursor = connection.execute(
                """
                INSERT INTO coordination_messages (
                    message_type, sender, recipient, scope_kind, scope_ref, body,
                    requested_action, created_at, updated_at, reply_to_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_type,
                    sender_value,
                    recipient_value,
                    scope_kind,
                    scope_value,
                    body_value,
                    action_value,
                    timestamp,
                    timestamp,
                    reply_to_id,
                ),
            )
            return self._get_in(connection, int(cursor.lastrowid))

    def list_open(self, *, limit: int = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoordinationInboxError("limit must be between 1 and 100")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM coordination_messages
                WHERE resolved_at IS NULL AND status IN ('OPEN','APPROVED')
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row(row) for row in rows]

    def list_for_dashboard(
        self,
        *,
        decision_cutoff: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        cutoff_value = _text(
            decision_cutoff,
            "decision cutoff",
            64,
        )
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoordinationInboxError("limit must be between 1 and 100")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM coordination_messages
                WHERE
                    operator_dismissed_at IS NULL
                    AND (
                    (status = 'OPEN' AND operator_decision IS NULL)
                    OR (
                        operator_decision IN ('APPROVED','DECLINED')
                        AND decided_at >= ?
                    )
                    )
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (cutoff_value, limit),
            ).fetchall()
        return [self._row(row) for row in rows]

    def link_reply(self, message_id: int, parent_id: int) -> dict[str, Any]:
        message_id = _positive_int(message_id, "message id")
        parent_id = _positive_int(parent_id, "parent id")
        if message_id == parent_id:
            raise CoordinationInboxError("message cannot reply to itself")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            message = self._get_in(connection, message_id)
            parent = self._get_in(connection, parent_id)
            if (
                message["scope_kind"] != parent["scope_kind"]
                or message["scope_ref"] != parent["scope_ref"]
            ):
                raise CoordinationInboxError("reply scope does not match parent")
            connection.execute(
                "UPDATE coordination_messages SET reply_to_id = ? WHERE id = ?",
                (parent_id, message_id),
            )
            return self._get_in(connection, message_id)

    def dismiss(self, message_id: int, expected_revision: int) -> dict[str, Any]:
        """Hide one item while preserving its closure and notifying Midlane."""
        message_id = _positive_int(message_id, "message id")
        expected_revision = _positive_int(expected_revision, "expected revision")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_in(connection, message_id)
            if int(current["revision"]) != expected_revision:
                raise CoordinationInboxError("message revision changed")
            if current.get("operator_dismissed_at"):
                raise CoordinationInboxError("message is already dismissed")
            timestamp = _now()
            is_action = current["message_type"] == "ACTION_REQUEST"
            status = "DECLINED" if is_action else "ACKNOWLEDGED"
            decision = "DECLINED" if is_action else None
            cursor = connection.execute(
                """
                UPDATE coordination_messages
                SET revision = revision + 1,
                    operator_decision = ?,
                    decision_reason = 'Operator closed this message from the dashboard.',
                    status = ?,
                    updated_at = ?,
                    decided_at = CASE WHEN ? IS NULL THEN decided_at ELSE ? END,
                    resolved_at = ?,
                    operator_dismissed_at = ?
                WHERE id = ? AND revision = ? AND operator_dismissed_at IS NULL
                """,
                (
                    decision,
                    status,
                    timestamp,
                    decision,
                    timestamp,
                    timestamp,
                    timestamp,
                    message_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise CoordinationInboxError("message revision changed")
            if str(current["sender"]).casefold() == "midlane":
                connection.execute(
                    """
                    INSERT INTO coordination_chat_messages (
                        sender, recipient, context_ref, body, status,
                        created_at, updated_at
                    ) VALUES ('operator', 'midlane', ?, ?, 'OPEN', ?, ?)
                    """,
                    (
                        f"{current['scope_kind']}:{current['scope_ref']}",
                        f"Operator closed coordination message #{message_id}; no further action is requested.",
                        timestamp,
                        timestamp,
                    ),
                )
            return self._get_in(connection, message_id)

    def reply(
        self,
        message_id: int,
        expected_revision: int,
        text: str,
    ) -> dict[str, Any]:
        message_id = _positive_int(message_id, "message id")
        expected_revision = _positive_int(expected_revision, "expected revision")
        reply_value = _text(text, "reply", TEXT_LIMIT)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_in(connection, message_id)
            if current["status"] != "OPEN":
                raise CoordinationInboxError("message is not open for reply")
            if int(current["revision"]) != expected_revision:
                raise CoordinationInboxError("message revision changed")
            timestamp = _now()
            cursor = connection.execute(
                """
                UPDATE coordination_messages
                SET revision = revision + 1,
                    operator_reply = ?,
                    operator_decision = NULL,
                    decision_reason = NULL,
                    updated_at = ?
                WHERE id = ? AND revision = ? AND status = 'OPEN'
                """,
                (reply_value, timestamp, message_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise CoordinationInboxError("message revision changed")
            return self._get_in(connection, message_id)

    def withdraw(
        self,
        message_id: int,
        expected_revision: int,
        sender: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Let the original sender retire an obsolete undecided request."""
        message_id = _positive_int(message_id, "message id")
        expected_revision = _positive_int(expected_revision, "expected revision")
        sender_value = _text(sender, "sender", ROLE_LIMIT)
        reason_value = _text(reason, "reason", TEXT_LIMIT, optional=True)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_in(connection, message_id)
            if current["message_type"] != "ACTION_REQUEST":
                raise CoordinationInboxError("only an action request can be withdrawn")
            if current["status"] != "OPEN" or current["operator_decision"] is not None:
                raise CoordinationInboxError("only an undecided open request can be withdrawn")
            if int(current["revision"]) != expected_revision:
                raise CoordinationInboxError("message revision changed")
            if str(current["sender"]).casefold() != str(sender_value).casefold():
                raise CoordinationInboxError("only the original sender can withdraw a request")
            timestamp = _now()
            detail = "Withdrawn by sender."
            if reason_value:
                detail += f" {reason_value}"
            cursor = connection.execute(
                """
                UPDATE coordination_messages
                SET revision = revision + 1,
                    decision_reason = ?,
                    status = 'DECLINED',
                    updated_at = ?,
                    resolved_at = ?
                WHERE id = ? AND revision = ? AND status = 'OPEN'
                  AND operator_decision IS NULL
                """,
                (detail, timestamp, timestamp, message_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise CoordinationInboxError("message revision changed")
            return self._get_in(connection, message_id)

    def decide(
        self,
        message_id: int,
        expected_revision: int,
        decision: str,
        reason: str = "",
    ) -> dict[str, Any]:
        message_id = _positive_int(message_id, "message id")
        expected_revision = _positive_int(expected_revision, "expected revision")
        if decision not in DECISIONS:
            raise CoordinationInboxError("invalid decision")
        reason_value = _text(reason, "reason", TEXT_LIMIT, optional=True)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_in(connection, message_id)
            if current["message_type"] != "ACTION_REQUEST":
                raise CoordinationInboxError("information cannot be approved or declined")
            if current["status"] != "OPEN":
                raise CoordinationInboxError("message is not open for decision")
            if int(current["revision"]) != expected_revision:
                raise CoordinationInboxError("message revision changed")
            timestamp = _now()
            resolved_at = timestamp if decision == "DECLINED" else None
            cursor = connection.execute(
                """
                UPDATE coordination_messages
                SET revision = revision + 1,
                    operator_decision = ?,
                    decision_reason = ?,
                    status = ?,
                    updated_at = ?,
                    decided_at = ?,
                    resolved_at = ?
                WHERE id = ? AND revision = ? AND status = 'OPEN'
                """,
                (
                    decision,
                    reason_value,
                    decision,
                    timestamp,
                    timestamp,
                    resolved_at,
                    message_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise CoordinationInboxError("message revision changed")
            return self._get_in(connection, message_id)

    def delta(self, consumer: str = "hunter", *, limit: int = 20) -> dict[str, Any]:
        consumer_value = _text(consumer, "consumer", ROLE_LIMIT)
        if consumer_value != "hunter":
            raise CoordinationInboxError("phase one supports only the hunter consumer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoordinationInboxError("limit must be between 1 and 100")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT * FROM coordination_messages
                WHERE recipient = 'hunter'
                  AND (
                    (message_type = 'INFORMATION' AND status = 'OPEN') OR
                    (message_type = 'ACTION_REQUEST' AND status = 'APPROVED')
                  )
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            messages = [self._row(row) for row in rows]
            timestamp = _now()
            for message in messages:
                if int(message["delivered_revision"]) >= int(message["revision"]):
                    continue
                cursor = connection.execute(
                    """
                    UPDATE coordination_messages
                    SET delivered_revision = revision,
                        consumed_at = ?,
                        updated_at = ?
                    WHERE id = ? AND revision = ? AND delivered_revision < revision
                    """,
                    (
                        timestamp,
                        timestamp,
                        int(message["id"]),
                        int(message["revision"]),
                    ),
                )
                if cursor.rowcount != 1:
                    raise CoordinationInboxError("message changed during delivery")
                message["delivered_revision"] = message["revision"]
                message["consumed_at"] = timestamp
                message["updated_at"] = timestamp
        return {"messages": messages}

    def record_outcome(
        self,
        message_id: int,
        expected_revision: int,
        outcome: str,
        detail: str = "",
    ) -> dict[str, Any]:
        message_id = _positive_int(message_id, "message id")
        expected_revision = _positive_int(expected_revision, "expected revision")
        if outcome not in OUTCOMES:
            raise CoordinationInboxError("invalid outcome")
        detail_value = _text(detail, "detail", TEXT_LIMIT, optional=True)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get_in(connection, message_id)
            if int(current["revision"]) != expected_revision:
                raise CoordinationInboxError("message revision changed")
            if int(current["delivered_revision"]) != expected_revision:
                raise CoordinationInboxError("message revision was not delivered")
            if current["message_type"] == "INFORMATION":
                if current["status"] != "OPEN" or outcome != "ACKNOWLEDGED":
                    raise CoordinationInboxError(
                        "information requires an acknowledged outcome"
                    )
            else:
                if current["status"] != "APPROVED" or outcome not in {
                    "COMPLETED",
                    "BLOCKED",
                }:
                    raise CoordinationInboxError(
                        "approved action requires completed or blocked outcome"
                    )
            timestamp = _now()
            cursor = connection.execute(
                """
                UPDATE coordination_messages
                SET hunter_outcome = ?,
                    hunter_detail = ?,
                    status = ?,
                    updated_at = ?,
                    resolved_at = ?
                WHERE id = ? AND revision = ? AND delivered_revision = ?
                """,
                (
                    outcome,
                    detail_value,
                    outcome,
                    timestamp,
                    timestamp,
                    message_id,
                    expected_revision,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise CoordinationInboxError("message changed during outcome recording")
            return self._get_in(connection, message_id)

    def chat_send(
        self,
        *,
        sender: str,
        recipient: str,
        context_ref: str,
        body: str,
    ) -> dict[str, Any]:
        sender_value = _text(sender, "sender", ROLE_LIMIT)
        recipient_value = _text(recipient, "recipient", ROLE_LIMIT)
        if (sender_value, recipient_value) not in CHAT_ROUTES:
            raise CoordinationInboxError("invalid chat route")
        context_value = _text(context_ref, "context reference", SCOPE_LIMIT)
        body_value = _text(body, "body", TEXT_LIMIT)
        status = "OPEN" if sender_value == "operator" else "SENT"
        timestamp = _now()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO coordination_chat_messages (
                    sender, recipient, context_ref, body, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sender_value,
                    recipient_value,
                    context_value,
                    body_value,
                    status,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM coordination_chat_messages WHERE id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
            return self._row(row)

    def chat_history(self, *, limit: int = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoordinationInboxError("limit must be between 1 and 100")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM (
                    SELECT * FROM coordination_chat_messages
                    ORDER BY id DESC LIMIT ?
                ) ORDER BY id ASC
                """,
                (limit,),
            ).fetchall()
        return [self._row(row) for row in rows]

    def chat_delta(self, consumer: str = "midlane", *, limit: int = 20) -> dict[str, Any]:
        consumer_value = _text(consumer, "consumer", ROLE_LIMIT)
        if consumer_value != "midlane":
            raise CoordinationInboxError("chat supports only the midlane consumer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoordinationInboxError("limit must be between 1 and 100")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM coordination_chat_messages
                WHERE sender = 'operator'
                  AND recipient = 'midlane'
                  AND status = 'OPEN'
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return {"messages": [self._row(row) for row in rows]}

    def chat_reply(
        self,
        message_id: int,
        expected_revision: int,
        body: str,
    ) -> dict[str, dict[str, Any]]:
        message_id = _positive_int(message_id, "message id")
        expected_revision = _positive_int(expected_revision, "expected revision")
        body_value = _text(body, "body", TEXT_LIMIT)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM coordination_chat_messages WHERE id = ?",
                (message_id,),
            ).fetchone()
            request = self._row(row)
            if (
                request["sender"] != "operator"
                or request["recipient"] != "midlane"
                or request["status"] != "OPEN"
            ):
                raise CoordinationInboxError("chat message is not open for reply")
            if int(request["revision"]) != expected_revision:
                raise CoordinationInboxError("chat message revision changed")
            timestamp = _now()
            updated = connection.execute(
                """
                UPDATE coordination_chat_messages
                SET revision = revision + 1,
                    status = 'ANSWERED',
                    updated_at = ?,
                    answered_at = ?
                WHERE id = ? AND revision = ? AND status = 'OPEN'
                """,
                (timestamp, timestamp, message_id, expected_revision),
            )
            if updated.rowcount != 1:
                raise CoordinationInboxError("chat message revision changed")
            cursor = connection.execute(
                """
                INSERT INTO coordination_chat_messages (
                    sender, recipient, context_ref, body, status, reply_to_id,
                    created_at, updated_at
                ) VALUES ('midlane', 'operator', ?, ?, 'SENT', ?, ?, ?)
                """,
                (
                    str(request["context_ref"]),
                    body_value,
                    message_id,
                    timestamp,
                    timestamp,
                ),
            )
            request_row = connection.execute(
                "SELECT * FROM coordination_chat_messages WHERE id = ?",
                (message_id,),
            ).fetchone()
            response_row = connection.execute(
                "SELECT * FROM coordination_chat_messages WHERE id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
            return {
                "request": self._row(request_row),
                "response": self._row(response_row),
            }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded Midlane-to-Hunter inbox")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    subparsers = parser.add_subparsers(dest="command", required=True)

    post = subparsers.add_parser("post")
    post.add_argument("--type", dest="message_type", required=True)
    post.add_argument("--sender", default="midlane")
    post.add_argument("--recipient", default="hunter")
    post.add_argument("--scope-kind", required=True)
    post.add_argument("--scope-ref", required=True)
    post.add_argument("--body", required=True)
    post.add_argument("--requested-action")
    post.add_argument("--reply-to", type=int)

    subparsers.add_parser("list-open")

    link_reply = subparsers.add_parser("link-reply")
    link_reply.add_argument("--id", type=int, required=True)
    link_reply.add_argument("--parent-id", type=int, required=True)

    dismiss = subparsers.add_parser("dismiss")
    dismiss.add_argument("--id", type=int, required=True)
    dismiss.add_argument("--revision", type=int, required=True)

    withdraw = subparsers.add_parser("withdraw")
    withdraw.add_argument("--id", type=int, required=True)
    withdraw.add_argument("--revision", type=int, required=True)
    withdraw.add_argument("--sender", required=True)
    withdraw.add_argument("--reason", default="")

    delta = subparsers.add_parser("delta")
    delta.add_argument("--consumer", default="hunter")

    outcome = subparsers.add_parser("outcome")
    outcome.add_argument("--id", dest="message_id", type=int, required=True)
    outcome.add_argument("--revision", type=int, required=True)
    outcome.add_argument("--outcome", required=True)
    outcome.add_argument("--detail", default="")

    chat_send = subparsers.add_parser("chat-send")
    chat_send.add_argument("--sender", required=True)
    chat_send.add_argument("--recipient", required=True)
    chat_send.add_argument("--context-ref", required=True)
    chat_send.add_argument("--body", required=True)

    chat_delta = subparsers.add_parser("chat-delta")
    chat_delta.add_argument("--consumer", default="midlane")

    chat_reply = subparsers.add_parser("chat-reply")
    chat_reply.add_argument("--id", dest="message_id", type=int, required=True)
    chat_reply.add_argument("--revision", type=int, required=True)
    chat_reply_body = chat_reply.add_mutually_exclusive_group(required=True)
    chat_reply_body.add_argument("--body")
    chat_reply_body.add_argument("--body-file", type=Path)

    subparsers.add_parser("chat-history")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        store = CoordinationInbox(args.db)
        if args.command == "post":
            result: object = store.post(
                message_type=args.message_type,
                scope_kind=args.scope_kind,
                scope_ref=args.scope_ref,
                body=args.body,
                requested_action=args.requested_action,
                sender=args.sender,
                recipient=args.recipient,
                reply_to_id=args.reply_to,
            )
        elif args.command == "link-reply":
            result = store.link_reply(args.id, args.parent_id)
        elif args.command == "dismiss":
            result = store.dismiss(args.id, args.revision)
        elif args.command == "withdraw":
            result = store.withdraw(
                args.id,
                args.revision,
                args.sender,
                args.reason,
            )
        elif args.command == "list-open":
            result = {"messages": store.list_open()}
        elif args.command == "delta":
            result = store.delta(args.consumer)
        elif args.command == "outcome":
            result = store.record_outcome(
                args.message_id,
                args.revision,
                args.outcome,
                args.detail,
            )
        elif args.command == "chat-send":
            result = store.chat_send(
                sender=args.sender,
                recipient=args.recipient,
                context_ref=args.context_ref,
                body=args.body,
            )
        elif args.command == "chat-delta":
            result = store.chat_delta(args.consumer)
        elif args.command == "chat-reply":
            body = (
                _text_file(args.body_file, "body")
                if args.body_file is not None
                else args.body
            )
            result = store.chat_reply(
                args.message_id,
                args.revision,
                body,
            )
        else:
            result = {"messages": store.chat_history()}
    except (CoordinationInboxError, OSError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
