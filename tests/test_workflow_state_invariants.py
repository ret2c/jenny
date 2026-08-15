from __future__ import annotations

import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tools.target_lifecycle import target_lifecycle


ROOT = Path(__file__).resolve().parents[1]
MAILBOX_TOOLS = ROOT / "tools" / "review_mailbox"
sys.path.insert(0, str(MAILBOX_TOOLS))

from candidate_challenge import CandidateChallengeStore  # noqa: E402
from review_mailbox import Mailbox, MailboxError  # noqa: E402


def test_midlane_cannot_report_idle_while_candidate_work_is_pending(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    database = tmp_path / "mailbox.sqlite3"
    mailbox = Mailbox(database, workspace)
    CandidateChallengeStore(database, workspace)
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO candidate_challenges(
                candidate_key, candidate_title, product, version, target_slug,
                goal_path, goal_hash, inventory_digest, root_family_id,
                dossier_path, dossier_sha256, dossier_json, state,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 'PENDING', ?, ?)
            """,
            (
                "candidate-one",
                "Candidate One",
                "Demo",
                "1.0",
                "demo",
                "targets/demo/GOAL.md",
                "a" * 64,
                "b" * 64,
                "demo-root",
                "targets/demo/private/candidate.json",
                "c" * 64,
                timestamp,
                timestamp,
            ),
        )
        connection.commit()

    with pytest.raises(MailboxError, match="Candidate Challenge 1 is ready"):
        mailbox.checkin(
            "midlane",
            "IDLE",
            "Wait for candidate or package review",
            "Blocking on the SQLite Midlane wake signal",
        )

    assert not any(
        worker["worker"] == "midlane" for worker in mailbox.status()["workers"]
    )


def test_activation_wording_is_natural_but_exact_target_bound() -> None:
    actions = (r"\bactivate\b", r"\bexecute\b", r"\bstart\b", r"\brun\b")

    assert target_lifecycle._instruction_affirmatively_names_target(
        "Please activate Example Server and begin the goal.",
        actions,
        {"example", "Example Server"},
    )
    assert not target_lifecycle._instruction_affirmatively_names_target(
        "Start the exampleish target.",
        actions,
        {"example", "Example Server"},
    )
    assert not target_lifecycle._instruction_affirmatively_names_target(
        "Do not activate Example Server.",
        actions,
        {"example", "Example Server"},
    )


def test_package_local_blocker_does_not_stop_unrelated_safe_hunt_work() -> None:
    contract = (
        ROOT / "tools" / "review_mailbox" / "role_operations" / "HUNTER_OPERATIONS.md"
    ).read_text(encoding="utf-8")

    assert "A package-local blocker does not make the active hunt IDLE" in contract
    assert "continue the active target's next safe goal-authorized lane" in contract
