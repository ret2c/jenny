from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL_DIR = ROOT / "tools" / "review_mailbox"
sys.path.insert(0, str(TOOL_DIR))

import bounded_text_repair  # noqa: E402
import package_safety  # noqa: E402
from review_mailbox import Mailbox  # noqa: E402


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_package(workspace: Path) -> Path:
    package = workspace / "ZDI_STAGING" / "202_Demo_Citation_Repair"
    loose = package / "folder_of_everything_necessary"
    loose.mkdir(parents=True)
    description = package / "demo_citation_repair_description.txt"
    description.write_text(
        "Reference: https://invalid.example/advisory\n", encoding="utf-8"
    )
    evidence = loose / "impact_proof.txt"
    evidence.write_text("technical proof unchanged\n", encoding="utf-8")
    duplicate = loose / "duplicate_and_staleness_review.txt"
    duplicate.write_text("No collision.\n", encoding="utf-8")
    (loose / "SHA256SUMS.txt").write_text(
        f"{sha256(duplicate)}  {duplicate.name}\n"
        f"{sha256(evidence)}  {evidence.name}\n",
        encoding="utf-8",
    )
    archive = package / "demo_citation_repair_evidence.zip"
    package_safety.atomic_rebuild_zip(loose, archive)
    (package / "PACKAGE_HASHES.txt").write_text(
        f"{sha256(description)}  {description.name}\n"
        f"{sha256(archive)}  {archive.name}\n",
        encoding="utf-8",
    )
    return package


def test_each_replacement_is_rechecked_at_application_time(tmp_path: Path) -> None:
    package = tmp_path / "202_Demo_Citation_Repair"
    package.mkdir()
    description = package / "demo_citation_repair_description.txt"
    description.write_text("alpha beta\n", encoding="utf-8")
    payload = {
        "replacements": [
            {"path": description.name, "old": "alpha beta", "new": "alpha"},
            {"path": description.name, "old": "beta", "new": "gamma"},
        ]
    }

    with pytest.raises(
        bounded_text_repair.RepairError,
        match="repair old text must occur exactly once at application time",
    ):
        bounded_text_repair._apply_exact_replacements(package, payload)


def test_audit_failure_rolls_back_package_and_mailbox_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    database = workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
    package = make_package(workspace)
    mailbox = Mailbox(database, workspace)
    item = mailbox.register(package, "Demo", "1.0", "ready")
    mailbox.claim_next_detailed()
    repair_file = (
        workspace
        / "scratch"
        / "review_mailbox"
        / "bounded_repair_requests"
        / "item_1_demo.json"
    )
    repair_file.parent.mkdir(parents=True)
    repair_file.write_text(
        json.dumps(
            {
                "schema": "jenny.bounded-text-repair.v1",
                "item_id": item["id"],
                "revision": item["revision"],
                "reviewed_hash": item["package_hash"],
                "reason": "Correct one unrelated public advisory URL.",
                "technical_gates_passed": True,
                "replacements": [
                    {
                        "path": "demo_citation_repair_description.txt",
                        "old": "https://invalid.example/advisory",
                        "new": "https://correct.example/advisory",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bounded_text_repair,
        "_run_mechanical_gates",
        lambda *_args: [
            {"id": gate_id, "status": "PASS", "exit_code": 0}
            for gate_id in bounded_text_repair.MECHANICAL_GATE_IDS
        ],
    )

    def fail_audit(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated audit write failure")

    monkeypatch.setattr(bounded_text_repair, "_atomic_json", fail_audit)

    with pytest.raises(OSError, match="simulated audit write failure"):
        bounded_text_repair.apply_repair(workspace, database, repair_file)

    current = mailbox.get_item(int(item["id"]))
    assert current["state"] == "MIDLANE_REVIEWING"
    assert current["revision"] == item["revision"]
    assert current["package_hash"] == item["package_hash"]
    assert Path(current["package_path"]) == package.resolve()
    assert mailbox._hash_package(package) == item["package_hash"]
    assert not (workspace / "ZDI" / package.name).exists()
