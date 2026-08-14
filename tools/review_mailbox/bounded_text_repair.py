from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

from package_preflight import MECHANICAL_GATE_IDS as _MECHANICAL_GATE_IDS
from package_preflight import _run_mechanical_gates
from package_safety import atomic_reseal_package, validate_submission_package
from review_mailbox import Mailbox, MailboxError, utc_now
from bounded_repair_contract import (
    SCHEMA,
    BoundedRepairContractError,
    allowed_paths,
    extract_repair_input_path,
    load_repair_input,
    validate_replacement_targets,
)


MECHANICAL_GATE_IDS = _MECHANICAL_GATE_IDS


class RepairError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"), key=lambda value: value.as_posix())
        if path.is_file()
    }


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _load_input(workspace: Path, input_path: Path) -> dict[str, Any]:
    try:
        return load_repair_input(workspace, input_path)
    except BoundedRepairContractError as error:
        raise RepairError(str(error)) from error


def _allowed_paths(package: Path) -> set[str]:
    try:
        return allowed_paths(package)
    except BoundedRepairContractError as error:
        raise RepairError(str(error)) from error


def _apply_exact_replacements(candidate: Path, payload: dict[str, Any]) -> list[str]:
    try:
        changed = validate_replacement_targets(candidate, payload)
    except BoundedRepairContractError as error:
        raise RepairError(str(error)) from error
    for replacement in payload["replacements"]:
        relative = Path(replacement["path"])
        target = candidate / relative
        text = target.read_text(encoding="utf-8")
        target.write_text(
            text.replace(replacement["old"], replacement["new"], 1),
            encoding="utf-8",
            newline="\n",
        )
    return changed


def apply_repair(
    workspace: str | Path,
    db_path: str | Path,
    input_path: str | Path,
) -> dict[str, Any]:
    root = Path(workspace).resolve()
    input_file = Path(input_path).resolve()
    payload = _load_input(root, input_file)
    mailbox = Mailbox(db_path, root)
    item_id = int(payload["item_id"])
    item = mailbox.get_item(item_id)
    if item["state"] not in {"MIDLANE_REVIEWING", "FINAL_REWORK_QUEUED"}:
        raise RepairError(
            "bounded repair requires MIDLANE_REVIEWING or FINAL_REWORK_QUEUED"
        )
    if (
        int(item["revision"]) != int(payload["revision"])
        or item["package_hash"] != payload["reviewed_hash"]
    ):
        raise RepairError("repair input is stale for the current revision")
    original = Path(item["package_path"]).resolve()
    if mailbox._hash_package(original) != payload["reviewed_hash"]:
        raise RepairError("package bytes drifted before bounded repair")
    input_relative = input_file.relative_to(root).as_posix()

    work_root = (
        root
        / "scratch"
        / "review_mailbox"
        / "bounded_repairs"
        / f"item-{item_id}-{uuid.uuid4().hex}"
    )
    candidate = work_root / "candidate" / original.name
    backup = work_root / "original" / original.name
    candidate.parent.mkdir(parents=True)
    shutil.copytree(original, candidate)
    before = _tree_hashes(original)
    moved_destination: Path | None = None
    committed = False
    try:
        changed_paths = _apply_exact_replacements(candidate, payload)
        atomic_reseal_package(candidate)
        validate_submission_package(candidate)
        mechanical_gates = _run_mechanical_gates(root, candidate, 300)
        failed_gates = [
            result["id"]
            for result in mechanical_gates
            if result.get("status") != "PASS"
        ]
        if failed_gates:
            raise RepairError(
                "bounded repair failed mechanical gates: "
                + ", ".join(failed_gates)
            )
        after = _tree_hashes(candidate)
        if set(before) != set(after):
            raise RepairError("bounded repair changed the package file list")
        archive = next(candidate.glob("*.zip")).name
        permitted_changes = set(changed_paths) | {
            "PACKAGE_HASHES.txt",
            archive,
            "folder_of_everything_necessary/SHA256SUMS.txt",
        }
        observed_changes = {
            relative for relative in before if before[relative] != after[relative]
        }
        unexpected = observed_changes - permitted_changes
        if unexpected:
            raise RepairError(
                "bounded repair changed non-allowlisted files: " + ", ".join(sorted(unexpected))
            )
        new_hash = mailbox._hash_package(candidate)
        new_manifest = json.dumps(mailbox._manifest_package(candidate), sort_keys=True)
        timestamp = utc_now()
        destination = (root / "ZDI" / original.name).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise RepairError(f"final-review destination already exists: {destination}")

        with mailbox._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = mailbox._get_item(connection, item_id)
            if (
                current["state"] != item["state"]
                or current["package_hash"] != payload["reviewed_hash"]
                or int(current["revision"]) != int(payload["revision"])
                or mailbox._hash_package(original) != payload["reviewed_hash"]
            ):
                raise RepairError("package state changed during bounded repair")
            request_id: int | None = None
            if current["state"] == "FINAL_REWORK_QUEUED":
                row = connection.execute(
                    "SELECT id, issues_json, review_scope FROM final_rework_requests "
                    "WHERE work_item_id = ? AND state = 'OPEN' ORDER BY id DESC LIMIT 1",
                    (item_id,),
                ).fetchone()
                if row is None:
                    raise RepairError("queued mechanical repair has no open request")
                issues = json.loads(row["issues_json"])
                if row["review_scope"] != "MECHANICAL":
                    raise RepairError("final rework request is not MECHANICAL")
                if extract_repair_input_path(issues) != input_relative:
                    raise RepairError(
                        "mechanical rework request is not bound to this repair input"
                    )
                request_id = int(row["id"])

            backup.parent.mkdir(parents=True)
            original.rename(backup)
            try:
                candidate.rename(destination)
                moved_destination = destination
                new_revision = int(current["revision"]) + 1
                connection.execute(
                    """
                    UPDATE work_items
                    SET package_path = ?, package_hash = ?, reviewed_hash = ?,
                        state = 'AWAITING_FINAL_REVIEW', revision = ?,
                        review_summary = ?, hold_reason = '', closure_completed = 0,
                        claimed_at = NULL, package_manifest_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        str(destination),
                        new_hash,
                        new_hash,
                        new_revision,
                        f"BOUNDED_TEXT_REPAIR: {payload['reason'].strip()}",
                        new_manifest,
                        timestamp,
                        item_id,
                    ),
                )
                if request_id is not None:
                    connection.execute(
                        """
                        UPDATE final_rework_requests
                        SET state = 'ADDRESSED', addressed_hash = ?,
                            addressed_revision = ?, addressed_at = ?
                        WHERE id = ?
                        """,
                        (new_hash, new_revision, timestamp, request_id),
                    )
                mailbox._set_worker_status(
                    connection,
                    "midlane",
                    "IDLE",
                    f"Bounded text repair item {item_id} complete",
                    "New revision is awaiting independent Final Review.",
                    timestamp,
                )
                mailbox._event(
                    connection,
                    item_id,
                    "midlane",
                    "BOUNDED_TEXT_REPAIR",
                    {
                        "changed_paths": changed_paths,
                        "from_hash": payload["reviewed_hash"],
                        "input_sha256": _sha256(input_file),
                        "request_id": request_id,
                        "revision": new_revision,
                        "to_hash": new_hash,
                    },
                )
                result_item = mailbox._get_item(connection, item_id)
            except Exception:
                if moved_destination is not None and moved_destination.exists():
                    moved_destination.rename(candidate)
                    moved_destination = None
                if backup.exists() and not original.exists():
                    backup.rename(original)
                raise

        committed = True

        audit_path = (
            root
            / "scratch"
            / "review_mailbox"
            / "bounded_repair_audit"
            / f"item_{item_id}_revision_{result_item['revision']}.json"
        )
        audit = {
            "schema": SCHEMA,
            "status": "PASS",
            "item_id": item_id,
            "from_hash": payload["reviewed_hash"],
            "to_hash": result_item["package_hash"],
            "changed_paths": changed_paths,
            "unexpected_changes": [],
            "input_sha256": _sha256(input_file),
            "mechanical_gates": [
                {
                    "id": result["id"],
                    "status": result["status"],
                    "exit_code": result.get("exit_code"),
                }
                for result in mechanical_gates
            ],
        }
        _atomic_json(audit_path, audit)
        return {"item": result_item, "audit_path": str(audit_path), "audit": audit}
    finally:
        if not committed:
            if moved_destination is not None and moved_destination.exists():
                moved_destination.rename(candidate)
            if backup.exists() and not original.exists():
                backup.rename(original)
        if work_root.exists():
            shutil.rmtree(work_root)


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Apply one audited mechanical text-only repair")
    parser.add_argument("--workspace", type=Path, default=workspace)
    parser.add_argument(
        "--db",
        type=Path,
        default=workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
    )
    parser.add_argument("--input", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = apply_repair(args.workspace, args.db, args.input)
    except (OSError, UnicodeError, ValueError, MailboxError, RepairError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
