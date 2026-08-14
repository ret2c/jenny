from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "jenny.bounded-text-repair.v1"
MAX_REPLACEMENTS = 4
MAX_TEXT_BUDGET = 16_000
_INPUT_PATTERN = re.compile(
    r"scratch/review_mailbox/bounded_repair_requests/[A-Za-z0-9_.-]+\.json"
)


class BoundedRepairContractError(RuntimeError):
    pass


def extract_repair_input_path(issues: object) -> str | None:
    if not isinstance(issues, list) or not issues:
        return None
    bound_path: str | None = None
    for issue in issues:
        if not isinstance(issue, dict):
            return None
        issue_id = issue.get("id")
        action = issue.get("action")
        if (
            not isinstance(issue_id, str)
            or not issue_id.startswith("MECHANICAL_")
            or not isinstance(action, str)
        ):
            return None
        matches = set(_INPUT_PATTERN.findall(action.replace("\\", "/")))
        if len(matches) != 1:
            return None
        current = matches.pop()
        if bound_path is None:
            bound_path = current
        elif current != bound_path:
            return None
    return bound_path


def load_repair_input(workspace: Path, input_path: Path) -> dict[str, Any]:
    root = workspace.resolve()
    resolved = input_path.resolve()
    request_root = (
        root / "scratch" / "review_mailbox" / "bounded_repair_requests"
    ).resolve()
    try:
        resolved.relative_to(request_root)
    except ValueError as error:
        raise BoundedRepairContractError(
            "repair input must stay in scratch/review_mailbox/bounded_repair_requests"
        ) from error
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BoundedRepairContractError(f"cannot read repair input: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise BoundedRepairContractError("repair input schema is invalid")
    if payload.get("technical_gates_passed") is not True:
        raise BoundedRepairContractError(
            "bounded repair requires technical_gates_passed=true"
        )
    for field in ("item_id", "revision"):
        if isinstance(payload.get(field), bool) or not isinstance(payload.get(field), int):
            raise BoundedRepairContractError(
                f"repair input {field} must be an integer"
            )
    if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("reviewed_hash", ""))):
        raise BoundedRepairContractError("repair input reviewed_hash is invalid")
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise BoundedRepairContractError("repair reason must be 1-500 characters")
    replacements = payload.get("replacements")
    if (
        not isinstance(replacements, list)
        or not 1 <= len(replacements) <= MAX_REPLACEMENTS
    ):
        raise BoundedRepairContractError(
            f"repair requires 1-{MAX_REPLACEMENTS} replacements"
        )
    budget = 0
    for replacement in replacements:
        if not isinstance(replacement, dict):
            raise BoundedRepairContractError("every replacement must be an object")
        if not all(
            isinstance(replacement.get(key), str) for key in ("path", "old", "new")
        ):
            raise BoundedRepairContractError(
                "replacement path, old, and new must be strings"
            )
        if (
            not replacement["old"]
            or "\x00" in replacement["old"]
            or "\x00" in replacement["new"]
        ):
            raise BoundedRepairContractError(
                "replacement text is empty or contains NUL"
            )
        budget += len(replacement["old"]) + len(replacement["new"])
    if budget > MAX_TEXT_BUDGET:
        raise BoundedRepairContractError("repair text budget exceeded")
    return payload


def allowed_paths(package: Path) -> set[str]:
    descriptions = [
        path
        for path in package.iterdir()
        if path.is_file()
        and re.search(r"description.*\.txt$|_description\.txt$", path.name, re.I)
    ]
    if len(descriptions) != 1:
        raise BoundedRepairContractError(
            "bounded repair requires exactly one description"
        )
    return {
        descriptions[0].name,
        "folder_of_everything_necessary/duplicate_and_staleness_review.txt",
        "folder_of_everything_necessary/PUBLIC_DUPLICATE_REVIEW.txt",
    }


def validate_replacement_targets(
    package: Path,
    payload: dict[str, Any],
) -> list[str]:
    permitted = allowed_paths(package)
    changed: list[str] = []
    for replacement in payload["replacements"]:
        relative = Path(replacement["path"])
        normalized = relative.as_posix()
        if relative.is_absolute() or ".." in relative.parts or normalized not in permitted:
            raise BoundedRepairContractError(
                f"repair path is outside the bounded text allowlist: {normalized}"
            )
        target = package / relative
        if not target.is_file():
            raise BoundedRepairContractError(
                f"repair target does not exist: {normalized}"
            )
        try:
            text = target.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise BoundedRepairContractError(
                f"cannot read repair target {normalized}: {error}"
            ) from error
        if text.count(replacement["old"]) != 1:
            raise BoundedRepairContractError(
                f"repair old text must occur exactly once: {normalized}"
            )
        changed.append(normalized)
    return sorted(set(changed))


def validate_queued_mechanical_repair(
    workspace: Path,
    package: Path,
    item: dict[str, Any],
    issues: list[dict[str, str]],
) -> str:
    relative = extract_repair_input_path(issues)
    if relative is None:
        raise BoundedRepairContractError(
            "MECHANICAL rework requires every issue to name the same bounded-repair JSON"
        )
    payload = load_repair_input(workspace, workspace / Path(relative))
    if (
        int(payload["item_id"]) != int(item["id"])
        or int(payload["revision"]) != int(item["revision"])
        or payload["reviewed_hash"] != item["package_hash"]
    ):
        raise BoundedRepairContractError(
            "bounded-repair JSON does not match the current item, revision, and hash"
        )
    validate_replacement_targets(package, payload)
    return relative
