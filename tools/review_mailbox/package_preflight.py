from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from candidate_challenge import (
    CandidateChallengeError,
    validate_result as validate_candidate_challenge_result,
)
from package_safety import EVIDENCE_ROOT, extract_validated_zip


SCHEMA = "jenny.package-preflight.v1"
MECHANICAL_GATE_IDS = (
    "package_validation",
    "sidecar_package_shape",
    "portal_text",
    "sidecar_package_gate",
    "zip_internal_notes",
    "secret_scan",
)
FINAL_CHECK_IDS = (
    "fresh_extraction",
    "external_dependencies",
    "packaged_command",
    "package_unchanged",
)
ADMISSION_GATE_IDS = (
    "candidate_challenge",
    "candidate_inventory",
    "portfolio_admission",
)
INVENTORY_ACK_SCHEMA = "jenny.candidate-inventory-ack.v1"
PRODUCT_ALIASES_SCHEMA = "jenny.product-aliases.v1"
_GENERIC_PRODUCT_TOKENS = {
    "agent",
    "and",
    "community",
    "defined",
    "edition",
    "enterprise",
    "manager",
    "platform",
    "proxy",
    "server",
    "software",
    "storage",
}
_CANONICAL_INVENTORY_ROOTS = (
    ("ACCEPTED", Path("ZDI") / "_ACCEPTED"),
    ("SUBMITTED", Path("ZDI") / "_SUBMITTED"),
    ("REJECTED", Path("ZDI") / "_REJECTED"),
    ("DEAD", Path("ZDI") / "_NUMBERED"),
    ("HOLD", Path("ZDI_STAGING") / "_HOLD"),
)
_FINDING_TITLE_START_TOKENS = {
    "api",
    "arbitrary",
    "auth",
    "authenticated",
    "authentication",
    "authorization",
    "command",
    "credential",
    "cross",
    "directory",
    "deployment",
    "file",
    "hardcoded",
    "heap",
    "improper",
    "incorrect",
    "integer",
    "legacy",
    "local",
    "low",
    "mcp",
    "missing",
    "oauth",
    "oidc",
    "parser",
    "path",
    "privilege",
    "public",
    "read",
    "remote",
    "saml",
    "sql",
    "stack",
    "unauthenticated",
    "use",
    "weak",
}


def _product_tokens(value: str) -> tuple[str, ...]:
    return tuple(
        token
        for token in re.findall(r"[a-z0-9]+", value.casefold())
        if token not in _GENERIC_PRODUCT_TOKENS
    )


def _load_product_aliases(workspace: Path) -> list[list[str]]:
    path = workspace / "notes" / "review_mailbox" / "product_aliases.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreflightError(f"cannot read product aliases: {error}") from error
    groups = payload.get("groups") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != PRODUCT_ALIASES_SCHEMA
        or not isinstance(groups, list)
    ):
        raise PreflightError("product alias registry is invalid")
    if any(
        not isinstance(group, list)
        or len(group) < 2
        or any(not isinstance(value, str) or not value.strip() for value in group)
        for group in groups
    ):
        raise PreflightError("product alias group is invalid")
    return [[value.strip() for value in group] for group in groups]


def _product_variants(value: str, aliases: list[list[str]]) -> list[str]:
    normalized = tuple(_product_tokens(value))
    for group in aliases:
        if any(tuple(_product_tokens(member)) == normalized for member in group):
            return group
    return [value]


def _canonical_product_identity(
    value: str, aliases: list[list[str]]
) -> tuple[str, list[str]]:
    variants = _product_variants(value, aliases)
    if len(variants) > 1:
        return variants[0], list(variants)
    cleaned = value.strip()
    return cleaned, [cleaned]


def _same_product(left: str, right: str, aliases: list[list[str]] | None = None) -> bool:
    alias_groups = aliases or []
    return any(
        _same_product_tokens(left_variant, right_variant)
        for left_variant in _product_variants(left, alias_groups)
        for right_variant in _product_variants(right, alias_groups)
    )


def _same_product_tokens(left: str, right: str) -> bool:
    left_tokens = _product_tokens(left)
    right_tokens = _product_tokens(right)
    return bool(left_tokens) and left_tokens == right_tokens


def _package_title_matches_product(
    product: str, package_title: str, aliases: list[list[str]]
) -> bool:
    """Match an archive title only through an explicit product/alias prefix.

    Package folder names append a finding title to the product name.  This is
    intentionally separate from product equality so a shorter product name
    can never make two products equal (for example Visual Studio and Visual
    Studio Code).
    """
    return any(
        _package_title_matches_variant(variant, package_title)
        for variant in _product_variants(product, aliases)
    )


def _package_title_matches_variant(variant: str, package_title: str) -> bool:
    """Match one exact product spelling against a package-title prefix."""
    title_tokens = tuple(re.findall(r"[a-z0-9]+", package_title.casefold()))
    product_tokens = _product_tokens(variant)
    title_product_tokens: list[str] = []
    boundary_token = ""
    for token in title_tokens:
        if token in _GENERIC_PRODUCT_TOKENS:
            continue
        if len(title_product_tokens) < len(product_tokens):
            title_product_tokens.append(token)
            continue
        boundary_token = token
        break
    return (
        bool(product_tokens)
        and tuple(title_product_tokens) == product_tokens
        and boundary_token in _FINDING_TITLE_START_TOKENS
    )


def _canonical_package_identity(name: str) -> tuple[int, str] | None:
    match = re.match(r"^(?:_(?:ACCEPTED|SUBMITTED|REJECTED)_)?(\d+)_(.+)$", name)
    if match is None:
        return None
    return int(match.group(1)), match.group(2)
PORTFOLIO_ADMISSION_SCHEMA = "jenny.portfolio-admission.v1"
PORTFOLIO_CLASSES = {"A_TIER", "CHAIN_COMPONENT", "TIER_B_EXCEPTION"}
TEXT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".http",
    ".ini",
    ".js",
    ".json",
    ".log",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


class PreflightError(RuntimeError):
    pass


def _reviewed_ids_match(reviewed: object, expected_ids: list[int]) -> bool:
    return (
        isinstance(reviewed, list)
        and all(
            isinstance(item_id, int)
            and not isinstance(item_id, bool)
            and item_id != 0
            for item_id in reviewed
        )
        and len(set(reviewed)) == len(reviewed)
        and sorted(reviewed) == sorted(expected_ids)
    )


def load_candidate_inventory(
    workspace: str | Path,
    product: str,
    db_path: str | Path | None = None,
    exclude_package_number: int | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    aliases = _load_product_aliases(workspace_path)
    canonical_product, product_aliases = _canonical_product_identity(product, aliases)
    database = (
        Path(db_path).resolve()
        if db_path is not None
        else workspace_path / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
    )
    items: list[dict[str, Any]] = []
    if database.is_file():
        try:
            uri = database.as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=5) as connection:
                connection.row_factory = sqlite3.Row
                has_work_items = connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'work_items'
                    """
                ).fetchone()
                rows = (
                    connection.execute(
                        """
                        SELECT id, package_path, product, version, package_hash, state, revision
                        FROM work_items ORDER BY id
                        """
                    ).fetchall()
                    if has_work_items is not None
                    else []
                )
        except sqlite3.Error as error:
            raise PreflightError(f"cannot read candidate inventory: {error}") from error
        items = [
            {
                "id": int(row["id"]),
                "package": Path(row["package_path"]).name,
                "product": row["product"],
                "version": row["version"],
                "state": row["state"],
                "revision": int(row["revision"]),
                "package_hash": row["package_hash"],
                "source": "sqlite",
            }
            for row in rows
            if _same_product(product, str(row["product"]), aliases)
            and (
                exclude_package_number is None
                or (
                    (identity := _canonical_package_identity(
                        Path(str(row["package_path"])).name
                    ))
                    is None
                    or identity[0] != exclude_package_number
                )
            )
        ]
    seen_package_numbers = {
        identity[0]
        for item in items
        if (identity := _canonical_package_identity(str(item["package"]))) is not None
    }
    for state, relative_root in _CANONICAL_INVENTORY_ROOTS:
        root = workspace_path / relative_root
        if not root.is_dir():
            continue
        for package in sorted(
            (entry for entry in root.iterdir() if entry.is_dir()),
            key=lambda entry: entry.name.casefold(),
        ):
            identity = _canonical_package_identity(package.name)
            if identity is None:
                continue
            package_number, package_title = identity
            if package_number == exclude_package_number:
                continue
            if package_number in seen_package_numbers:
                continue
            if not _package_title_matches_product(product, package_title, aliases):
                continue
            matched_product = next(
                (
                    variant
                    for variant in _product_variants(product, aliases)
                    if _package_title_matches_variant(variant, package_title)
                ),
                product,
            )
            items.append(
                {
                    "id": -package_number,
                    "package": package.name,
                    "product": matched_product,
                    "version": "",
                    "state": state,
                    "revision": 0,
                    "package_hash": "",
                    "source": "canonical_archive",
                }
            )
            seen_package_numbers.add(package_number)
    # Workflow state is intentionally excluded from the acknowledgement identity.
    # A Midlane transition such as READY_FOR_MIDLANE -> QUESTIONS_OPEN does not
    # change the candidate set that Hunter reviewed. Revision, hash, item identity,
    # package identity, and source remain bound and therefore still invalidate a
    # stale acknowledgement when substantive package identity changes.
    digest_items = [
        {key: value for key, value in item.items() if key != "state"}
        for item in items
    ]
    digest_payload: object = digest_items
    if len(product_aliases) > 1:
        digest_payload = {
            "schema": "jenny.candidate-inventory.v2",
            "product": canonical_product,
            "aliases": product_aliases,
            "items": digest_items,
        }
    canonical = json.dumps(
        digest_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return {
        "product": canonical_product,
        "aliases": product_aliases,
        "digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "items": items,
    }


def _inventory_gate(
    workspace: Path,
    product: str,
    ack_path: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    inventory = load_candidate_inventory(workspace, product)
    expected_ids = [item["id"] for item in inventory["items"]]
    if not expected_ids:
        return inventory, {"status": "PASS", "reviewed_item_ids": []}
    if ack_path is None:
        return inventory, {
            "status": "FAIL",
            "detail": "same-product history requires --inventory-ack",
            "required_item_ids": expected_ids,
        }
    resolved = ack_path.resolve()
    if not resolved.is_file() or not _is_within(resolved, workspace):
        return inventory, {"status": "FAIL", "detail": "inventory acknowledgement is unavailable"}
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return inventory, {"status": "FAIL", "detail": f"invalid inventory acknowledgement: {error}"}
    closest = payload.get("closest_sibling") if isinstance(payload, dict) else None
    reviewed = payload.get("reviewed_item_ids") if isinstance(payload, dict) else None
    valid_closest = (
        isinstance(closest, dict)
        and closest.get("item_id") in expected_ids
        and closest.get("disposition") in {"DISTINCT", "CONSOLIDATE", "DUPLICATE"}
        and isinstance(closest.get("reason"), str)
        and bool(closest["reason"].strip())
    )
    valid = (
        isinstance(payload, dict)
        and payload.get("schema") == INVENTORY_ACK_SCHEMA
        and payload.get("product") == product
        and payload.get("inventory_digest") == inventory["digest"]
        and _reviewed_ids_match(reviewed, expected_ids)
        and valid_closest
    )
    return inventory, {
        "status": "PASS" if valid else "FAIL",
        "reviewed_item_ids": reviewed if isinstance(reviewed, list) else [],
        **({} if valid else {"detail": "inventory acknowledgement is missing, incomplete, or stale"}),
    }


def _portfolio_admission_gate(
    workspace: Path,
    product: str,
    inventory: dict[str, Any],
    admission_path: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if admission_path is None:
        return {}, {
            "status": "FAIL",
            "detail": "PROMOTE requires --portfolio-admission",
        }
    resolved = admission_path.resolve()
    external_roots = (
        (workspace / "ZDI").resolve(),
        (workspace / "ZDI_STAGING").resolve(),
    )
    if (
        not resolved.is_file()
        or not _is_within(resolved, workspace)
        or any(_is_within(resolved, root) for root in external_roots)
    ):
        return {}, {
            "status": "FAIL",
            "detail": "portfolio admission must be a private workspace JSON file",
        }
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return {}, {
            "status": "FAIL",
            "detail": f"invalid portfolio admission: {error}",
        }

    expected_ids = [item["id"] for item in inventory["items"]]
    reviewed = payload.get("reviewed_item_ids") if isinstance(payload, dict) else None
    payout = payload.get("likely_payout_usd") if isinstance(payload, dict) else None
    low = payout.get("low") if isinstance(payout, dict) else None
    high = payout.get("high") if isinstance(payout, dict) else None
    ceiling = payload.get("theoretical_ceiling_usd") if isinstance(payload, dict) else None
    portfolio_class = payload.get("portfolio_class") if isinstance(payload, dict) else None
    operator_exception = (
        payload.get("operator_exception") if isinstance(payload, dict) else None
    )
    operator_instruction = (
        payload.get("operator_instruction") if isinstance(payload, dict) else None
    )

    valid = (
        isinstance(payload, dict)
        and payload.get("schema") == PORTFOLIO_ADMISSION_SCHEMA
        and payload.get("product") == product
        and payload.get("inventory_digest") == inventory["digest"]
        and _reviewed_ids_match(reviewed, expected_ids)
        and payload.get("disposition") == "PROMOTE"
        and portfolio_class in PORTFOLIO_CLASSES
        and isinstance(operator_exception, bool)
        and (
            portfolio_class != "TIER_B_EXCEPTION"
            or (
                operator_exception is True
                and isinstance(operator_instruction, str)
                and bool(operator_instruction.strip())
            )
        )
        and isinstance(payload.get("candidate_title"), str)
        and bool(payload["candidate_title"].strip())
        and isinstance(payload.get("root_family_id"), str)
        and bool(payload["root_family_id"].strip())
        and isinstance(payload.get("chain_role"), str)
        and bool(payload["chain_role"].strip())
        and isinstance(payload.get("why_now"), str)
        and bool(payload["why_now"].strip())
        and isinstance(payload.get("same_product_rank"), int)
        and not isinstance(payload["same_product_rank"], bool)
        and payload["same_product_rank"] > 0
        and isinstance(low, int)
        and not isinstance(low, bool)
        and low >= 0
        and isinstance(high, int)
        and not isinstance(high, bool)
        and high >= low
        and isinstance(ceiling, int)
        and not isinstance(ceiling, bool)
        and ceiling >= high
    )
    summary = {
        "schema": payload.get("schema") if isinstance(payload, dict) else None,
        "product": payload.get("product") if isinstance(payload, dict) else None,
        "inventory_digest": (
            payload.get("inventory_digest") if isinstance(payload, dict) else None
        ),
        "reviewed_item_ids": reviewed if isinstance(reviewed, list) else [],
        "disposition": payload.get("disposition") if isinstance(payload, dict) else None,
        "portfolio_class": portfolio_class,
        "likely_payout_usd": payout if isinstance(payout, dict) else None,
        "theoretical_ceiling_usd": ceiling,
        "same_product_rank": (
            payload.get("same_product_rank") if isinstance(payload, dict) else None
        ),
        "operator_exception": operator_exception,
        "operator_instruction_sha256": (
            hashlib.sha256(operator_instruction.encode("utf-8")).hexdigest()
            if isinstance(operator_instruction, str) and operator_instruction
            else None
        ),
        "file_sha256": _sha256(resolved),
    }
    return summary, {
        "status": "PASS" if valid else "FAIL",
        **(
            {}
            if valid
            else {
                "detail": (
                    "portfolio admission is missing required PROMOTE economics, "
                    "ranking, lineage, or current inventory binding"
                )
            }
        ),
    }


def _candidate_challenge_gate(
    workspace: Path,
    package: Path,
    product: str,
    result_path: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    match = re.match(r"^(?:_READY_TO_SUBMIT_)?(\d+)_", package.name)
    if match is None:
        return {}, {"status": "FAIL", "detail": "package number is invalid"}
    package_number = int(match.group(1))
    database = (
        workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
    )
    candidate_id: int | None = None
    version = ""
    if database.is_file():
        try:
            uri = database.as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=5) as connection:
                connection.row_factory = sqlite3.Row
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                build_columns = (
                    {
                        str(row[1])
                        for row in connection.execute(
                            "PRAGMA table_info(package_builds)"
                        )
                    }
                    if "package_builds" in tables
                    else set()
                )
                build = (
                    connection.execute(
                        """
                        SELECT candidate_challenge_id, version
                        FROM package_builds WHERE package_number = ?
                        """,
                        (package_number,),
                    ).fetchone()
                    if {"candidate_challenge_id", "version"} <= build_columns
                    else None
                )
                bound = build
                item_columns = (
                    {
                        str(row[1])
                        for row in connection.execute(
                            "PRAGMA table_info(work_items)"
                        )
                    }
                    if "work_items" in tables
                    else set()
                )
                if (
                    bound is None
                    and {"package_path", "candidate_challenge_id", "version"}
                    <= item_columns
                ):
                    rows = connection.execute(
                        """
                        SELECT package_path, candidate_challenge_id, version
                        FROM work_items
                        WHERE candidate_challenge_id IS NOT NULL
                        ORDER BY id DESC
                        """
                    ).fetchall()
                    bound = next(
                        (
                            row
                            for row in rows
                            if re.match(
                                rf"^(?:_READY_TO_SUBMIT_)?{package_number}_",
                                Path(str(row["package_path"])).name,
                            )
                        ),
                        None,
                    )
        except sqlite3.Error as error:
            return {}, {
                "status": "FAIL",
                "detail": f"cannot read candidate challenge binding: {error}",
            }
        if bound is not None and bound["candidate_challenge_id"] is not None:
            candidate_id = int(bound["candidate_challenge_id"])
            version = str(bound["version"])

    if candidate_id is None:
        return {
            "legacy_unbound": True,
            "package_number": package_number,
        }, {
            "status": "PASS",
            "detail": "legacy numbered lineage predates Candidate Challenge",
        }
    if result_path is None:
        return {"candidate_id": candidate_id}, {
            "status": "FAIL",
            "detail": "package-bound candidate requires --candidate-challenge",
        }
    try:
        validated = validate_candidate_challenge_result(
            workspace=workspace,
            db_path=database,
            result_path=result_path,
            product=product,
            version=version,
        )
    except CandidateChallengeError as error:
        return {"candidate_id": candidate_id}, {
            "status": "FAIL",
            "detail": str(error),
        }
    if int(validated["candidate_id"]) != candidate_id:
        return {"candidate_id": candidate_id}, {
            "status": "FAIL",
            "detail": "candidate challenge does not match package binding",
        }
    return {
        "candidate_id": candidate_id,
        "candidate_key": validated["candidate_key"],
        "disposition": validated["disposition"],
        "result_path": validated["result_path"],
        "result_sha256": validated["result_sha256"],
    }, {"status": "PASS", "candidate_id": candidate_id}


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def hash_package_tree(package: str | Path) -> str:
    package_path = Path(package).resolve()
    if not package_path.is_dir():
        raise PreflightError(f"package directory does not exist: {package_path}")
    digest = hashlib.sha256()
    for path in sorted(package_path.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_symlink():
            raise PreflightError(f"package contains a symbolic link: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(package_path).as_posix().encode("utf-8")
        digest.update(b"FILE\0")
        digest.update(relative)
        digest.update(b"\0")
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
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


def _validate_paths(
    workspace: Path, package: Path, goal: Path, result_path: Path
) -> None:
    if not _is_within(package, workspace / "ZDI_STAGING"):
        raise PreflightError("package must be under ZDI_STAGING")
    if package.parent != (workspace / "ZDI_STAGING").resolve():
        raise PreflightError("package must be directly under ZDI_STAGING")
    if not re.fullmatch(r"\d+_.+", package.name):
        raise PreflightError("package must be a direct numbered folder")
    if goal.name != "GOAL.md" or not _is_within(goal, workspace / "targets"):
        raise PreflightError("goal must be a targets/<slug>/GOAL.md file")
    if not goal.is_file():
        raise PreflightError(f"goal file does not exist: {goal}")
    if _is_within(result_path, package):
        raise PreflightError("preflight result must stay outside the external package")
    if not _is_within(result_path, workspace):
        raise PreflightError("preflight result must stay inside the workspace")
    if _is_within(result_path, workspace / "ZDI") or _is_within(
        result_path, workspace / "ZDI_STAGING"
    ):
        raise PreflightError("preflight result must stay in private scratch or target notes")
    if result_path.suffix.casefold() != ".json":
        raise PreflightError("preflight result must use a .json filename")


def _result_for_process(
    gate_id: str, completed: subprocess.CompletedProcess[str]
) -> dict[str, Any]:
    stdout = completed.stdout.encode("utf-8", errors="replace")
    stderr = completed.stderr.encode("utf-8", errors="replace")
    return {
        "id": gate_id,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "exit_code": completed.returncode,
        "stdout_length": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_length": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def _run_mechanical_gates(
    workspace: Path, package: Path, timeout_seconds: int
) -> list[dict[str, Any]]:
    descriptions = [
        path
        for path in package.iterdir()
        if path.is_file()
        and re.search(r"description.*\.txt$|_description\.txt$", path.name, re.I)
    ]
    if len(descriptions) != 1:
        return [
            {
                "id": gate_id,
                "status": "FAIL",
                "exit_code": None,
                "detail": "exactly one description is required before gate execution",
            }
            for gate_id in MECHANICAL_GATE_IDS
        ]
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if powershell is None:
        return [
            {
                "id": gate_id,
                "status": "FAIL",
                "exit_code": None,
                "detail": "Windows PowerShell is unavailable",
            }
            for gate_id in MECHANICAL_GATE_IDS
        ]
    commands = (
        (
            "package_validation",
            [
                sys.executable,
                "-B",
                str(workspace / "tools" / "review_mailbox" / "package_safety.py"),
                "validate",
                "--package",
                str(package),
            ],
        ),
        (
            "sidecar_package_shape",
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(workspace / "tools" / "sidecar_package_shape.ps1"),
                "-PackagePath",
                str(package),
                "-Modern",
            ],
        ),
        (
            "portal_text",
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(workspace / "tools" / "sidecar_portal_text_gate.ps1"),
                "-DescriptionPath",
                str(descriptions[0]),
                "-Mode",
                "candidate",
            ],
        ),
        (
            "sidecar_package_gate",
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(workspace / "tools" / "sidecar_package_gate.ps1"),
                "-PackagePath",
                str(package),
            ],
        ),
        (
            "zip_internal_notes",
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(workspace / "tools" / "sidecar_zip_internal_note_gate.ps1"),
                "-PackagePath",
                str(package),
                "-Quiet",
            ],
        ),
        (
            "secret_scan",
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(workspace / "tools" / "sidecar_package_secret_scan.ps1"),
                "-PackagePath",
                str(package),
            ],
        ),
    )
    results: list[dict[str, Any]] = []
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for gate_id, argv in commands:
        try:
            completed = subprocess.run(
                argv,
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            results.append(_result_for_process(gate_id, completed))
        except subprocess.TimeoutExpired:
            results.append(
                {
                    "id": gate_id,
                    "status": "FAIL",
                    "exit_code": None,
                    "detail": f"gate exceeded {timeout_seconds} seconds",
                }
            )
        if results[-1]["status"] != "PASS":
            failed_gate = gate_id
            remaining = commands[len(results) :]
            results.extend(
                {
                    "id": remaining_gate,
                    "status": "NOT_RUN",
                    "exit_code": None,
                    "detail": f"blocked by failed {failed_gate} gate",
                }
                for remaining_gate, _ in remaining
            )
            break
    return results


def _dependency_hits(root: Path, workspace: Path) -> list[dict[str, Any]]:
    workspace_windows = str(workspace.resolve()).casefold()
    workspace_windows_escaped = workspace_windows.replace("\\", "\\\\")
    workspace_posix = workspace.resolve().as_posix().casefold()
    hits: list[dict[str, Any]] = []
    relative_patterns = (
        ("targets/", "target_local_path"),
        ("targets\\", "target_local_path"),
        ("zdi_staging", "staging_path"),
        ("scratch/review_mailbox", "scratch_path"),
        ("scratch\\review_mailbox", "scratch_path"),
    )
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if not path.is_file() or path.suffix.casefold() not in TEXT_SUFFIXES:
            continue
        if path.stat().st_size > 10 * 1024 * 1024:
            hits.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "line": None,
                    "marker": "text_file_exceeds_scan_limit",
                }
            )
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            folded = line.casefold()
            marker: str | None = None
            if (
                workspace_windows in folded
                or workspace_windows_escaped in folded
                or workspace_posix in folded
            ):
                marker = "workspace_absolute_path"
            else:
                for pattern, label in relative_patterns:
                    if pattern in folded:
                        marker = label
                        break
            if marker is not None:
                hits.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "line": line_number,
                        "marker": marker,
                    }
                )
    return hits


_PINNED_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/:\-]*@sha256:[0-9a-f]{64}$", re.I)
_CONTAINER_OUTPUT_LIMIT = 4 * 1024 * 1024


def _load_command(path: Path, workspace: Path) -> tuple[list[str], str, str, str]:
    command_path = path.resolve()
    if not command_path.is_file() or not _is_within(command_path, workspace):
        raise PreflightError("command JSON must be an existing private workspace file")
    payload = json.loads(command_path.read_text(encoding="utf-8"))
    argv = payload.get("argv") if isinstance(payload, dict) else None
    runner_image = payload.get("runner_image") if isinstance(payload, dict) else None
    network = payload.get("network", "none") if isinstance(payload, dict) else "none"
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(value, str) or not value for value in argv)
    ):
        raise PreflightError("command JSON must contain one non-empty string argv array")
    if not isinstance(runner_image, str) or not _PINNED_IMAGE_RE.fullmatch(
        runner_image.strip()
    ):
        raise PreflightError(
            "command JSON must name one digest-pinned container image"
        )
    if network != "none" and not (
        isinstance(network, str) and re.fullmatch(r"jenny-[a-z0-9_.-]+", network)
    ):
        raise PreflightError(
            "command network must be none or an explicitly named jenny-* internal network"
        )
    executable = Path(argv[0]).name.casefold()
    if executable.startswith("python"):
        argv[0] = "python"
    if "-c" in argv:
        raise PreflightError("inline interpreter commands are not permitted")
    serialized = json.dumps(argv, ensure_ascii=True).casefold()
    workspace_markers = {
        str(workspace.resolve()).casefold(),
        workspace.resolve().as_posix().casefold(),
        "targets/",
        "targets\\",
        "zdi_staging",
    }
    if any(marker in serialized for marker in workspace_markers):
        raise PreflightError("declared command contains an external workspace dependency")
    for value in argv[1:]:
        if not value.startswith("-") and Path(value).is_absolute():
            raise PreflightError("declared command contains an absolute host path")
        if any(part == ".." for part in Path(value).parts):
            raise PreflightError("declared command contains parent traversal")
    return argv, _sha256(command_path), runner_image.strip(), network


def _docker_environment() -> dict[str, str]:
    allowed = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _require_container_runtime(image: str, network: str) -> None:
    docker = shutil.which("docker") or shutil.which("docker.exe")
    if docker is None:
        raise PreflightError("Docker is required for isolated package replay")
    environment = _docker_environment()
    image_check = subprocess.run(
        [docker, "image", "inspect", image],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
    if image_check.returncode != 0:
        raise PreflightError("digest-pinned replay image is not present locally")
    if network != "none":
        network_check = subprocess.run(
            [docker, "network", "inspect", "--format", "{{.Internal}}", network],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if network_check.returncode != 0 or network_check.stdout.strip().casefold() != "true":
            raise PreflightError("live replay network must exist and be Docker-internal")


def _run_isolated_container(
    *,
    argv: list[str],
    image: str,
    run_root: Path,
    timeout_seconds: int,
    kind: str,
    network: str,
) -> dict[str, Any]:
    _require_container_runtime(image, network)
    docker = shutil.which("docker") or shutil.which("docker.exe")
    assert docker is not None
    name = f"jenny-preflight-{uuid.uuid4().hex[:12]}"
    command = [
        docker,
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "64",
        "--cpus",
        "1",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--mount",
        f"type=bind,source={run_root.resolve()},target=/work,readonly",
        "--workdir",
        "/work",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        image,
        *argv,
    ]
    environment = _docker_environment()
    started = time.monotonic()
    limit_exceeded = False
    timed_out = False
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
        )
        while process.poll() is None:
            if time.monotonic() - started > timeout_seconds:
                timed_out = True
                break
            if (
                stdout_file.tell() > _CONTAINER_OUTPUT_LIMIT
                or stderr_file.tell() > _CONTAINER_OUTPUT_LIMIT
            ):
                limit_exceeded = True
                break
            time.sleep(0.1)
        if timed_out or limit_exceeded:
            process.kill()
            process.wait(timeout=5)
            subprocess.run(
                [docker, "rm", "-f", name],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_CONTAINER_OUTPUT_LIMIT + 1)
        stderr = stderr_file.read(_CONTAINER_OUTPUT_LIMIT + 1)
    if timed_out:
        return {
            "kind": kind,
            "status": "FAIL",
            "exit_code": None,
            "detail": f"isolated command exceeded {timeout_seconds} seconds",
        }
    if limit_exceeded or len(stdout) > _CONTAINER_OUTPUT_LIMIT or len(stderr) > _CONTAINER_OUTPUT_LIMIT:
        return {
            "kind": kind,
            "status": "FAIL",
            "exit_code": process.returncode,
            "detail": "isolated command exceeded the 4 MiB output limit",
        }
    return {
        "kind": kind,
        "status": "PASS" if process.returncode == 0 else "FAIL",
        "exit_code": process.returncode,
        "stdout_length": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_length": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def _run_declared_command(
    command_path: Path,
    workspace: Path,
    run_root: Path,
    timeout_seconds: int,
    kind: str,
) -> dict[str, Any]:
    argv, command_hash, image, network = _load_command(command_path, workspace)
    if kind == "offline" and network != "none":
        raise PreflightError("offline replay must use network none")
    result = _run_isolated_container(
        argv=argv,
        image=image,
        run_root=run_root,
        timeout_seconds=timeout_seconds,
        kind=kind,
        network=network,
    )
    result["command_file_sha256"] = command_hash
    result["runner_image"] = image
    result["network"] = network
    return result


def run_preflight(
    *,
    workspace: str | Path,
    package: str | Path,
    goal: str | Path,
    result_path: str | Path,
    product: str = "",
    inventory_ack: str | Path | None = None,
    portfolio_admission: str | Path | None = None,
    candidate_challenge: str | Path | None = None,
    offline_command: str | Path | None = None,
    live_command: str | Path | None = None,
    allow_live_replay: bool = False,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    package_path = Path(package).resolve()
    goal_path = Path(goal).resolve()
    output_path = Path(result_path).resolve()
    _validate_paths(workspace_path, package_path, goal_path, output_path)
    if timeout_seconds < 1:
        raise PreflightError("timeout must be positive")

    package_hash_before = hash_package_tree(package_path)
    checks: dict[str, dict[str, Any]] = {
        check_id: {"status": "NOT_RUN"}
        for check_id in (*ADMISSION_GATE_IDS, *MECHANICAL_GATE_IDS, *FINAL_CHECK_IDS)
    }
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "FAIL",
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "workspace": str(workspace_path),
        "package_path": str(package_path),
        "package_hash": package_hash_before,
        "goal_path": str(goal_path),
        "goal_hash": _sha256(goal_path),
        "product": product,
        "checks": checks,
    }

    challenge, challenge_check = _candidate_challenge_gate(
        workspace_path,
        package_path,
        product,
        Path(candidate_challenge) if candidate_challenge is not None else None,
    )
    result["candidate_challenge"] = challenge
    checks["candidate_challenge"] = challenge_check
    inventory, inventory_check = _inventory_gate(
        workspace_path,
        product,
        Path(inventory_ack) if inventory_ack is not None else None,
    )
    result["candidate_inventory"] = inventory
    checks["candidate_inventory"] = inventory_check
    portfolio, portfolio_check = _portfolio_admission_gate(
        workspace_path,
        product,
        inventory,
        Path(portfolio_admission) if portfolio_admission is not None else None,
    )
    result["portfolio_admission"] = portfolio
    checks["portfolio_admission"] = portfolio_check

    gate_results = _run_mechanical_gates(
        workspace_path, package_path, timeout_seconds
    )
    for gate in gate_results:
        gate_id = str(gate.get("id", ""))
        if gate_id in checks:
            checks[gate_id] = {key: value for key, value in gate.items() if key != "id"}

    run_root = (
        workspace_path
        / "scratch"
        / "review_mailbox"
        / "package_preflight"
        / f"run-{uuid.uuid4().hex}"
    )
    try:
        if all(checks[gate_id]["status"] == "PASS" for gate_id in MECHANICAL_GATE_IDS):
            archive = next(package_path.glob("*.zip"))
            extract_validated_zip(archive, run_root)
            extracted_root = run_root / EVIDENCE_ROOT
            if extracted_root.is_dir():
                checks["fresh_extraction"] = {
                    "status": "PASS",
                    "root": EVIDENCE_ROOT,
                    "file_count": sum(1 for path in extracted_root.rglob("*") if path.is_file()),
                }
            else:
                checks["fresh_extraction"] = {
                    "status": "FAIL",
                    "detail": f"fresh extraction did not create {EVIDENCE_ROOT}",
                }

        if checks["fresh_extraction"]["status"] == "PASS":
            hits = _dependency_hits(run_root / EVIDENCE_ROOT, workspace_path)
            checks["external_dependencies"] = {
                "status": "FAIL" if hits else "PASS",
                "hits": hits,
            }

        if checks["external_dependencies"]["status"] == "PASS":
            command_results: list[dict[str, Any]] = []
            if offline_command is not None:
                try:
                    command_results.append(
                        _run_declared_command(
                            Path(offline_command),
                            workspace_path,
                            run_root,
                            timeout_seconds,
                            "offline",
                        )
                    )
                except (OSError, ValueError, json.JSONDecodeError, PreflightError) as error:
                    command_results.append(
                        {"kind": "offline", "status": "FAIL", "detail": str(error)}
                    )
            if live_command is not None:
                if not allow_live_replay:
                    command_results.append(
                        {
                            "kind": "live",
                            "status": "FAIL",
                            "detail": "live replay requires explicit --allow-live-replay authority",
                        }
                    )
                else:
                    try:
                        command_results.append(
                            _run_declared_command(
                                Path(live_command),
                                workspace_path,
                                run_root,
                                timeout_seconds,
                                "live",
                            )
                        )
                    except (OSError, ValueError, json.JSONDecodeError, PreflightError) as error:
                        command_results.append(
                            {"kind": "live", "status": "FAIL", "detail": str(error)}
                        )
            if not command_results:
                checks["packaged_command"] = {
                    "status": "FAIL",
                    "detail": "at least one packaged offline or live command is required",
                    "commands": [],
                }
            else:
                failed_commands = [
                    command
                    for command in command_results
                    if command["status"] != "PASS"
                ]
                checks["packaged_command"] = {
                    "status": (
                        "PASS"
                        if all(command["status"] == "PASS" for command in command_results)
                        else "FAIL"
                    ),
                    "commands": command_results,
                }
                if failed_commands and "detail" in failed_commands[0]:
                    checks["packaged_command"]["detail"] = failed_commands[0][
                        "detail"
                    ]
            generated = [
                path.relative_to(run_root).as_posix()
                for path in run_root.rglob("*")
                if path.is_file()
                and (path.suffix.casefold() == ".pyc" or "__pycache__" in path.parts)
            ]
            if generated:
                checks["packaged_command"] = {
                    "status": "FAIL",
                    "detail": "packaged command generated Python cache artifacts",
                    "generated_artifacts": generated,
                    "commands": command_results,
                }
    finally:
        if run_root.exists():
            shutil.rmtree(run_root)

    package_hash_after = hash_package_tree(package_path)
    checks["package_unchanged"] = {
        "status": "PASS" if package_hash_after == package_hash_before else "FAIL",
        "before": package_hash_before,
        "after": package_hash_after,
    }
    result["status"] = (
        "PASS"
        if all(check["status"] == "PASS" for check in checks.values())
        else "FAIL"
    )
    _atomic_write_json(output_path, result)
    return result


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Create one private hash-bound package preflight result"
    )
    parser.add_argument("--workspace", type=Path, default=workspace)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--goal", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--product", required=True)
    parser.add_argument("--inventory-ack", type=Path)
    parser.add_argument("--portfolio-admission", type=Path, required=True)
    parser.add_argument("--candidate-challenge", type=Path)
    parser.add_argument("--offline-command", type=Path)
    parser.add_argument("--live-command", type=Path)
    parser.add_argument("--allow-live-replay", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = run_preflight(
            workspace=args.workspace,
            package=args.package,
            goal=args.goal,
            result_path=args.result,
            product=args.product,
            inventory_ack=args.inventory_ack,
            portfolio_admission=args.portfolio_admission,
            candidate_challenge=args.candidate_challenge,
            offline_command=args.offline_command,
            live_command=args.live_command,
            allow_live_replay=args.allow_live_replay,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, ValueError, zipfile.BadZipFile, PreflightError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
