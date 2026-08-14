#!/usr/bin/env python3
"""Validate the target-scoper decision contract and acquisition hard gate."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any


VERDICTS = {"CANDIDATE", "SCOPED", "DISCOURAGED", "HARD_EXCLUDED"}
ACQUISITION_STATES = {
    "SELF_SERVE_VERIFIED",
    "OPERATOR_ENTITLEMENT_CONFIRMED",
    "UNRESOLVED",
    "BLOCKED",
}
SCOPED_ACQUISITION_STATES = {
    "SELF_SERVE_VERIFIED",
    "OPERATOR_ENTITLEMENT_CONFIRMED",
}
SCORE_LIMITS = {
    "buyer_fit": 25,
    "impact": 20,
    "enterprise": 15,
    "proof_distance": 15,
    "novelty": 15,
    "workspace_leverage": 10,
}
REQUIRED_SCOPE_FILES = (
    "GOAL.md",
    "EVIDENCE_APPENDIX.md",
    "SCOPE_RECORD.md",
    "HISTORICAL_SECURITY_LINEAGE.md",
    "PUBLIC_SOURCE_INDEX.csv",
    "SCOPE_DECISION.json",
    "ACQUISITION_AND_LAB_PLAN.md",
)
REVISION_FILES = ("GOAL.md", "EVIDENCE_APPENDIX.md", "SCOPE_RECORD.md")


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _required_strings(value: Any, prefix: str, fields: tuple[str, ...]) -> list[str]:
    if not isinstance(value, dict):
        return [f"{prefix} must be an object"]
    return [
        f"{prefix}.{field} must be non-empty"
        for field in fields
        if not _nonempty(value.get(field))
    ]


def _resolve_path(value: str, workspace: Path) -> Path:
    candidate = Path(value)
    return candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()


def validate(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["document must be a JSON object"]
    required = {
        "schema_version",
        "scope_revision",
        "generated_at",
        "target",
        "verdict",
        "score",
        "economics",
        "acquisition",
        "paths",
        "decisive_reasons",
    }
    missing = sorted(required - set(payload))
    if missing:
        errors.append("missing required fields: " + ", ".join(missing))
    if payload.get("schema_version") != 2:
        errors.append("schema_version must be 2")
    scope_revision = payload.get("scope_revision")
    if not _integer(scope_revision) or scope_revision < 1:
        errors.append("scope_revision must be an integer of at least 1")
    if not _nonempty(payload.get("generated_at")):
        errors.append("generated_at must be non-empty")

    errors.extend(
        _required_strings(
            payload.get("target"),
            "target",
            ("slug", "vendor", "product", "current_version", "official_release_url"),
        )
    )

    verdict = payload.get("verdict")
    if verdict not in VERDICTS:
        errors.append("verdict is invalid")

    score = payload.get("score")
    if not isinstance(score, dict):
        errors.append("score must be an object")
    else:
        total = score.get("total")
        if not _integer(total) or not 0 <= total <= 100:
            errors.append("score.total must be between 0 and 100")
        valid_factors = True
        for field, maximum in SCORE_LIMITS.items():
            value = score.get(field)
            if not _integer(value) or not 0 <= value <= maximum:
                errors.append(f"score.{field} must be between 0 and {maximum}")
                valid_factors = False
        if valid_factors and _integer(total):
            factor_total = sum(int(score[field]) for field in SCORE_LIMITS)
            if total != factor_total:
                errors.append(
                    "score.total must equal the six factor scores "
                    f"({factor_total})"
                )

    errors.extend(
        _required_strings(
            payload.get("economics"),
            "economics",
            ("buyer_route", "likely_band", "ceiling"),
        )
    )

    paths = payload.get("paths")
    if not isinstance(paths, dict):
        errors.append("paths must be an object")
    elif verdict == "SCOPED":
        for field in ("scope_dir", "goal", "mirror"):
            if not _nonempty(paths.get(field)):
                errors.append(f"SCOPED requires non-empty paths.{field}")

    decisive_reasons = payload.get("decisive_reasons")
    if not (
        isinstance(decisive_reasons, list)
        and decisive_reasons
        and all(_nonempty(reason) for reason in decisive_reasons)
    ):
        errors.append("decisive_reasons must contain at least one non-empty string")

    source_count = payload.get("source_count")
    if not _integer(source_count) or source_count < 0:
        errors.append("source_count must be a non-negative integer")

    acquisition = payload.get("acquisition")
    if not isinstance(acquisition, dict):
        errors.append("acquisition must be an object")
        return errors
    status = acquisition.get("status")
    if status not in ACQUISITION_STATES:
        errors.append("acquisition.status is invalid")
    for field in ("exact_artifact", "official_url", "verified_at", "evidence"):
        if not _nonempty(acquisition.get(field)):
            errors.append(f"acquisition.{field} must be non-empty")
    if verdict == "SCOPED" and status not in SCOPED_ACQUISITION_STATES:
        errors.append("SCOPED requires verified exact-current acquisition")
    if status == "OPERATOR_ENTITLEMENT_CONFIRMED" and not _nonempty(
        acquisition.get("operator_confirmation")
    ):
        errors.append(
            "acquisition.operator_confirmation is required for OPERATOR_ENTITLEMENT_CONFIRMED"
        )
    return errors


def validate_bundle(
    payload: Any,
    scope_dir: Path,
    *,
    workspace: Path | None = None,
) -> list[str]:
    """Validate cross-file integrity for one complete scope bundle."""
    if not isinstance(payload, dict):
        return ["document must be a JSON object"]
    root = scope_dir.resolve()
    workspace_root = (workspace or Path.cwd()).resolve()
    errors: list[str] = []

    missing = [name for name in REQUIRED_SCOPE_FILES if not (root / name).is_file()]
    if missing:
        errors.append("missing required scope files: " + ", ".join(missing))

    paths = payload.get("paths")
    if isinstance(paths, dict):
        recorded_scope = paths.get("scope_dir")
        if _nonempty(recorded_scope):
            resolved_scope = _resolve_path(recorded_scope, workspace_root)
            if resolved_scope != root:
                errors.append(
                    f"paths.scope_dir resolves to {resolved_scope}, expected {root}"
                )
        recorded_goal = paths.get("goal")
        if _nonempty(recorded_goal):
            resolved_goal = _resolve_path(recorded_goal, workspace_root)
            expected_goal = (root / "GOAL.md").resolve()
            if resolved_goal != expected_goal:
                errors.append(
                    f"paths.goal resolves to {resolved_goal}, expected {expected_goal}"
                )

    revision = payload.get("scope_revision")
    if _integer(revision):
        for name in REVISION_FILES:
            path = root / name
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                errors.append(f"{name} must be readable UTF-8")
                continue
            match = re.search(r"^Scope revision:\s*(\d+)\s*$", text, re.MULTILINE)
            if match is None:
                errors.append(f"{name} must declare Scope revision")
                continue
            file_revision = int(match.group(1))
            if file_revision != revision:
                errors.append(
                    f"{name} scope revision {file_revision} does not match "
                    f"decision revision {revision}"
                )

    decision_path = root / "SCOPE_DECISION.json"
    if decision_path.is_file():
        try:
            bundled_payload = json.loads(decision_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append("SCOPE_DECISION.json must be readable UTF-8 JSON")
        else:
            if bundled_payload != payload:
                errors.append("bundled SCOPE_DECISION.json does not match the validated decision")

    source_path = root / "PUBLIC_SOURCE_INDEX.csv"
    if source_path.is_file():
        try:
            with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                columns = tuple(reader.fieldnames or ())
                rows: list[dict[str | None, Any]] = []
                malformed_rows = False
                for row in reader:
                    if None in row or any(
                        value is not None and not isinstance(value, str)
                        for value in row.values()
                    ):
                        malformed_rows = True
                    if any(
                        isinstance(value, str) and bool(value.strip())
                        for value in row.values()
                    ):
                        rows.append(row)
        except (OSError, UnicodeDecodeError, csv.Error):
            errors.append("PUBLIC_SOURCE_INDEX.csv must be readable UTF-8 CSV")
        else:
            if "url" not in columns:
                errors.append("PUBLIC_SOURCE_INDEX.csv must contain a url column")
            if malformed_rows or any(not _nonempty(row.get("url")) for row in rows):
                errors.append("PUBLIC_SOURCE_INDEX.csv rows must match the header and contain a URL")
            source_count = payload.get("source_count")
            if _integer(source_count) and source_count != len(rows):
                errors.append(
                    f"source_count {source_count} does not match "
                    f"PUBLIC_SOURCE_INDEX.csv row count {len(rows)}"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--scope-dir",
        type=Path,
        help="also validate the complete seven-file scope bundle",
    )
    args = parser.parse_args()
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        print("INVALID: could not read valid UTF-8 JSON")
        return 2
    errors = validate(payload)
    if args.scope_dir is not None:
        errors.extend(validate_bundle(payload, args.scope_dir))
    if errors:
        for error in errors:
            print(f"INVALID: {error}")
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
