from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


DOSSIER_SCHEMA = "jenny.candidate-dossier.v1"
DECISION_SCHEMA = "jenny.candidate-challenge.v1"
RESULT_SCHEMA = "jenny.candidate-challenge-result.v1"
PROOF_GATES = (
    "current_identity",
    "attacker_reachability",
    "boundary_controls",
    "deterministic_impact",
    "hard_eligibility",
    "economic_review",
)
HARD_PROOF_GATES = PROOF_GATES[:4]
LEGACY_PROOF_LEVELS = ("L0", "L1", "L2", "L3", "L4")
LEGACY_TO_NAMED_GATES = dict(
    zip(LEGACY_PROOF_LEVELS[:4], HARD_PROOF_GATES, strict=True)
)
PROOF_STATUSES = {"PASS", "PARTIAL", "FAIL", "NOT_RUN"}
DISPOSITIONS = {
    "ADMIT_PROOF",
    "BANK",
    "CONSOLIDATE",
    "WRITE_OFF",
    "OPERATOR_EXCEPTION",
}
ADMITTED_DISPOSITIONS = {"ADMIT_PROOF", "OPERATOR_EXCEPTION"}
PORTFOLIO_CLASSES = {"A_TIER", "CHAIN_COMPONENT", "TIER_B_EXCEPTION"}
PRIOR_ART_DISPOSITIONS = {
    "DISTINCT",
    "DUPLICATE",
    "INCOMPLETE_FIX",
    "RELATED",
    "NOT_SECURITY_RELEVANT",
}
PRIOR_ART_ROOT_RELATIONS = {"EXACT_FUNCTION", "SAME_ROOT_FAMILY", "DISTINCT"}
PRIOR_ART_REMEDIATION_STATUSES = {
    "EXACT_REMEDIATION",
    "INCOMPLETE_REMEDIATION",
    "NO_REMEDIATION",
}
UPGRADE_OUTCOMES = {"STRONGEST_PROVEN", "LOWER_RUNG_JUSTIFIED"}
UPGRADE_DISPOSITIONS = {"PROVED", "CLOSED", "NOT_APPLICABLE"}
UPGRADE_CLOSURE_BASES = {
    "ALLOCATOR_GEOMETRY_BLOCKS_CONTROL",
    "CONTROL_DATA_UNREACHABLE",
    "MITIGATION_PREVENTS_STRONGER_IMPACT",
    "PRODUCT_PATH_UNREACHABLE",
    "SUPPORTED_BOUNDARY_EXCLUDES_PATH",
    "SEMANTICALLY_NOT_APPLICABLE",
}
ABSENCE_OF_PROOF_RE = re.compile(
    r"\b(?:not demonstrated|not yet|remains? untested|untested|"
    r"could not (?:prove|reproduce|demonstrate)|"
    r"no stable .{0,80}? (?:shown|demonstrated|found))\b",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class CandidateChallengeError(RuntimeError):
    pass


def _proof_records(dossier: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return named admission checks while accepting durable legacy dossiers."""
    proof = dossier.get("proof")
    if not isinstance(proof, dict):
        raise CandidateChallengeError("candidate proof contract is missing")
    if all(isinstance(proof.get(gate), dict) for gate in PROOF_GATES):
        return {gate: proof[gate] for gate in PROOF_GATES}
    if all(isinstance(proof.get(level), dict) for level in LEGACY_PROOF_LEVELS):
        records = {
            gate: proof[level]
            for level, gate in LEGACY_TO_NAMED_GATES.items()
        }
        legacy_admission = proof["L4"]
        records["hard_eligibility"] = {
            **legacy_admission,
            "status": legacy_admission.get(
                "eligibility_status", legacy_admission.get("status")
            ),
        }
        records["economic_review"] = {
            **legacy_admission,
            "status": legacy_admission.get(
                "economic_status", legacy_admission.get("status")
            ),
        }
        return records
    raise CandidateChallengeError(
        "candidate proof contract must contain every named admission check"
    )


def _admission_statuses(dossier: dict[str, Any]) -> tuple[str, str]:
    records = _proof_records(dossier)
    return (
        str(records["hard_eligibility"].get("status", "")),
        str(records["economic_review"].get("status", "")),
    )


def _result_proof_statuses(payload: dict[str, Any]) -> dict[str, str]:
    raw = payload.get("proof_status")
    if not isinstance(raw, dict):
        raise CandidateChallengeError(
            "candidate challenge result proof status is invalid"
        )
    if all(gate in raw for gate in PROOF_GATES):
        return {gate: str(raw[gate]) for gate in PROOF_GATES}
    if all(level in raw for level in LEGACY_PROOF_LEVELS):
        statuses = {
            gate: str(raw[level])
            for level, gate in LEGACY_TO_NAMED_GATES.items()
        }
        statuses["hard_eligibility"] = str(
            payload.get("eligibility_status", raw["L4"])
        )
        statuses["economic_review"] = str(
            payload.get("economic_status", raw["L4"])
        )
        return statuses
    raise CandidateChallengeError(
        "candidate challenge result lacks named admission checks"
    )


def _require_admission_proof(
    dossier: dict[str, Any], disposition: str
) -> None:
    proof = _proof_records(dossier)
    if any(
        proof[gate]["status"] != "PASS"
        for gate in HARD_PROOF_GATES
    ):
        raise CandidateChallengeError(
            f"{disposition} requires every technical proof check to PASS"
        )
    eligibility_status, economic_status = _admission_statuses(dossier)
    if eligibility_status != "PASS":
        raise CandidateChallengeError(
            f"{disposition} requires hard eligibility to PASS"
        )
    if disposition == "ADMIT_PROOF" and economic_status != "PASS":
        raise CandidateChallengeError(
            "ADMIT_PROOF requires economic review to PASS"
        )
    if disposition == "OPERATOR_EXCEPTION" and economic_status not in {
        "PASS",
        "PARTIAL",
    }:
        raise CandidateChallengeError(
            "OPERATOR_EXCEPTION may override only a PARTIAL economic review"
        )


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _private_json_path(workspace: Path, value: str | Path, label: str) -> Path:
    path = Path(value).resolve()
    if path.suffix.casefold() != ".json":
        raise CandidateChallengeError(f"{label} must use a .json filename")
    if not path.is_file():
        raise CandidateChallengeError(f"{label} does not exist: {path}")
    if not _is_within(path, workspace):
        raise CandidateChallengeError(f"{label} must stay inside the workspace")
    for root in ((workspace / "ZDI").resolve(), (workspace / "ZDI_STAGING").resolve()):
        if _is_within(path, root):
            raise CandidateChallengeError(
                f"{label} must stay outside external package roots"
            )
    return path


def _private_output_path(workspace: Path, value: str | Path) -> Path:
    path = Path(value).resolve()
    if path.suffix.casefold() != ".json":
        raise CandidateChallengeError("challenge result must use a .json filename")
    if not _is_within(path, workspace):
        raise CandidateChallengeError(
            "challenge result must stay inside the workspace"
        )
    for root in ((workspace / "ZDI").resolve(), (workspace / "ZDI_STAGING").resolve()):
        if _is_within(path, root):
            raise CandidateChallengeError(
                "challenge result must stay outside external package roots"
            )
    return path


def _require_nonempty_string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CandidateChallengeError(f"dossier field is required: {field}")
    return value.strip()


def validate_dossier(
    workspace: str | Path,
    dossier_path: str | Path,
) -> tuple[Path, dict[str, Any]]:
    workspace_path = Path(workspace).resolve()
    path = _private_json_path(workspace_path, dossier_path, "candidate dossier")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateChallengeError(
            f"cannot read candidate dossier: {error}"
        ) from error
    if not isinstance(payload, dict) or payload.get("schema") != DOSSIER_SCHEMA:
        raise CandidateChallengeError("candidate dossier schema is invalid")

    for field in (
        "candidate_key",
        "candidate_title",
        "product",
        "version",
        "target_slug",
        "goal_path",
        "goal_hash",
        "inventory_digest",
        "root_family_id",
    ):
        _require_nonempty_string(payload, field)
    if any(
        not isinstance(payload.get(field), str) or not payload[field].strip()
        for field in (
            "current_version_receipt_path",
            "current_version_receipt_sha256",
        )
    ):
        raise CandidateChallengeError("current-version receipt fields are required")
    if any(
        not isinstance(payload.get(field), str) or not payload[field].strip()
        for field in (
            "public_prior_art_receipt_path",
            "public_prior_art_receipt_sha256",
        )
    ):
        raise CandidateChallengeError("public-prior-art receipt fields are required")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,128}", payload["candidate_key"]):
        raise CandidateChallengeError("candidate_key format is invalid")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", payload["target_slug"]):
        raise CandidateChallengeError("target_slug format is invalid")
    if not HASH_RE.fullmatch(payload["goal_hash"]):
        raise CandidateChallengeError("goal_hash is invalid")
    if not HASH_RE.fullmatch(payload["current_version_receipt_sha256"]):
        raise CandidateChallengeError("current-version receipt hash is invalid")
    if not HASH_RE.fullmatch(payload["public_prior_art_receipt_sha256"]):
        raise CandidateChallengeError("public-prior-art receipt hash is invalid")
    if not HASH_RE.fullmatch(payload["inventory_digest"]):
        raise CandidateChallengeError("inventory_digest is invalid")
    reviewed = payload.get("reviewed_item_ids")
    if (
        not isinstance(reviewed, list)
        or any(
            not isinstance(item_id, int)
            or isinstance(item_id, bool)
            or item_id == 0
            for item_id in reviewed
        )
        or len(set(reviewed)) != len(reviewed)
    ):
        raise CandidateChallengeError("reviewed_item_ids is invalid")

    goal_path = Path(payload["goal_path"]).resolve()
    target_root = (workspace_path / "targets").resolve()
    if (
        not goal_path.is_file()
        or goal_path.name != "GOAL.md"
        or not _is_within(goal_path, target_root)
    ):
        raise CandidateChallengeError("goal_path is not a current target GOAL.md")
    if _sha256(goal_path) != payload["goal_hash"]:
        raise CandidateChallengeError("goal_hash does not match current goal bytes")
    expected_goal_path = (
        workspace_path / "targets" / payload["target_slug"] / "GOAL.md"
    ).resolve()
    if goal_path != expected_goal_path:
        raise CandidateChallengeError(
            "target_slug does not match the candidate goal_path"
        )

    attacker = payload.get("attacker")
    if not isinstance(attacker, dict):
        raise CandidateChallengeError("attacker contract is missing")
    for field in (
        "identity",
        "product_role",
        "network_position",
        "transport",
        "prerequisites",
    ):
        _require_nonempty_string(attacker, field)

    boundary = payload.get("supported_boundary")
    if not isinstance(boundary, dict):
        raise CandidateChallengeError("supported_boundary contract is missing")
    for field in ("deployment", "exposure", "configuration", "privilege"):
        _require_nonempty_string(boundary, field)

    proof = payload.get("proof")
    records = _proof_records(payload)
    for gate, record in records.items():
        if record.get("status") not in PROOF_STATUSES:
            raise CandidateChallengeError(f"{gate} status is invalid")
        if not isinstance(record.get("claim"), str) or not record["claim"].strip():
            raise CandidateChallengeError(f"{gate} claim is required")
        refs = record.get("evidence_refs")
        if not isinstance(refs, list) or any(
            not isinstance(ref, str) or not ref.strip() for ref in refs
        ):
            raise CandidateChallengeError(f"{gate} evidence_refs are invalid")

    if isinstance(proof, dict) and all(
        level in proof for level in LEGACY_PROOF_LEVELS
    ):
        legacy_admission = proof["L4"]
        has_eligibility = "eligibility_status" in legacy_admission
        has_economics = "economic_status" in legacy_admission
        if has_eligibility != has_economics:
            raise CandidateChallengeError(
                "legacy admission must define both eligibility_status and "
                "economic_status"
            )
        if has_eligibility:
            eligibility_status = legacy_admission["eligibility_status"]
            economic_status = legacy_admission["economic_status"]
            if eligibility_status not in PROOF_STATUSES:
                raise CandidateChallengeError("hard eligibility status is invalid")
            if economic_status not in PROOF_STATUSES:
                raise CandidateChallengeError("economic review status is invalid")
            if "FAIL" in {eligibility_status, economic_status}:
                expected_status = "FAIL"
            elif "NOT_RUN" in {eligibility_status, economic_status}:
                expected_status = "NOT_RUN"
            elif eligibility_status == economic_status == "PASS":
                expected_status = "PASS"
            else:
                expected_status = "PARTIAL"
            if legacy_admission["status"] != expected_status:
                raise CandidateChallengeError(
                    "legacy admission status does not match eligibility and "
                    "economic review"
                )

    matrices = payload.get("matrices")
    if not isinstance(matrices, dict):
        raise CandidateChallengeError("candidate matrices are missing")
    for field in ("role_object", "lifecycle", "claim_to_evidence"):
        value = matrices.get(field)
        if not isinstance(value, list) or not value or any(
            not isinstance(entry, dict) for entry in value
        ):
            raise CandidateChallengeError(f"candidate matrix is invalid: {field}")
    version_identity = matrices.get("version_identity")
    if not isinstance(version_identity, dict):
        raise CandidateChallengeError("version_identity matrix is missing")
    if version_identity.get("release") != payload["version"]:
        raise CandidateChallengeError(
            "version_identity release does not match dossier version"
        )
    artifact_hash = version_identity.get("artifact_sha256")
    if not isinstance(artifact_hash, str) or not HASH_RE.fullmatch(artifact_hash):
        raise CandidateChallengeError("version_identity artifact hash is invalid")

    adverse = payload.get("adverse_prior_art")
    if not isinstance(adverse, list) or not adverse or any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("reference"), str)
        or not entry["reference"].strip()
        or not isinstance(entry.get("analysis"), str)
        or not entry["analysis"].strip()
        or entry.get("disposition") not in PRIOR_ART_DISPOSITIONS
        for entry in adverse
    ):
        raise CandidateChallengeError("adverse_prior_art is missing or invalid")

    upgrade = payload.get("exploit_upgrade_challenge")
    if not isinstance(upgrade, dict) or upgrade.get("outcome") not in UPGRADE_OUTCOMES:
        raise CandidateChallengeError("exploit-upgrade challenge is missing or invalid")
    upgrade_paths = upgrade.get("paths")
    if not isinstance(upgrade_paths, list) or not upgrade_paths:
        raise CandidateChallengeError("exploit-upgrade challenge paths are missing")
    for entry in upgrade_paths:
        evidence_refs = entry.get("evidence_refs") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("path"), str)
            or not entry["path"].strip()
            or entry.get("disposition") not in UPGRADE_DISPOSITIONS
            or not isinstance(entry.get("reason"), str)
            or not entry["reason"].strip()
            or not isinstance(evidence_refs, list)
            or not evidence_refs
            or any(
                not isinstance(reference, str) or not reference.strip()
                for reference in evidence_refs
            )
        ):
            raise CandidateChallengeError(
                "exploit-upgrade challenge requires every stronger path to be proved or closed"
            )
        disposition = str(entry["disposition"])
        if disposition in {"CLOSED", "NOT_APPLICABLE"}:
            closure_basis = entry.get("closure_basis")
            if closure_basis not in UPGRADE_CLOSURE_BASES:
                raise CandidateChallengeError(
                    "exploit-upgrade CLOSED paths require a valid closure_basis"
                )
            if (
                disposition == "NOT_APPLICABLE"
                and closure_basis != "SEMANTICALLY_NOT_APPLICABLE"
            ):
                raise CandidateChallengeError(
                    "NOT_APPLICABLE upgrade paths require the semantic closure_basis"
                )
            if ABSENCE_OF_PROOF_RE.search(str(entry["reason"])):
                raise CandidateChallengeError(
                    "absence of proof or untested work is not exploit-upgrade closure"
                )
            for reference in evidence_refs:
                evidence_path = (workspace_path / str(reference)).resolve()
                if not _is_within(evidence_path, workspace_path) or not evidence_path.is_file():
                    raise CandidateChallengeError(
                        "exploit-upgrade closure evidence must be an existing private file"
                    )

    outcome = payload.get("economic_outcome")
    if not isinstance(outcome, dict):
        raise CandidateChallengeError("economic_outcome is missing")
    portfolio_class = outcome.get("portfolio_class")
    if portfolio_class not in PORTFOLIO_CLASSES:
        raise CandidateChallengeError("portfolio_class is invalid")
    payout = outcome.get("likely_payout_usd")
    low = payout.get("low") if isinstance(payout, dict) else None
    high = payout.get("high") if isinstance(payout, dict) else None
    ceiling = outcome.get("theoretical_ceiling_usd")
    if (
        not isinstance(low, int)
        or isinstance(low, bool)
        or low < 0
        or not isinstance(high, int)
        or isinstance(high, bool)
        or high < low
        or not isinstance(ceiling, int)
        or isinstance(ceiling, bool)
        or ceiling < high
    ):
        raise CandidateChallengeError("candidate payout calibration is invalid")
    rank = outcome.get("same_product_rank")
    if not isinstance(rank, int) or isinstance(rank, bool) or rank <= 0:
        raise CandidateChallengeError("same_product_rank is invalid")
    _require_nonempty_string(outcome, "chain_role")
    operator_exception = outcome.get("operator_exception")
    instruction = outcome.get("operator_instruction")
    if not isinstance(operator_exception, bool):
        raise CandidateChallengeError("operator_exception must be boolean")
    if portfolio_class == "TIER_B_EXCEPTION" and (
        operator_exception is not True
        or not isinstance(instruction, str)
        or not instruction.strip()
    ):
        raise CandidateChallengeError(
            "Tier-B exception requires the exact operator instruction"
        )
    if portfolio_class != "TIER_B_EXCEPTION" and operator_exception:
        raise CandidateChallengeError(
            "operator_exception is valid only for TIER_B_EXCEPTION"
        )
    return path, payload


def _validate_current_admission_identity(
    workspace: Path,
    db_path: Path,
    payload: dict[str, Any],
    *,
    exclude_package_number: int | None = None,
    allow_recorded_target_authority: bool = False,
) -> None:
    # Imported lazily because package_preflight also consumes this module.
    from package_preflight import PreflightError, load_candidate_inventory
    from current_version_gate import CurrentVersionError, validate_receipt
    from public_prior_art_gate import PublicPriorArtError, validate_receipt as validate_prior_art

    try:
        receipt = validate_receipt(
            workspace,
            payload["current_version_receipt_path"],
            target_slug=payload["target_slug"],
            product=payload["product"],
            version=payload["version"],
            expected_sha256=payload["current_version_receipt_sha256"],
            allow_registered_legacy_authority=exclude_package_number is not None,
            allow_recorded_target_authority=allow_recorded_target_authority,
        )
    except CurrentVersionError as error:
        raise CandidateChallengeError(str(error)) from error
    dossier_artifact = str(
        payload.get("matrices", {})
        .get("version_identity", {})
        .get("artifact_sha256", "")
    )
    receipt_artifact = str(receipt.get("artifact", {}).get("sha256", ""))
    if dossier_artifact != receipt_artifact:
        raise CandidateChallengeError(
            "candidate version-identity artifact hash does not match "
            "the current-version receipt"
        )

    try:
        prior_art_receipt = validate_prior_art(
            workspace,
            payload["public_prior_art_receipt_path"],
            target_slug=payload["target_slug"],
            product=payload["product"],
            root_family_id=payload["root_family_id"],
            expected_sha256=payload["public_prior_art_receipt_sha256"],
        )
    except PublicPriorArtError as error:
        raise CandidateChallengeError(str(error)) from error

    dispositioned = {
        str(entry["reference"]).strip(): entry
        for entry in payload["adverse_prior_art"]
        if isinstance(entry, dict) and isinstance(entry.get("reference"), str)
    }
    returned_urls = {
        str(result["url"]).strip()
        for search in prior_art_receipt.get("searches", [])
        if isinstance(search, dict)
        for result in search.get("results", [])
        if isinstance(result, dict)
        and isinstance(result.get("url"), str)
        and result["url"].strip()
    }
    missing_dispositions = sorted(returned_urls - set(dispositioned))
    if missing_dispositions:
        raise CandidateChallengeError(
            "undispositioned public prior-art result(s): "
            + ", ".join(missing_dispositions)
        )
    unassessed_results = sorted(
        reference
        for reference in returned_urls
        if dispositioned[reference].get("root_relation")
        not in PRIOR_ART_ROOT_RELATIONS
        or dispositioned[reference].get("remediation_status")
        not in PRIOR_ART_REMEDIATION_STATUSES
    )
    if unassessed_results:
        raise CandidateChallengeError(
            "public prior-art result lacks explicit root/remediation assessment: "
            + ", ".join(unassessed_results)
        )

    try:
        inventory = load_candidate_inventory(
            workspace,
            payload["product"],
            db_path,
            exclude_package_number=exclude_package_number,
        )
    except PreflightError as error:
        raise CandidateChallengeError(str(error)) from error
    expected_ids = [int(item["id"]) for item in inventory["items"]]
    reviewed = payload["reviewed_item_ids"]
    if (
        payload["inventory_digest"] != inventory["digest"]
        or sorted(reviewed) != sorted(expected_ids)
    ):
        raise CandidateChallengeError(
            "candidate inventory identity is incomplete or stale"
        )

    lifecycle_db = (
        workspace
        / "notes"
        / "target_lifecycle"
        / "target_lifecycle.sqlite3"
    )
    if not lifecycle_db.is_file():
        raise CandidateChallengeError(
            "candidate identity requires exactly one ACTIVE target"
        )
    try:
            with sqlite3.connect(lifecycle_db, timeout=5) as connection:
                connection.row_factory = sqlite3.Row
                if allow_recorded_target_authority:
                    active_rows = connection.execute(
                        """
                        SELECT slug, product, current_version, mirror_path, goal_sha256
                        FROM targets
                        WHERE slug = ? AND status IN ('ACTIVE', 'PARKED_REHYDRATABLE')
                        """,
                        (payload["target_slug"],),
                    ).fetchall()
                else:
                    active_rows = connection.execute(
                        """
                        SELECT slug, product, current_version, mirror_path, goal_sha256
                        FROM targets WHERE status = 'ACTIVE' ORDER BY slug
                        """
                    ).fetchall()
    except sqlite3.Error as error:
        raise CandidateChallengeError(
            f"cannot validate candidate ACTIVE target: {error}"
        ) from error
    if len(active_rows) != 1:
            message = (
                "candidate identity requires recorded target authority"
                if allow_recorded_target_authority
                else "candidate identity requires exactly one ACTIVE target"
            )
            raise CandidateChallengeError(message)
    active = active_rows[0]
    active_goal = Path(str(active["mirror_path"] or ""))
    if not active_goal.is_absolute():
        active_goal = workspace / active_goal
    current_version = str(active["current_version"] or "")
    if (
        str(active["slug"]) != payload["target_slug"]
        or str(active["product"]) != payload["product"]
        or (current_version and current_version != payload["version"])
        or active_goal.resolve() != Path(payload["goal_path"]).resolve()
        or str(active["goal_sha256"] or "") != payload["goal_hash"]
    ):
        message = (
            "candidate identity does not match the recorded rework target"
            if allow_recorded_target_authority
            else "candidate identity does not match the current ACTIVE target"
        )
        raise CandidateChallengeError(message)


class CandidateChallengeStore:
    def __init__(self, db_path: str | Path, workspace: str | Path):
        self.db_path = Path(db_path).resolve()
        self.workspace = Path(workspace).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_item_id INTEGER,
                    actor TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS candidate_challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_key TEXT NOT NULL,
                    candidate_title TEXT NOT NULL,
                    product TEXT NOT NULL,
                    version TEXT NOT NULL,
                    target_slug TEXT NOT NULL,
                    goal_path TEXT NOT NULL,
                    goal_hash TEXT NOT NULL,
                    inventory_digest TEXT NOT NULL,
                    root_family_id TEXT NOT NULL,
                    dossier_path TEXT NOT NULL,
                    dossier_sha256 TEXT NOT NULL,
                    dossier_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    reviewer TEXT NOT NULL DEFAULT '',
                    disposition TEXT NOT NULL DEFAULT '',
                    decision_path TEXT NOT NULL DEFAULT '',
                    decision_sha256 TEXT NOT NULL DEFAULT '',
                    decision_json TEXT NOT NULL DEFAULT '{}',
                    package_number INTEGER,
                    created_at TEXT NOT NULL,
                    claimed_at TEXT,
                    decided_at TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE(candidate_key, dossier_sha256)
                );

                CREATE TABLE IF NOT EXISTS operator_exception_authorizations (
                    candidate_id INTEGER PRIMARY KEY,
                    candidate_key TEXT NOT NULL,
                    dossier_sha256 TEXT NOT NULL,
                    instruction_sha256 TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    authorized_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    state TEXT NOT NULL,
                    FOREIGN KEY(candidate_id) REFERENCES candidate_challenges(id)
                );

                CREATE TABLE IF NOT EXISTS worker_status (
                    worker TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    task TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result.pop("dossier_json", None)
        result.pop("decision_json", None)
        return result

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        actor: str,
        event_type: str,
        detail: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO events(work_item_id, actor, event_type, detail_json, created_at)
            VALUES (NULL, ?, ?, ?, ?)
            """,
            (
                actor,
                event_type,
                json.dumps(detail, ensure_ascii=True, sort_keys=True),
                utc_now(),
            ),
        )

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

    @staticmethod
    def _final_rework_refresh_context(
        connection: sqlite3.Connection,
        candidate: sqlite3.Row,
    ) -> dict[str, int] | None:
        """Return exact durable Final Rework lineage, or None for ordinary candidates."""
        matching_events: list[dict[str, Any]] = []
        for event in connection.execute(
            """
            SELECT detail_json FROM events
            WHERE event_type = 'FINAL_REWORK_CANDIDATE_REFRESH_SUBMITTED'
            ORDER BY id
            """
        ):
            try:
                detail = json.loads(event["detail_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(detail, dict) and detail.get("candidate_id") == int(
                candidate["id"]
            ):
                matching_events.append(detail)
        if not matching_events:
            return None
        if len(matching_events) != 1:
            raise CandidateChallengeError(
                "Final Rework candidate refresh lineage is ambiguous"
            )
        detail = matching_events[0]
        integer_fields = (
            "candidate_id",
            "item_id",
            "package_number",
            "prior_candidate_id",
            "request_id",
        )
        if any(
            not isinstance(detail.get(field), int)
            or isinstance(detail.get(field), bool)
            or int(detail[field]) <= 0
            for field in integer_fields
        ) or detail.get("dossier_sha256") != candidate["dossier_sha256"]:
            raise CandidateChallengeError(
                "Final Rework candidate refresh lineage is invalid"
            )
        if (
            candidate["package_number"] is None
            or int(candidate["package_number"]) != int(detail["package_number"])
        ):
            raise CandidateChallengeError(
                "Final Rework candidate package identity is stale"
            )
        lineage = connection.execute(
            """
            SELECT
                frr.work_item_id,
                frr.review_scope,
                frr.prior_candidate_challenge_id,
                frr.state AS request_state,
                wi.state AS item_state,
                wi.candidate_challenge_id AS item_candidate_id,
                wi.package_path,
                wi.revision
            FROM final_rework_requests AS frr
            JOIN work_items AS wi ON wi.id = frr.work_item_id
            WHERE frr.id = ? AND wi.id = ?
            """,
            (int(detail["request_id"]), int(detail["item_id"])),
        ).fetchone()
        if (
            lineage is None
            or lineage["request_state"] != "CLAIMED"
            or lineage["item_state"] != "FINAL_REWORK"
            or lineage["review_scope"] not in {"EVIDENCE_ONLY", "SEMANTIC"}
            or lineage["prior_candidate_challenge_id"]
            != int(detail["prior_candidate_id"])
        ):
            raise CandidateChallengeError(
                "Final Rework candidate no longer has claimed reviewed lineage"
            )
        package_match = re.match(r"^(\d+)_", Path(lineage["package_path"]).name)
        if (
            package_match is None
            or int(package_match.group(1)) != int(detail["package_number"])
        ):
            raise CandidateChallengeError(
                "Final Rework candidate package identity is stale"
            )
        prior = connection.execute(
            "SELECT * FROM candidate_challenges WHERE id = ?",
            (int(detail["prior_candidate_id"]),),
        ).fetchone()
        if (
            prior is None
            or prior["state"] != "DECIDED"
            or prior["disposition"] not in ADMITTED_DISPOSITIONS
            or prior["package_number"] != int(detail["package_number"])
        ):
            raise CandidateChallengeError(
                "Final Rework candidate reviewed lineage is stale"
            )
        for field in (
            "candidate_key",
            "product",
            "version",
            "target_slug",
            "root_family_id",
        ):
            if candidate[field] != prior[field]:
                raise CandidateChallengeError(
                    f"Final Rework candidate changes protected identity field: {field}"
                )
        item_candidate_id = int(lineage["item_candidate_id"])
        if item_candidate_id not in {
            int(detail["prior_candidate_id"]),
            int(candidate["id"]),
        }:
            raise CandidateChallengeError(
                "Final Rework candidate item lineage is stale"
            )
        if item_candidate_id == int(candidate["id"]):
            rebound = connection.execute(
                """
                SELECT id FROM events
                WHERE work_item_id = ?
                  AND event_type = 'FINAL_REWORK_CANDIDATE_REBOUND'
                  AND json_extract(detail_json, '$.candidate_id') = ?
                  AND json_extract(detail_json, '$.prior_candidate_id') = ?
                  AND json_extract(detail_json, '$.request_id') = ?
                LIMIT 1
                """,
                (
                    int(detail["item_id"]),
                    int(candidate["id"]),
                    int(detail["prior_candidate_id"]),
                    int(detail["request_id"]),
                ),
            ).fetchone()
            if rebound is None:
                raise CandidateChallengeError(
                    "Final Rework candidate rebound lineage is unavailable"
                )
        return {
            "item_id": int(detail["item_id"]),
            "package_number": int(detail["package_number"]),
            "prior_candidate_id": int(detail["prior_candidate_id"]),
            "request_id": int(detail["request_id"]),
        }

    def _supersede_undecided_revisions(
        self,
        connection: sqlite3.Connection,
        payload: dict[str, Any],
        replacement_id: int,
        replacement_sha256: str,
        timestamp: str,
    ) -> None:
        obsolete_rows = connection.execute(
            """
            SELECT id, dossier_sha256, state, reviewer
            FROM candidate_challenges
            WHERE candidate_key = ? AND id != ?
              AND state IN ('PENDING', 'CLAIMED')
            ORDER BY id
            """,
            (payload["candidate_key"], replacement_id),
        ).fetchall()
        connection.executemany(
            """
            UPDATE candidate_challenges
            SET state = 'SUPERSEDED', updated_at = ?
            WHERE id = ? AND state IN ('PENDING', 'CLAIMED')
            """,
            ((timestamp, int(row["id"])) for row in obsolete_rows),
        )
        for obsolete in obsolete_rows:
            self._event(
                connection,
                "hunter",
                "CANDIDATE_CHALLENGE_SUPERSEDED",
                {
                    "candidate_id": int(obsolete["id"]),
                    "candidate_key": payload["candidate_key"],
                    "dossier_sha256": obsolete["dossier_sha256"],
                    "prior_state": obsolete["state"],
                    "prior_reviewer": obsolete["reviewer"],
                    "product": payload["product"],
                    "superseded_by_candidate_id": replacement_id,
                    "superseded_by_dossier_sha256": replacement_sha256,
                    "summary": (
                        "Undecided Candidate Challenge revision superseded "
                        "by a newly validated dossier for the same candidate key"
                    ),
                },
            )

    def submit(self, dossier_path: str | Path) -> dict[str, Any]:
        path, payload = validate_dossier(self.workspace, dossier_path)
        _validate_current_admission_identity(
            self.workspace, self.db_path, payload
        )
        dossier_sha256 = _sha256(path)
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """
                SELECT * FROM candidate_challenges
                WHERE candidate_key = ? AND dossier_sha256 = ?
                """,
                (payload["candidate_key"], dossier_sha256),
            ).fetchone()
            if prior is not None:
                self._supersede_undecided_revisions(
                    connection,
                    payload,
                    int(prior["id"]),
                    dossier_sha256,
                    timestamp,
                )
                current = connection.execute(
                    "SELECT * FROM candidate_challenges WHERE id = ?",
                    (int(prior["id"]),),
                ).fetchone()
                return self._record(current)
            cursor = connection.execute(
                """
                INSERT INTO candidate_challenges(
                    candidate_key, candidate_title, product, version, target_slug,
                    goal_path, goal_hash, inventory_digest, root_family_id,
                    dossier_path, dossier_sha256, dossier_json, state,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
                """,
                (
                    payload["candidate_key"],
                    payload["candidate_title"],
                    payload["product"],
                    payload["version"],
                    payload["target_slug"],
                    payload["goal_path"],
                    payload["goal_hash"],
                    payload["inventory_digest"],
                    payload["root_family_id"],
                    str(path),
                    dossier_sha256,
                    json.dumps(payload, ensure_ascii=True, sort_keys=True),
                    timestamp,
                    timestamp,
                ),
            )
            candidate_id = int(cursor.lastrowid)
            self._supersede_undecided_revisions(
                connection,
                payload,
                candidate_id,
                dossier_sha256,
                timestamp,
            )
            self._event(
                connection,
                "hunter",
                "CANDIDATE_CHALLENGE_SUBMITTED",
                {
                    "candidate_id": candidate_id,
                    "candidate_key": payload["candidate_key"],
                    "dossier_sha256": dossier_sha256,
                    "product": payload["product"],
                    "summary": (
                        f"Candidate challenge submitted: "
                        f"{payload['candidate_title']}"
                    ),
                },
            )
            row = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            return self._record(row)

    def submit_final_rework_refresh(
        self, item_id: int, dossier_path: str | Path
    ) -> dict[str, Any]:
        if not isinstance(item_id, int) or item_id <= 0:
            raise CandidateChallengeError("work item id must be a positive integer")
        path, payload = validate_dossier(self.workspace, dossier_path)
        with self._connect() as connection:
            item = connection.execute(
                "SELECT * FROM work_items WHERE id = ?", (item_id,)
            ).fetchone()
            if item is None:
                raise CandidateChallengeError(f"unknown work item: {item_id}")
            if item["state"] != "FINAL_REWORK":
                raise CandidateChallengeError(
                    "candidate refresh requires a claimed FINAL_REWORK item"
                )
            request = connection.execute(
                """
                SELECT id, review_scope, prior_candidate_challenge_id
                FROM final_rework_requests
                WHERE work_item_id = ? AND state = 'CLAIMED'
                ORDER BY id DESC LIMIT 1
                """,
                (item_id,),
            ).fetchone()
            if request is None:
                raise CandidateChallengeError(
                    "candidate refresh requires a claimed final rework request"
                )
            prior_candidate_id = item["candidate_challenge_id"]
            if prior_candidate_id is None:
                raise CandidateChallengeError(
                    "final rework item has no Candidate Challenge binding"
                )
            prior_candidate = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (int(prior_candidate_id),),
            ).fetchone()
            if prior_candidate is None or prior_candidate["package_number"] is None:
                raise CandidateChallengeError(
                    "prior Candidate Challenge package binding is incomplete"
                )
            if (
                request["review_scope"] not in {"EVIDENCE_ONLY", "SEMANTIC"}
                or request["prior_candidate_challenge_id"] != int(prior_candidate_id)
                or prior_candidate["state"] != "DECIDED"
                or prior_candidate["disposition"] not in ADMITTED_DISPOSITIONS
            ):
                raise CandidateChallengeError(
                    "candidate refresh reviewed Final Rework lineage is invalid"
                )
            request_id = int(request["id"])
            package_number = int(prior_candidate["package_number"])
            package_path = str(item["package_path"])
            package_match = re.match(r"^(\d+)_", Path(item["package_path"]).name)
            if package_match is None or int(package_match.group(1)) != package_number:
                raise CandidateChallengeError(
                    "candidate refresh package identity does not match the claimed item"
                )
            if (
                item["product"] != payload["product"]
                or item["version"] != payload["version"]
            ):
                raise CandidateChallengeError(
                    "candidate refresh product/version does not match the claimed item"
                )
            for field in (
                "candidate_key",
                "product",
                "version",
                "target_slug",
                "root_family_id",
            ):
                if payload[field] != prior_candidate[field]:
                    raise CandidateChallengeError(
                        f"refreshed candidate changes protected identity field: {field}"
                    )

        _validate_current_admission_identity(
            self.workspace,
            self.db_path,
            payload,
            exclude_package_number=package_number,
            allow_recorded_target_authority=True,
        )
        dossier_sha256 = _sha256(path)
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = connection.execute(
                "SELECT * FROM work_items WHERE id = ?", (item_id,)
            ).fetchone()
            if item is None or item["state"] != "FINAL_REWORK":
                raise CandidateChallengeError(
                    "candidate refresh lost claimed FINAL_REWORK authority"
                )
            request = connection.execute(
                """
                SELECT id, review_scope, prior_candidate_challenge_id
                FROM final_rework_requests
                WHERE work_item_id = ? AND state = 'CLAIMED'
                ORDER BY id DESC LIMIT 1
                """,
                (item_id,),
            ).fetchone()
            if (
                request is None
                or request["review_scope"] not in {"EVIDENCE_ONLY", "SEMANTIC"}
                or int(request["id"]) != request_id
                or request["prior_candidate_challenge_id"] != int(prior_candidate_id)
                or item["candidate_challenge_id"] != int(prior_candidate_id)
                or str(item["package_path"]) != package_path
                or item["product"] != payload["product"]
                or item["version"] != payload["version"]
            ):
                raise CandidateChallengeError(
                    "candidate refresh authority changed during validation"
                )
            current_prior_candidate = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (int(prior_candidate_id),),
            ).fetchone()
            if (
                current_prior_candidate is None
                or current_prior_candidate["state"] != "DECIDED"
                or current_prior_candidate["disposition"] not in ADMITTED_DISPOSITIONS
                or current_prior_candidate["package_number"] != package_number
                or current_prior_candidate["dossier_sha256"]
                != prior_candidate["dossier_sha256"]
                or any(
                    payload[field] != current_prior_candidate[field]
                    for field in (
                        "candidate_key",
                        "product",
                        "version",
                        "target_slug",
                        "root_family_id",
                    )
                )
            ):
                raise CandidateChallengeError(
                    "candidate refresh authority changed during validation"
                )
            existing = connection.execute(
                """
                SELECT * FROM candidate_challenges
                WHERE candidate_key = ? AND dossier_sha256 = ?
                """,
                (payload["candidate_key"], dossier_sha256),
            ).fetchone()
            if existing is not None:
                if existing["package_number"] != package_number:
                    raise CandidateChallengeError(
                        "existing refreshed candidate has a different package binding"
                    )
                context = self._final_rework_refresh_context(connection, existing)
                expected_context = {
                    "item_id": item_id,
                    "package_number": package_number,
                    "prior_candidate_id": int(prior_candidate_id),
                    "request_id": request_id,
                }
                if context != expected_context:
                    raise CandidateChallengeError(
                        "existing candidate is not bound to this Final Rework request"
                    )
                return self._record(existing)
            cursor = connection.execute(
                """
                INSERT INTO candidate_challenges(
                    candidate_key, candidate_title, product, version, target_slug,
                    goal_path, goal_hash, inventory_digest, root_family_id,
                    dossier_path, dossier_sha256, dossier_json, state,
                    package_number, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
                """,
                (
                    payload["candidate_key"],
                    payload["candidate_title"],
                    payload["product"],
                    payload["version"],
                    payload["target_slug"],
                    payload["goal_path"],
                    payload["goal_hash"],
                    payload["inventory_digest"],
                    payload["root_family_id"],
                    str(path),
                    dossier_sha256,
                    json.dumps(payload, ensure_ascii=True, sort_keys=True),
                    package_number,
                    timestamp,
                    timestamp,
                ),
            )
            candidate_id = int(cursor.lastrowid)
            self._event(
                connection,
                "hunter",
                "FINAL_REWORK_CANDIDATE_REFRESH_SUBMITTED",
                {
                    "candidate_id": candidate_id,
                    "candidate_key": payload["candidate_key"],
                    "dossier_sha256": dossier_sha256,
                    "item_id": item_id,
                    "package_number": package_number,
                    "prior_candidate_id": int(prior_candidate_id),
                    "request_id": int(request["id"]),
                    "summary": (
                        f"Candidate Challenge refresh submitted for package "
                        f"{package_number} final rework"
                    ),
                },
            )
            row = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            return self._record(row)

    def claim_next(self, reviewer: str) -> dict[str, Any] | None:
        if not isinstance(reviewer, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", reviewer
        ):
            raise CandidateChallengeError("reviewer name is invalid")
        reviewer = reviewer.casefold()
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM candidate_challenges
                WHERE state = 'CLAIMED' AND reviewer = ?
                ORDER BY id LIMIT 1
                """,
                (reviewer,),
            ).fetchone()
            resumed = row is not None
            if row is None:
                row = connection.execute(
                    """
                    SELECT * FROM candidate_challenges
                    WHERE state = 'PENDING' ORDER BY id LIMIT 1
                    """
                ).fetchone()
                if row is None:
                    return None
                connection.execute(
                    """
                    UPDATE candidate_challenges
                    SET state = 'CLAIMED', reviewer = ?, claimed_at = ?,
                        updated_at = ?
                    WHERE id = ? AND state = 'PENDING'
                    """,
                    (reviewer, timestamp, timestamp, int(row["id"])),
                )
                self._event(
                    connection,
                    reviewer,
                    "CANDIDATE_CHALLENGE_CLAIMED",
                    {
                        "candidate_id": int(row["id"]),
                        "candidate_key": row["candidate_key"],
                        "product": row["product"],
                        "summary": (
                            f"Candidate challenge claimed: "
                            f"{row['candidate_title']}"
                        ),
                    },
                )
            self._set_worker_status(
                connection,
                reviewer,
                "WORKING",
                f"Candidate Challenge {int(row['id'])}",
                (
                    f"Candidate {row['candidate_key']}; "
                    f"{'resumed' if resumed else 'claimed'}"
                ),
                timestamp,
            )
            current = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (int(row["id"]),),
            ).fetchone()
            record = self._record(current)
            dossier = json.loads(current["dossier_json"])
            record["operator_exception_authority"] = (
                self._operator_exception_authority(connection, current, dossier)
            )
            return record

    def authorize_operator_exception(
        self,
        candidate_id: int,
        instruction: str,
        *,
        expires_in_hours: int = 24,
    ) -> dict[str, Any]:
        if not isinstance(instruction, str) or not instruction.strip():
            raise CandidateChallengeError("operator instruction is required")
        if not isinstance(expires_in_hours, int) or not 1 <= expires_in_hours <= 168:
            raise CandidateChallengeError("operator authorization expiry is invalid")
        authorized = datetime.now(UTC)
        expires = authorized + timedelta(hours=expires_in_hours)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            candidate = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?", (candidate_id,)
            ).fetchone()
            if candidate is None:
                raise CandidateChallengeError(
                    f"unknown candidate challenge: {candidate_id}"
                )
            dossier = json.loads(candidate["dossier_json"])
            outcome = dossier["economic_outcome"]
            if (
                outcome["portfolio_class"] != "TIER_B_EXCEPTION"
                or outcome["operator_exception"] is not True
                or outcome["operator_instruction"].strip() != instruction.strip()
            ):
                raise CandidateChallengeError(
                    "operator instruction does not match the frozen Tier-B dossier"
                )
            prior = connection.execute(
                "SELECT revision FROM operator_exception_authorizations "
                "WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
            revision = int(prior["revision"]) + 1 if prior is not None else 1
            record = {
                "candidate_id": candidate_id,
                "candidate_key": candidate["candidate_key"],
                "dossier_sha256": candidate["dossier_sha256"],
                "instruction_sha256": hashlib.sha256(
                    instruction.strip().encode("utf-8")
                ).hexdigest(),
                "disposition": "OPERATOR_EXCEPTION",
                "revision": revision,
                "authorized_at": authorized.isoformat(timespec="seconds"),
                "expires_at": expires.isoformat(timespec="seconds"),
                "state": "ACTIVE",
            }
            connection.execute(
                """
                INSERT INTO operator_exception_authorizations(
                    candidate_id, candidate_key, dossier_sha256,
                    instruction_sha256, disposition, revision, authorized_at,
                    expires_at, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(candidate_id) DO UPDATE SET
                    candidate_key=excluded.candidate_key,
                    dossier_sha256=excluded.dossier_sha256,
                    instruction_sha256=excluded.instruction_sha256,
                    disposition=excluded.disposition,
                    revision=excluded.revision,
                    authorized_at=excluded.authorized_at,
                    expires_at=excluded.expires_at,
                    state=excluded.state
                """,
                tuple(record.values()),
            )
            self._event(
                connection,
                "operator",
                "CANDIDATE_OPERATOR_EXCEPTION_AUTHORIZED",
                {
                    "candidate_id": candidate_id,
                    "candidate_key": candidate["candidate_key"],
                    "dossier_sha256": candidate["dossier_sha256"],
                    "instruction_sha256": record["instruction_sha256"],
                    "revision": revision,
                },
            )
            return record

    def _has_standing_include_b_tier_authority(
        self,
        dossier: dict[str, Any],
    ) -> bool:
        policy_db = (
            self.workspace / "notes" / "hunt_policy" / "hunt_policy.sqlite3"
        )
        if not policy_db.is_file():
            return False
        try:
            with sqlite3.connect(policy_db) as policy_connection:
                policy_connection.row_factory = sqlite3.Row
                active = policy_connection.execute(
                    """
                    SELECT preset, state, target
                    FROM policy_revisions
                    WHERE state = 'ACKNOWLEDGED'
                    ORDER BY id DESC LIMIT 1
                    """
                ).fetchone()
        except sqlite3.Error:
            return False
        if active is None or active["preset"] != "INCLUDE_B_TIER":
            return False
        target = active["target"]
        return target is None or target == dossier["target_slug"]

    def _require_operator_exception_authorization(
        self,
        connection: sqlite3.Connection,
        candidate: sqlite3.Row,
        dossier: dict[str, Any],
    ) -> None:
        if self._operator_exception_authority(connection, candidate, dossier) is None:
            raise CandidateChallengeError(
                "OPERATOR_EXCEPTION lacks a matching operator authorization record"
            )

    def _operator_exception_authority(
        self,
        connection: sqlite3.Connection,
        candidate: sqlite3.Row,
        dossier: dict[str, Any],
    ) -> dict[str, Any] | None:
        outcome = dossier["economic_outcome"]
        if outcome.get("operator_exception") is not True:
            return None
        authorization = connection.execute(
            "SELECT * FROM operator_exception_authorizations WHERE candidate_id = ?",
            (int(candidate["id"]),),
        ).fetchone()
        instruction = outcome["operator_instruction"].strip()
        expected_instruction_hash = hashlib.sha256(
            instruction.encode("utf-8")
        ).hexdigest()
        authorization_matches = authorization is not None and not (
            authorization["candidate_key"] != candidate["candidate_key"]
            or authorization["dossier_sha256"] != candidate["dossier_sha256"]
            or authorization["instruction_sha256"] != expected_instruction_hash
            or authorization["disposition"] != "OPERATOR_EXCEPTION"
            or authorization["state"] != "ACTIVE"
        )
        if authorization_matches:
            try:
                expires_at = datetime.fromisoformat(str(authorization["expires_at"]))
            except ValueError:
                expires_at = None
            if (
                expires_at is not None
                and expires_at.tzinfo is not None
                and expires_at.astimezone(UTC) > datetime.now(UTC)
            ):
                return {
                    "source": "CANDIDATE_BOUND",
                    "state": "ACTIVE",
                    "revision": int(authorization["revision"]),
                    "authorized_at": authorization["authorized_at"],
                    "expires_at": authorization["expires_at"],
                }
        if self._has_standing_include_b_tier_authority(dossier):
            return {
                "source": "HUNT_PROFILE",
                "state": "ACTIVE",
                "revision": None,
                "authorized_at": None,
                "expires_at": None,
            }
        return None

    def decide(
        self,
        candidate_id: int,
        reviewer: str,
        decision_path: str | Path,
    ) -> dict[str, Any]:
        path = _private_json_path(
            self.workspace, decision_path, "candidate challenge decision"
        )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CandidateChallengeError(
                f"cannot read candidate challenge decision: {error}"
            ) from error
        if not isinstance(payload, dict) or payload.get("schema") != DECISION_SCHEMA:
            raise CandidateChallengeError("candidate challenge decision schema is invalid")
        if payload.get("candidate_id") != candidate_id:
            raise CandidateChallengeError("candidate challenge decision ID does not match")
        disposition = payload.get("disposition")
        if disposition not in DISPOSITIONS:
            raise CandidateChallengeError("candidate challenge disposition is invalid")
        if not isinstance(payload.get("summary"), str) or not payload["summary"].strip():
            raise CandidateChallengeError("candidate challenge summary is required")
        issue_ids = payload.get("issue_ids")
        evidence_refs = payload.get("evidence_refs")
        if not isinstance(issue_ids, list) or any(
            not isinstance(value, str) or not value.strip() for value in issue_ids
        ):
            raise CandidateChallengeError("candidate challenge issue_ids are invalid")
        if not isinstance(evidence_refs, list) or any(
            not isinstance(value, str) or not value.strip() for value in evidence_refs
        ):
            raise CandidateChallengeError("candidate challenge evidence_refs are invalid")
        reviewer = reviewer.casefold()
        timestamp = utc_now()
        with self._connect() as identity_connection:
            identity_row = identity_connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            if identity_row is None:
                raise CandidateChallengeError(
                    f"unknown candidate challenge: {candidate_id}"
                )
            final_rework_context = self._final_rework_refresh_context(
                identity_connection, identity_row
            )
            _validate_current_admission_identity(
                self.workspace,
                self.db_path,
                json.loads(identity_row["dossier_json"]),
                exclude_package_number=(
                    int(identity_row["package_number"])
                    if identity_row["package_number"] is not None
                    else None
                ),
                allow_recorded_target_authority=final_rework_context is not None,
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise CandidateChallengeError(f"unknown candidate challenge: {candidate_id}")
            if row["state"] != "CLAIMED" or row["reviewer"] != reviewer:
                raise CandidateChallengeError(
                    "candidate challenge is not claimed by this reviewer"
                )
            current_final_rework_context = self._final_rework_refresh_context(
                connection, row
            )
            if current_final_rework_context != final_rework_context:
                raise CandidateChallengeError(
                    "Final Rework candidate authority changed during decision"
                )
            if payload.get("dossier_sha256") != row["dossier_sha256"]:
                raise CandidateChallengeError(
                    "candidate challenge decision dossier hash does not match"
                )
            dossier = json.loads(row["dossier_json"])
            if disposition in ADMITTED_DISPOSITIONS:
                duplicate_references = sorted(
                    str(entry["reference"]).strip()
                    for entry in dossier["adverse_prior_art"]
                    if entry.get("disposition") == "DUPLICATE"
                )
                if duplicate_references:
                    raise CandidateChallengeError(
                        "candidate with duplicate prior art cannot be admitted: "
                        + ", ".join(duplicate_references)
                    )
                exact_remediations = sorted(
                    str(entry["reference"]).strip()
                    for entry in dossier["adverse_prior_art"]
                    if entry.get("root_relation")
                    in {"EXACT_FUNCTION", "SAME_ROOT_FAMILY"}
                    and entry.get("remediation_status") == "EXACT_REMEDIATION"
                )
                if exact_remediations:
                    raise CandidateChallengeError(
                        "candidate with exact public remediation cannot be admitted: "
                        + ", ".join(exact_remediations)
                    )
                _require_admission_proof(dossier, disposition)
            outcome = dossier["economic_outcome"]
            operator_authority = self._operator_exception_authority(
                connection, row, dossier
            )
            proof_records = _proof_records(dossier)
            eligibility_status, economic_status = _admission_statuses(dossier)
            if (
                disposition == "BANK"
                and outcome["portfolio_class"] == "A_TIER"
                and all(
                    proof_records[gate]["status"] == "PASS"
                    for gate in HARD_PROOF_GATES
                )
                and eligibility_status == "PASS"
                and economic_status == "PASS"
            ):
                raise CandidateChallengeError(
                    "fully passing A_TIER candidate requires ADMIT_PROOF rather than BANK"
                )
            if (
                disposition == "BANK"
                and operator_authority is not None
                and outcome["portfolio_class"] == "TIER_B_EXCEPTION"
                and outcome["operator_exception"] is True
                and all(
                    proof_records[gate]["status"] == "PASS"
                    for gate in HARD_PROOF_GATES
                )
                and eligibility_status == "PASS"
                and economic_status in {"PASS", "PARTIAL"}
            ):
                raise CandidateChallengeError(
                    "current operator exception authority requires "
                    "OPERATOR_EXCEPTION rather than BANK"
                )
            if disposition == "ADMIT_PROOF" and outcome["portfolio_class"] not in {
                "A_TIER",
                "CHAIN_COMPONENT",
            }:
                raise CandidateChallengeError(
                    "ADMIT_PROOF requires A_TIER or CHAIN_COMPONENT"
                )
            if disposition == "OPERATOR_EXCEPTION" and (
                outcome["portfolio_class"] != "TIER_B_EXCEPTION"
                or outcome["operator_exception"] is not True
                or not outcome["operator_instruction"].strip()
            ):
                raise CandidateChallengeError(
                    "OPERATOR_EXCEPTION requires exact Tier-B operator authority"
                )
            if disposition == "OPERATOR_EXCEPTION":
                self._require_operator_exception_authorization(
                    connection, row, dossier
                )
            decision_sha256 = _sha256(path)
            connection.execute(
                """
                UPDATE candidate_challenges
                SET state = 'DECIDED', disposition = ?, decision_path = ?,
                    decision_sha256 = ?, decision_json = ?, decided_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    disposition,
                    str(path),
                    decision_sha256,
                    json.dumps(payload, ensure_ascii=True, sort_keys=True),
                    timestamp,
                    timestamp,
                    candidate_id,
                ),
            )
            self._event(
                connection,
                reviewer,
                "CANDIDATE_CHALLENGE_DECIDED",
                {
                    "candidate_id": candidate_id,
                    "candidate_key": row["candidate_key"],
                    "decision_sha256": decision_sha256,
                    "disposition": disposition,
                    "product": row["product"],
                    "summary": payload["summary"].strip(),
                },
            )
            self._set_worker_status(
                connection,
                reviewer,
                "IDLE",
                f"Candidate Challenge {candidate_id} complete",
                f"Disposition {disposition}",
                timestamp,
            )
            updated = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            return self._record(updated)

    def withdraw_candidate(
        self,
        candidate_id: int,
        reviewer: str,
        reason: str,
    ) -> dict[str, Any]:
        reviewer = reviewer.casefold().strip()
        if reviewer != "midlane":
            raise CandidateChallengeError("withdraw-candidate is Midlane-only")
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise CandidateChallengeError("withdraw-candidate reason is required")
        if len(normalized_reason) > 2000:
            raise CandidateChallengeError("withdraw-candidate reason is too long")
        timestamp = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise CandidateChallengeError(
                    f"unknown candidate challenge: {candidate_id}"
                )
            if row["state"] != "CLAIMED" or row["reviewer"] != reviewer:
                raise CandidateChallengeError(
                    "withdraw-candidate requires the current Midlane-owned CLAIMED row"
                )
            connection.execute(
                """
                UPDATE candidate_challenges
                SET state = 'WITHDRAWN', updated_at = ?
                WHERE id = ? AND state = 'CLAIMED' AND reviewer = ?
                """,
                (timestamp, candidate_id, reviewer),
            )
            self._event(
                connection,
                reviewer,
                "CANDIDATE_CHALLENGE_WITHDRAWN",
                {
                    "candidate_id": candidate_id,
                    "candidate_key": row["candidate_key"],
                    "dossier_sha256": row["dossier_sha256"],
                    "product": row["product"],
                    "reason": normalized_reason,
                    "summary": "Claim withdrawn; a refreshed dossier is required",
                },
            )
            self._set_worker_status(
                connection,
                reviewer,
                "IDLE",
                f"Candidate Challenge {candidate_id} withdrawn",
                "Awaiting a refreshed dossier",
                timestamp,
            )
            updated = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            return self._record(updated)

    def export_result(
        self,
        candidate_id: int,
        output_path: str | Path,
    ) -> dict[str, Any]:
        output = _private_output_path(self.workspace, output_path)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise CandidateChallengeError(f"unknown candidate challenge: {candidate_id}")
            if row["state"] != "DECIDED" or row["disposition"] not in ADMITTED_DISPOSITIONS:
                raise CandidateChallengeError(
                    "candidate decision does not authorize package construction"
                )
            dossier = json.loads(row["dossier_json"])
            final_rework_context = self._final_rework_refresh_context(connection, row)
            _validate_current_admission_identity(
                self.workspace,
                self.db_path,
                dossier,
                exclude_package_number=(
                    int(row["package_number"])
                    if row["package_number"] is not None
                    else None
                ),
                allow_recorded_target_authority=final_rework_context is not None,
            )
            result = {
                "schema": RESULT_SCHEMA,
                "candidate_id": candidate_id,
                "candidate_key": row["candidate_key"],
                "candidate_title": row["candidate_title"],
                "product": row["product"],
                "version": row["version"],
                "target_slug": row["target_slug"],
                "goal_path": row["goal_path"],
                "goal_hash": row["goal_hash"],
                "current_version_receipt_path": dossier[
                    "current_version_receipt_path"
                ],
                "current_version_receipt_sha256": dossier[
                    "current_version_receipt_sha256"
                ],
                "inventory_digest": row["inventory_digest"],
                "reviewed_item_ids": dossier["reviewed_item_ids"],
                "root_family_id": row["root_family_id"],
                "dossier_path": row["dossier_path"],
                "dossier_sha256": row["dossier_sha256"],
                "decision_path": row["decision_path"],
                "decision_sha256": row["decision_sha256"],
                "disposition": row["disposition"],
                "reviewer": row["reviewer"],
                "proof_status": {
                    gate: record["status"]
                    for gate, record in _proof_records(dossier).items()
                },
                "eligibility_status": _admission_statuses(dossier)[0],
                "economic_status": _admission_statuses(dossier)[1],
                "portfolio_class": dossier["economic_outcome"]["portfolio_class"],
                "likely_payout_usd": dossier["economic_outcome"][
                    "likely_payout_usd"
                ],
                "theoretical_ceiling_usd": dossier["economic_outcome"][
                    "theoretical_ceiling_usd"
                ],
                "same_product_rank": dossier["economic_outcome"][
                    "same_product_rank"
                ],
                "operator_exception": dossier["economic_outcome"][
                    "operator_exception"
                ],
                "decided_at": row["decided_at"],
            }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return result

    def bind_package(self, candidate_id: int, package_number: int) -> None:
        with self._connect() as identity_connection:
            identity_row = identity_connection.execute(
                "SELECT dossier_json FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
        if identity_row is None:
            raise CandidateChallengeError(f"unknown candidate challenge: {candidate_id}")
        _validate_current_admission_identity(
            self.workspace,
            self.db_path,
            json.loads(identity_row["dossier_json"]),
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT disposition, package_number FROM candidate_challenges WHERE id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise CandidateChallengeError(f"unknown candidate challenge: {candidate_id}")
            if row["disposition"] not in ADMITTED_DISPOSITIONS:
                raise CandidateChallengeError(
                    "candidate decision does not authorize package construction"
                )
            if row["package_number"] not in (None, package_number):
                raise CandidateChallengeError(
                    "candidate challenge is already bound to another package"
                )
            connection.execute(
                """
                UPDATE candidate_challenges
                SET package_number = ?, updated_at = ?
                WHERE id = ?
                """,
                (package_number, utc_now(), candidate_id),
            )

    def status(self, candidate_id: int | None = None) -> dict[str, Any]:
        with self._connect() as connection:
            if candidate_id is None:
                rows = connection.execute(
                    "SELECT * FROM candidate_challenges ORDER BY id"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM candidate_challenges WHERE id = ?",
                    (candidate_id,),
                ).fetchall()
            return {"candidates": [self._record(row) for row in rows]}

    def metrics(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, product, disposition, package_number
                FROM candidate_challenges
                WHERE state = 'DECIDED' ORDER BY id
                """
            ).fetchall()
        dispositions = Counter(str(row["disposition"]) for row in rows)
        products = Counter(str(row["product"]) for row in rows)
        admitted = sum(
            dispositions.get(disposition, 0)
            for disposition in ADMITTED_DISPOSITIONS
        )
        cohort = rows[:20]
        cohort_dispositions = Counter(str(row["disposition"]) for row in cohort)
        return {
            "total_decided": len(rows),
            "admitted": admitted,
            "admission_rate": (admitted / len(rows)) if rows else 0.0,
            "package_bound": sum(row["package_number"] is not None for row in rows),
            "dispositions": dict(sorted(dispositions.items())),
            "products": dict(sorted(products.items())),
            "first_twenty": {
                "size": len(cohort),
                "complete": len(cohort) >= 20,
                "dispositions": dict(sorted(cohort_dispositions.items())),
            },
        }


def validate_result(
    *,
    workspace: str | Path,
    db_path: str | Path,
    result_path: str | Path,
    product: str,
    version: str,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    path = _private_json_path(
        workspace_path, result_path, "candidate challenge result"
    )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateChallengeError(
            f"cannot read candidate challenge result: {error}"
        ) from error
    if not isinstance(payload, dict) or payload.get("schema") != RESULT_SCHEMA:
        raise CandidateChallengeError("candidate challenge result schema is invalid")
    if payload.get("product") != product or payload.get("version") != version:
        raise CandidateChallengeError(
            "candidate challenge product/version does not match package build"
        )
    if payload.get("disposition") not in ADMITTED_DISPOSITIONS:
        raise CandidateChallengeError(
            "candidate challenge result does not authorize package construction"
        )
    proof = _result_proof_statuses(payload)
    if any(proof.get(gate) != "PASS" for gate in HARD_PROOF_GATES):
        raise CandidateChallengeError(
            "candidate challenge result lacks complete technical proof"
        )
    eligibility_status = proof["hard_eligibility"]
    economic_status = proof["economic_review"]
    if eligibility_status != "PASS":
        raise CandidateChallengeError(
            "candidate challenge result lacks hard eligibility PASS"
        )
    if payload["disposition"] == "ADMIT_PROOF" and economic_status != "PASS":
        raise CandidateChallengeError(
            "candidate challenge result lacks economic review PASS"
        )
    if payload["disposition"] == "OPERATOR_EXCEPTION" and economic_status not in {
        "PASS",
        "PARTIAL",
    }:
        raise CandidateChallengeError(
            "candidate challenge result has no operator-overridable economic status"
        )
    candidate_id = payload.get("candidate_id")
    if not isinstance(candidate_id, int) or candidate_id <= 0:
        raise CandidateChallengeError("candidate challenge result ID is invalid")
    store = CandidateChallengeStore(db_path, workspace_path)
    with store._connect() as connection:
        stored = connection.execute(
            "SELECT * FROM candidate_challenges WHERE id = ?",
            (candidate_id,),
        ).fetchone()
    if stored is None:
        raise CandidateChallengeError("candidate challenge result is not in SQLite")
    row = store._record(stored)
    for field in (
        "candidate_key",
        "product",
        "version",
        "target_slug",
        "goal_path",
        "goal_hash",
        "inventory_digest",
        "root_family_id",
        "dossier_sha256",
        "decision_sha256",
        "disposition",
        "reviewer",
    ):
        if payload.get(field) != row.get(field):
            raise CandidateChallengeError(
                f"candidate challenge result is stale or mismatched: {field}"
            )
    dossier = json.loads(stored["dossier_json"])
    if payload.get("reviewed_item_ids") != dossier["reviewed_item_ids"]:
        raise CandidateChallengeError(
            "candidate challenge reviewed inventory does not match the dossier"
        )
    for field in (
        "current_version_receipt_path",
        "current_version_receipt_sha256",
    ):
        if not dossier.get(field):
            raise CandidateChallengeError(
                "candidate challenge requires a fresh current-version receipt"
            )
        if payload.get(field) != dossier[field]:
            raise CandidateChallengeError(
                f"candidate challenge result is stale or mismatched: {field}"
            )
    with store._connect() as authority_connection:
        authoritative_stored = authority_connection.execute(
            "SELECT * FROM candidate_challenges WHERE id = ?", (candidate_id,)
        ).fetchone()
        assert authoritative_stored is not None
        final_rework_context = store._final_rework_refresh_context(
            authority_connection, authoritative_stored
        )
        _validate_current_admission_identity(
            workspace_path,
            Path(db_path),
            dossier,
            exclude_package_number=(
                int(stored["package_number"])
                if stored["package_number"] is not None
                else None
            ),
            allow_recorded_target_authority=final_rework_context is not None,
        )
    authoritative_proof = {
        gate: record["status"]
        for gate, record in _proof_records(dossier).items()
    }
    if proof != authoritative_proof:
        raise CandidateChallengeError(
            "candidate challenge proof does not match the authoritative dossier"
        )
    authoritative_eligibility, authoritative_economics = _admission_statuses(dossier)
    if eligibility_status != authoritative_eligibility or (
        economic_status != authoritative_economics
    ):
        raise CandidateChallengeError(
            "candidate challenge admission checks do not match the "
            "authoritative dossier"
        )
    _require_admission_proof(dossier, row["disposition"])
    outcome = dossier["economic_outcome"]
    for field in (
        "portfolio_class",
        "likely_payout_usd",
        "theoretical_ceiling_usd",
        "same_product_rank",
        "operator_exception",
    ):
        if payload.get(field) != outcome[field]:
            raise CandidateChallengeError(
                "candidate challenge economics do not match the authoritative dossier"
            )
    if row["disposition"] == "OPERATOR_EXCEPTION":
        with store._connect() as authorization_connection:
            authoritative_row = authorization_connection.execute(
                "SELECT * FROM candidate_challenges WHERE id = ?", (candidate_id,)
            ).fetchone()
            store._require_operator_exception_authorization(
                authorization_connection, authoritative_row, dossier
            )
    return {
        **payload,
        "result_path": str(path),
        "result_sha256": _sha256(path),
    }


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Manage independent pre-package candidate challenges"
    )
    parser.add_argument("--workspace", type=Path, default=workspace)
    parser.add_argument(
        "--db",
        type=Path,
        default=workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    submit = commands.add_parser("submit")
    submit.add_argument("--input", type=Path, required=True)
    refresh_submit = commands.add_parser("submit-final-rework-refresh")
    refresh_submit.add_argument("--item", type=int, required=True)
    refresh_submit.add_argument("--input", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    claim = commands.add_parser("claim-next")
    claim.add_argument("--reviewer", default="midlane")
    decide = commands.add_parser("decide")
    decide.add_argument("--id", type=int, required=True)
    decide.add_argument("--reviewer", default="midlane")
    decide.add_argument("--input", type=Path, required=True)
    withdraw = commands.add_parser("withdraw-candidate")
    withdraw.add_argument("--id", type=int, required=True)
    withdraw.add_argument("--reviewer", default="midlane")
    withdraw.add_argument("--reason", required=True)
    export = commands.add_parser("export")
    export.add_argument("--id", type=int, required=True)
    export.add_argument("--output", type=Path, required=True)
    status = commands.add_parser("status")
    status.add_argument("--id", type=int)
    commands.add_parser("metrics")
    authorize = commands.add_parser("authorize-exception")
    authorize.add_argument("--id", type=int, required=True)
    authorize.add_argument("--instruction", required=True)
    authorize.add_argument("--expires-in-hours", type=int, default=24)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "validate":
            path, payload = validate_dossier(args.workspace, args.input)
            output = {
                "schema": "jenny.candidate-dossier-validation.v1",
                "status": "PASS",
                "candidate_key": payload["candidate_key"],
                "dossier_path": str(path),
                "dossier_sha256": _sha256(path),
            }
        else:
            store = CandidateChallengeStore(args.db, args.workspace)
        if args.command == "validate":
            pass
        elif args.command == "submit":
            output = {"candidate": store.submit(args.input)}
        elif args.command == "submit-final-rework-refresh":
            output = {
                "candidate": store.submit_final_rework_refresh(args.item, args.input)
            }
        elif args.command == "claim-next":
            output = {"candidate": store.claim_next(args.reviewer)}
        elif args.command == "decide":
            output = {
                "candidate": store.decide(args.id, args.reviewer, args.input)
            }
        elif args.command == "withdraw-candidate":
            output = {
                "candidate": store.withdraw_candidate(
                    args.id, args.reviewer, args.reason
                )
            }
        elif args.command == "export":
            output = {"result": store.export_result(args.id, args.output)}
        elif args.command == "status":
            output = store.status(args.id)
        elif args.command == "metrics":
            output = store.metrics()
        elif args.command == "authorize-exception":
            output = {
                "authorization": store.authorize_operator_exception(
                    args.id,
                    args.instruction,
                    expires_in_hours=args.expires_in_hours,
                )
            }
        else:
            raise CandidateChallengeError(f"unsupported command: {args.command}")
    except (OSError, ValueError, sqlite3.Error, CandidateChallengeError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
