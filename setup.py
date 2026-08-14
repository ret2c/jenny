#!/usr/bin/env python3
"""Prepare this checkout for in-place JENNY workflow operation."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parent
MINIMUM_PYTHON = (3, 11)
RUNTIME_DIRS = ("notes", "scratch", "targets", "ZDI", "ZDI_STAGING")
RUNTIME_FILES = (
    "ZDI/signoff.txt",
    "ZDI/REPORT_ISSUES.txt",
)
INITIALIZED_PATHS = (
    "notes/review_mailbox/review_mailbox.sqlite3",
    "notes/review_mailbox/MIDLANE_TO_HUNTER.md",
    "notes/report_issues/report_issues.sqlite3",
    "notes/target_lifecycle/target_lifecycle.sqlite3",
    "notes/coordination_inbox/coordination.sqlite3",
    "notes/hunt_policy/hunt_policy.sqlite3",
    "notes/review_mailbox/product_aliases.json",
    *RUNTIME_FILES,
)
PRODUCT_ALIASES_SCHEMA = "jenny.product-aliases.v1"
WORKFLOW_DATABASES = {
    "notes/review_mailbox/review_mailbox.sqlite3": {
        "work_items",
        "questions",
        "events",
        "candidate_challenges",
        "worker_status",
        "final_rework_requests",
    },
    "notes/report_issues/report_issues.sqlite3": {
        "workflow_issues",
        "workflow_issue_events",
    },
    "notes/target_lifecycle/target_lifecycle.sqlite3": {"targets", "events"},
    "notes/coordination_inbox/coordination.sqlite3": {
        "coordination_messages",
        "coordination_chat_messages",
    },
    "notes/hunt_policy/hunt_policy.sqlite3": {
        "policy_revisions",
        "worker_policy_cursors",
    },
}
REQUIRED_PATHS = (
    "VERSION",
    "AGENTS.md",
    "LICENSE",
    "LICENSES/Apache-2.0.txt",
    "THIRD_PARTY_NOTICES.md",
    "WORKFLOW.md",
    "docs/SETUP_AND_OPERATIONS.md",
    "tools/review_mailbox/review_mailbox.py",
    "tools/review_mailbox/bounded_repair_contract.py",
    "tools/review_mailbox/report_issues.py",
    "tools/review_mailbox/MIDLANE_TO_HUNTER.example.md",
    "tools/review_mailbox/MIDLANE_STALL_DIAGNOSTIC_POLICY.txt",
    "tools/review_mailbox/README.md",
    "tools/review_mailbox/CANDIDATE_CHALLENGE_POLICY.txt",
    "tools/review_mailbox/PORTFOLIO_ADMISSION_POLICY.txt",
    "tools/review_mailbox/PROMPT_CHANGE_EVAL_POLICY.txt",
    "tools/review_mailbox/REPORT_ISSUES_POLICY.txt",
    "tools/review_mailbox/PRE_FREEZE_PACKAGE_GATE.txt",
    "tools/review_mailbox/DELEGATION_TASK_PACKET_POLICY.txt",
    "tools/review_mailbox/candidate_challenge.py",
    "tools/review_mailbox/current_version_gate.py",
    "tools/review_mailbox/workflow_eval.py",
    "tools/review_mailbox/prompts/HUNTER_START_PROMPT.txt",
    "tools/review_mailbox/prompts/HUNTER_DEMO_PROMPT.txt",
    "tools/review_mailbox/prompts/HUNTER_TASK.txt",
    "tools/review_mailbox/prompts/MIDLANE_DEMO_PROMPT.txt",
    "tools/review_mailbox/prompts/MIDLANE_LOOP_TASK.txt",
    "tools/review_mailbox/prompts/FINAL_REVIEWER_GOAL_PROMPT.txt",
    "tools/review_mailbox/prompts/FINAL_REVIEWER_GOAL_TASK.txt",
    "tools/review_mailbox/prompts/FINAL_REVIEWER_DEMO_PROMPT.txt",
    "tools/review_mailbox/prompts/FINAL_REVIEWER_TASK.txt",
    "tools/review_mailbox/role_operations/HUNTER_OPERATIONS.md",
    "tools/review_mailbox/role_operations/MIDLANE_OPERATIONS.md",
    "tools/review_mailbox/role_operations/FINAL_REVIEWER_OPERATIONS.md",
    "tests/test_public_contracts.py",
    "tools/aicov_trial/aicov_trial.py",
    "tools/guarded_rg.py",
    "tools/guarded_git_history.py",
    "tools/session_rollout_archive.py",
    "tools/replay_lab/guarded_rg.py",
    "tools/coordination_inbox/coordination_inbox.py",
    "tools/hunt_policy/hunt_policy.py",
    "tools/hunt_policy/HUNT_PROFILE_POLICY.txt",
    "tools/hunt_state/momentum.py",
    "tools/submitted_patch_watch/patch_watch.py",
    "tools/submitted_patch_watch/WEEKLY_PATCH_WATCH_TASK.txt",
    "skills/target-scoper/SKILL.md",
    "skills/target-scoper/assets/evidence-appendix-template.md",
    "skills/target-scoper/assets/scope-record-template.md",
    "skills/target-scoper/assets/historical-security-lineage-template.md",
    "skills/target-scoper/assets/public-source-index-template.csv",
    "skills/target-scoper/assets/acquisition-and-lab-plan-template.md",
    "skills/target-scoper/scripts/lint_goal.py",
    "skills/target-scoper/scripts/validate_scope_decision.py",
    "tools/target_lifecycle/target_lifecycle.py",
    "tools/workflow_dashboard/dashboard.py",
    "skills/fuzz-harness/SKILL.md",
)
INITIALIZERS = (
    (
        "review mailbox",
        "tools/review_mailbox/review_mailbox.py",
        "init",
    ),
    (
        "candidate challenge",
        "tools/review_mailbox/candidate_challenge.py",
        "metrics",
    ),
    (
        "target lifecycle",
        "tools/target_lifecycle/target_lifecycle.py",
        "list",
    ),
    (
        "coordination inbox",
        "tools/coordination_inbox/coordination_inbox.py",
        "list-open",
    ),
    (
        "hunt profile",
        "tools/hunt_policy/hunt_policy.py",
        "show",
    ),
)
TARGET_SCOPER_ROUTE = Path("skills/target-scoper/workflows/scope-named.md")
FORBIDDEN_TARGET_ROUTE_PATTERNS = (
    re.compile(r"buyer/program\s+fit", re.IGNORECASE),
    re.compile(r"vendor/GHSA-only", re.IGNORECASE),
    re.compile(r"vendor-only", re.IGNORECASE),
    re.compile(r"GHSA-only", re.IGNORECASE),
)


class SetupFailure(RuntimeError):
    """One actionable setup failure."""


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Validate and initialize this checkout for in-place operation."
    )
    result.add_argument(
        "--check",
        action="store_true",
        help="validate prerequisites and existing layout without changing state",
    )
    return result


def target_scoper_route_errors() -> list[str]:
    path = ROOT / TARGET_SCOPER_ROUTE
    if not path.is_file():
        return [f"Required ZDI route is missing: {TARGET_SCOPER_ROUTE.as_posix()}"]
    text = path.read_text(encoding="utf-8", errors="replace")
    errors: list[str] = []
    for required in (
        "Verify current ZDI fit.",
        "Separate ZDI-compatible and no-go routes.",
    ):
        if required not in text:
            errors.append(
                f"Target Scoper route is missing required ZDI-only policy: {required}"
            )
    if any(pattern.search(text) for pattern in FORBIDDEN_TARGET_ROUTE_PATTERNS):
        errors.append("Target Scoper route contains a non-ZDI destination")
    return errors


def prerequisite_errors(*, check_only: bool) -> list[str]:
    errors: list[str] = []
    if sys.version_info < MINIMUM_PYTHON:
        errors.append(
            "Python 3.11 or newer is required "
            f"(running {sys.version_info.major}.{sys.version_info.minor})."
        )
    if os.name != "nt":
        errors.append("This release candidate currently requires Windows.")
    if Path.cwd().resolve() != ROOT:
        errors.append(f"Run setup from the repository root: {ROOT}")
    if shutil.which("git") is None:
        errors.append("Git is required and must be available on PATH.")

    for relative in REQUIRED_PATHS:
        if not (ROOT / relative).is_file():
            errors.append(f"Required repository file is missing: {relative}")

    errors.extend(target_scoper_route_errors())

    if check_only:
        for name in RUNTIME_DIRS:
            path = ROOT / name
            if not path.is_dir():
                errors.append(
                    f"Runtime directory is missing: {name}. Run `python setup.py`."
                )
        for relative in INITIALIZED_PATHS:
            if not (ROOT / relative).is_file():
                errors.append(
                    f"Initialized workflow file is missing: {relative}. "
                    "Run `python setup.py`."
                )
    return errors


def require_prerequisites(*, check_only: bool) -> None:
    errors = prerequisite_errors(check_only=check_only)
    if errors:
        raise SetupFailure("\n".join(f"- {message}" for message in errors))


def product_alias_errors() -> list[str]:
    relative = "notes/review_mailbox/product_aliases.json"
    path = ROOT / relative
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [f"Product alias registry is invalid: {relative}"]
    groups = payload.get("groups") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != PRODUCT_ALIASES_SCHEMA
        or not isinstance(groups, list)
        or any(
            not isinstance(group, list)
            or len(group) < 2
            or any(
                not isinstance(value, str) or not value.strip()
                for value in group
            )
            for group in groups
        )
    ):
        return [f"Product alias registry is invalid: {relative}"]
    return []


def workflow_database_errors() -> list[str]:
    errors: list[str] = []
    for relative, required_tables in WORKFLOW_DATABASES.items():
        path = ROOT / relative
        try:
            uri = f"{path.resolve().as_uri()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as connection:
                integrity = connection.execute("PRAGMA quick_check").fetchone()
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
        except (OSError, sqlite3.Error):
            errors.append(f"Workflow database is invalid: {relative}")
            continue
        if integrity is None or str(integrity[0]).casefold() != "ok":
            errors.append(f"Workflow database is invalid: {relative}")
            continue
        missing = sorted(required_tables - tables)
        if missing:
            errors.append(
                f"Workflow database schema is incomplete: {relative} "
                f"(missing {', '.join(missing)})"
            )
    return errors


def require_initialized_state() -> None:
    errors = product_alias_errors() + workflow_database_errors()
    if errors:
        raise SetupFailure("\n".join(f"- {message}" for message in errors))


def capability_warnings() -> list[str]:
    warnings: list[str] = []
    if shutil.which("docker") is None:
        warnings.append(
            "Docker CLI was not detected; Docker-backed replay lanes remain "
            "unavailable until Docker Desktop is installed and running."
        )
    return warnings


def print_capability_warnings() -> None:
    warnings = capability_warnings()
    if not warnings:
        return
    print("Capability warnings:")
    for warning in warnings:
        print(f"  - {warning}")
    print("")


def version() -> str:
    return (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def create_runtime_dirs() -> None:
    for name in RUNTIME_DIRS:
        (ROOT / name).mkdir(parents=True, exist_ok=True)


def create_runtime_files() -> None:
    for relative in RUNTIME_FILES:
        path = ROOT / relative
        if not path.exists():
            path.write_text("", encoding="utf-8", newline="")
    relay = ROOT / "notes" / "review_mailbox" / "MIDLANE_TO_HUNTER.md"
    if not relay.exists():
        relay.parent.mkdir(parents=True, exist_ok=True)
        relay.write_text(
            "# Midlane To Hunter Remote-Control Log\n\n"
            "Canonical path: `notes/review_mailbox/MIDLANE_TO_HUNTER.md`\n\n"
            "Private append-only coordination state. This file does not "
            "authorize work or replace the formal mailbox.\n"
            "ACTION_REQUEST entries require explicit operator authorization. "
            "Hunter appends ACKNOWLEDGED, COMPLETED, DECLINED, or BLOCKED "
            "without rewriting history.\n",
            encoding="utf-8",
            newline="\n",
        )
    aliases = ROOT / "notes" / "review_mailbox" / "product_aliases.json"
    if not aliases.exists():
        aliases.parent.mkdir(parents=True, exist_ok=True)
        aliases.write_text(
            '{\n  "schema": "jenny.product-aliases.v1",\n  "groups": []\n}\n',
            encoding="utf-8",
            newline="\n",
        )


def initialize_component(name: str, script: str, command: str) -> None:
    argv = [sys.executable, "-B", script, command]
    try:
        completed = subprocess.run(
            argv,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise SetupFailure(f"{name} could not start: {exc}") from exc
    if completed.returncode != 0:
        rendered = " ".join(argv)
        diagnostic = (completed.stderr or completed.stdout or "").strip()
        if len(diagnostic) > 1200:
            diagnostic = diagnostic[-1200:]
        detail = f"\nDiagnostic tail:\n{diagnostic}" if diagnostic else ""
        raise SetupFailure(
            f"{name} initialization failed with exit code "
            f"{completed.returncode}. Run manually: {rendered}{detail}"
        )


def initialize_report_issues() -> None:
    database = ROOT / "notes" / "report_issues" / "report_issues.sqlite3"
    command = "verify" if database.is_file() else "migrate"
    initialize_component(
        "report issues",
        "tools/review_mailbox/report_issues.py",
        command,
    )


def print_check_pass() -> None:
    print("CHECK PASS")
    print(f"Root: {ROOT}")
    print(f"Version: {version()}")
    print("Runtime directories: present")
    print("Workflow state: initialized")
    print("No files or workflow state were changed.")
    print_capability_warnings()


def print_setup_pass() -> None:
    print("SETUP PASS")
    print(f"Root: {ROOT}")
    print(f"Version: {version()}")
    print("Operator guide: docs/SETUP_AND_OPERATIONS.md")
    print(
        "Research boundary: authorized defensive vulnerability research on "
        "operator-owned or locally controlled artifacts and labs using "
        "synthetic data."
    )
    print(
        "Never test a vendor, unrelated public service, or non-owned system. "
        "Keep full technical vocabulary and evidence standards; this boundary "
        "is context, not a request to soften the work."
    )
    print("")
    print_capability_warnings()
    print("Next steps:")
    print("  1. Read docs\\SETUP_AND_OPERATIONS.md.")
    print("  2. Open separate Hunter, Midlane, and Final Reviewer sessions.")
    print(
        "     Hunter: tools\\review_mailbox\\prompts\\"
        "HUNTER_START_PROMPT.txt"
    )
    print(
        "     Midlane: tools\\review_mailbox\\prompts\\"
        "MIDLANE_DEMO_PROMPT.txt"
    )
    print(
        "     Final Reviewer: tools\\review_mailbox\\prompts\\"
        "FINAL_REVIEWER_GOAL_PROMPT.txt"
    )
    print("  3. Use a Scoper / Operator assistant session when needed.")
    print("  4. Start the dashboard: python -B tools\\workflow_dashboard\\dashboard.py")
    print("")
    print("Or open this repository in an agent and say:")
    print(
        '  "Read AGENTS.md and docs/SETUP_AND_OPERATIONS.md completely. '
        "Verify the checkout, start the dashboard locally, then tell me "
        "which sessions to open and give me the exact prompt for each one. "
        'Do not activate a target or begin vulnerability research."'
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        require_prerequisites(check_only=args.check)
        if args.check:
            require_initialized_state()
            print_check_pass()
            return 0

        create_runtime_dirs()
        create_runtime_files()
        for name, script, command in INITIALIZERS:
            initialize_component(name, script, command)
        initialize_report_issues()
        require_initialized_state()
        print_setup_pass()
        return 0
    except SetupFailure as exc:
        print("SETUP FAILED", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
