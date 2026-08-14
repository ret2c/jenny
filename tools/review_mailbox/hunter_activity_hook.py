#!/usr/bin/env python3
"""Record sanitized Hunter activity from one explicitly goal-armed agent session."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any

from review_mailbox import Mailbox


WORKSPACE = Path(__file__).resolve().parents[2]
GOAL_PATTERN = re.compile(
    r"\btargets[\\/](?P<slug>[A-Za-z0-9._-]+)[\\/]GOAL\.md\b",
    re.IGNORECASE,
)
SHELL_TOOL_NAMES = {"bash", "powershell", "shell", "shell_command"}
GIT_HISTORY_COMMANDS = {"blame", "cat-file", "log", "rev-list", "show"}
GIT_OPTIONS_WITH_VALUES = {
    "-C",
    "-c",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
}
HISTORY_DENIAL_REASON = (
    "Direct Git history walks are blocked for Hunter sessions. "
    "Use python -B tools/guarded_git_history.py with an exact "
    "checkout root, repository-relative path, bounded window, "
    "count, and timeout."
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _marker_path(workspace: Path, session_id: str) -> Path:
    digest = _sha256_text(session_id)
    return (
        workspace
        / "notes"
        / "review_mailbox"
        / "hunter_hook_sessions"
        / f"{digest}.json"
    )


def _semantic_authority_path(workspace: Path) -> Path:
    return (
        workspace
        / "notes"
        / "review_mailbox"
        / "hunter_semantic_authority.json"
    )


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _collect_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        strings: list[str] = []
        for entry in value:
            strings.extend(_collect_strings(entry))
        return strings
    if isinstance(value, dict):
        strings = []
        for entry in value.values():
            strings.extend(_collect_strings(entry))
        return strings
    return []


def _tool_input_text(payload: dict[str, Any]) -> str:
    for key in ("tool_input", "toolInput", "arguments", "input"):
        if key in payload:
            return "\n".join(_collect_strings(payload[key]))
    return ""


def _prompt_text(payload: dict[str, Any]) -> str:
    for key in ("prompt", "user_prompt", "userPrompt", "text"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    return ""


def _session_context(
    payload: dict[str, Any], workspace: Path
) -> tuple[str, Path] | None:
    session_id = payload.get("session_id")
    cwd_raw = payload.get("cwd")
    if not isinstance(session_id, str) or not session_id:
        return None
    if not isinstance(cwd_raw, str):
        return None
    try:
        cwd = Path(cwd_raw).resolve()
    except OSError:
        return None
    if cwd != workspace and workspace not in cwd.parents:
        return None
    return session_id, cwd


def _goal_from_prompt(prompt: str, workspace: Path) -> tuple[str, Path] | None:
    normalized = prompt.strip()
    folded = normalized.casefold()
    if not re.match(r"^(?:/goal\s+)?read\b", folded):
        return None
    if "until i tell you to stop" not in folded:
        return None
    matches = list(GOAL_PATTERN.finditer(normalized))
    slugs = {match.group("slug").casefold() for match in matches}
    if len(slugs) != 1:
        return None
    slug = next(iter(slugs))
    goal = (workspace / "targets" / slug / "GOAL.md").resolve()
    targets_root = (workspace / "targets").resolve()
    if targets_root not in goal.parents or not goal.is_file():
        return None
    return slug, goal


def _target_is_active(workspace: Path, slug: str) -> bool:
    db_path = workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
    if not db_path.is_file():
        return False
    try:
        uri = db_path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as connection:
            row = connection.execute(
                "SELECT status FROM targets WHERE slug = ?", (slug,)
            ).fetchone()
        return row is not None and str(row[0]).upper() == "ACTIVE"
    except sqlite3.Error:
        return False


def _classify_tool(payload: dict[str, Any], slug: str) -> tuple[str, str]:
    tool_name = str(payload.get("tool_name", "")).casefold()
    tool_text = _tool_input_text(payload).replace("\\", "/").casefold()
    if tool_name in {"apply_patch", "edit", "write"}:
        return "WORKSPACE EDIT", f"{slug} - workspace edit completed"
    if any(
        marker in tool_text
        for marker in (
            "review_mailbox.py checkin",
            "review_mailbox.py register",
            "package_preflight.py",
            "package_safety.py",
            "zdi_staging",
        )
    ):
        return "WORKFLOW CHECKPOINT", f"{slug} - workflow or package tool completed"
    if any(
        marker in tool_text
        for marker in (
            "guarded_run.py",
            "run_sandbox_guarded.ps1",
            "docker ",
            "docker.exe",
            "windows sandbox",
            "hyper-v",
            "vmrun",
        )
    ):
        return "LAB OR REPLAY", f"{slug} - owned lab or replay tool completed"
    if tool_name in {
        "read",
        "open",
        "view_image",
        "mcp__filesystem__read_file",
    } or any(
        marker in tool_text
        for marker in ("rg ", "get-content", "select-string", "findstr ")
    ):
        return "SOURCE REVIEW", f"{slug} - local source or evidence tool completed"
    return "LOCAL TOOL", f"{slug} - local tool completed"


def _handle_prompt(
    payload: dict[str, Any], *, workspace: Path, session_id: str
) -> dict[str, Any]:
    selected = _goal_from_prompt(_prompt_text(payload), workspace)
    if selected is None:
        return {"action": "IGNORED", "reason": "NOT_HUNTER_GOAL_PROMPT"}
    slug, goal = selected
    authority = {
        "goal_hash": _sha256_file(goal),
        "goal_path": goal.relative_to(workspace).as_posix(),
        "session_hash": _sha256_text(session_id),
        "target": slug,
    }
    _atomic_write(
        _marker_path(workspace, session_id),
        authority,
    )
    _atomic_write(_semantic_authority_path(workspace), authority)
    return {
        "action": "ARMED",
        "active": _target_is_active(workspace, slug),
        "target": slug,
    }


def _valid_session_marker(
    workspace: Path, session_id: str
) -> tuple[Path, dict[str, Any]] | None:
    marker_path = _marker_path(workspace, session_id)
    if not marker_path.is_file():
        return None
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        goal = (workspace / str(marker["goal_path"])).resolve()
        targets_root = (workspace / "targets").resolve()
        if (
            marker.get("session_hash") != _sha256_text(session_id)
            or targets_root not in goal.parents
            or not goal.is_file()
            or marker.get("goal_hash") != _sha256_file(goal)
        ):
            raise ValueError("stale marker")
        return marker_path, marker
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        marker_path.unlink(missing_ok=True)
        return None


def _normalized_token(token: str) -> str:
    return token.strip().strip("\"'").replace("\\", "/")


def _git_subcommand(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    while tokens and _normalized_token(tokens[0]).casefold() in {
        "&",
        "call",
        "command",
    }:
        tokens = tokens[1:]
    if not tokens:
        return None
    executable = _normalized_token(tokens[0]).rsplit("/", 1)[-1].casefold()
    if executable not in {"git", "git.exe"}:
        return None

    index = 1
    while index < len(tokens):
        token = _normalized_token(tokens[index])
        folded = token.casefold()
        if folded == "--":
            index += 1
            break
        if not token.startswith("-"):
            return folded
        option_name = token.split("=", 1)[0]
        if option_name in GIT_OPTIONS_WITH_VALUES and "=" not in token:
            index += 2
        else:
            index += 1
    if index < len(tokens):
        return _normalized_token(tokens[index]).casefold()
    return None


def _is_direct_git_history(command: str) -> bool:
    for segment in re.split(r"(?:\r?\n|&&|\|\||[;|])", command):
        try:
            tokens = shlex.split(segment, posix=False)
        except ValueError:
            # An unparseable shell fragment is not treated as proof of a direct
            # Git invocation; the shell itself will reject most such fragments.
            continue
        if _git_subcommand(tokens) in GIT_HISTORY_COMMANDS:
            return True
    return False


def _handle_pre_tool(
    payload: dict[str, Any], *, workspace: Path, session_id: str
) -> dict[str, Any]:
    marker_path = _marker_path(workspace, session_id)
    if not marker_path.is_file():
        return {"action": "IGNORED", "reason": "SESSION_NOT_ARMED"}
    tool_name = str(payload.get("tool_name", "")).casefold()
    is_direct_history = (
        tool_name in SHELL_TOOL_NAMES
        and _is_direct_git_history(_tool_input_text(payload))
    )
    if _valid_session_marker(workspace, session_id) is None:
        if not is_direct_history:
            return {"action": "DISARMED", "reason": "INVALID_MARKER"}
    elif not is_direct_history:
        return {"action": "ALLOWED", "reason": "NOT_DIRECT_GIT_HISTORY"}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": HISTORY_DENIAL_REASON,
        }
    }


def _handle_post_tool(
    payload: dict[str, Any], *, workspace: Path, session_id: str
) -> dict[str, Any]:
    marker_path = _marker_path(workspace, session_id)
    if not marker_path.is_file():
        return {"action": "IGNORED", "reason": "SESSION_NOT_ARMED"}
    validated = _valid_session_marker(workspace, session_id)
    if validated is None:
        return {"action": "DISARMED", "reason": "INVALID_MARKER"}
    _, marker = validated
    slug = str(marker["target"])
    if not _target_is_active(workspace, slug):
        return {"action": "IGNORED", "reason": "TARGET_NOT_ACTIVE"}

    category, detail = _classify_tool(payload, slug)
    mailbox = Mailbox(
        workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
        workspace,
    )
    mailbox.record_worker_activity(
        "hunter",
        category=category,
        detail=detail,
        source="codex-post-tool",
        session_hash=str(marker["session_hash"]),
        target=slug,
    )
    return {"action": "RECORDED", "category": category}


def handle_hook(
    payload: dict[str, Any], *, workspace: Path = WORKSPACE
) -> dict[str, Any]:
    workspace = Path(workspace).resolve()
    context = _session_context(payload, workspace)
    if context is None:
        return {"action": "IGNORED", "reason": "INVALID_SESSION_CONTEXT"}
    session_id, _ = context
    event = payload.get("hook_event_name")
    if event == "UserPromptSubmit":
        return _handle_prompt(payload, workspace=workspace, session_id=session_id)
    if event == "PreToolUse":
        return _handle_pre_tool(payload, workspace=workspace, session_id=session_id)
    if event == "PostToolUse":
        return _handle_post_tool(payload, workspace=workspace, session_id=session_id)
    return {"action": "IGNORED", "reason": "UNSUPPORTED_EVENT"}


def handle_post_tool(
    payload: dict[str, Any], *, workspace: Path = WORKSPACE, **_: Any
) -> dict[str, Any]:
    """Compatibility wrapper for existing local callers."""
    return handle_hook(payload, workspace=workspace)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if isinstance(payload, dict):
            result = handle_hook(payload, workspace=WORKSPACE)
            if "hookSpecificOutput" in result:
                print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    except Exception:
        # Visibility automation must never block or steer the research tool call.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
