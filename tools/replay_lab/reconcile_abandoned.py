#!/usr/bin/env python3
"""Reconcile one recorded guarded run after its controller process died."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

try:
    from .guarded_run import (
        GuardError,
        _execute_once,
        _command_result_is_clean,
        _utc_now,
        _windows_process_snapshot,
        _write_json_atomic,
        inspect_owned_docker_containers,
    )
except ImportError:  # Direct script execution.
    from guarded_run import (  # type: ignore
        GuardError,
        _execute_once,
        _command_result_is_clean,
        _utc_now,
        _windows_process_snapshot,
        _write_json_atomic,
        inspect_owned_docker_containers,
    )


def _process_exists(pid: int) -> bool:
    if pid <= 0:
        raise GuardError("recorded PID must be positive")
    if sys.platform == "win32":
        try:
            return pid in _windows_process_snapshot()
        except OSError as error:
            raise GuardError(f"cannot prove process state for PID {pid}: {error}") from error
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        raise GuardError(f"cannot prove process state for PID {pid}: {error}") from error
    return True


def _recorded_path(payload: dict[str, Any], field: str, run_directory: Path) -> Path:
    raw = payload.get(field)
    if not isinstance(raw, str) or not raw:
        raise GuardError(f"lock is missing recorded {field}")
    path = Path(raw)
    if not path.is_absolute():
        raise GuardError(f"recorded {field} is not absolute")
    path = path.resolve()
    if path != run_directory and run_directory not in path.parents:
        raise GuardError(f"recorded {field} is outside recorded run directory")
    return path


def _inventory(paths: list[Path]) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in paths:
        exists = path.exists()
        entry: dict[str, Any] = {"exists": exists, "path": str(path)}
        if exists and path.is_file():
            entry["byte_length"] = path.stat().st_size
        inventory.append(entry)
    return inventory


def _validate_command(value: Any, field: str) -> list[str]:
    if value == []:
        return []
    if not isinstance(value, list) or not value or not all(
        isinstance(part, str) and part for part in value
    ):
        raise GuardError(f"recorded {field} is not a JSON string array")
    return list(value)


def reconcile_abandoned(
    lock_path: Path,
    *,
    process_probe: Callable[[int], bool] = _process_exists,
    docker_inspector: Callable[[list[str]], dict[str, Any]] = inspect_owned_docker_containers,
) -> dict[str, Any]:
    """Fail closed unless the exact recorded owner, root, paths, and action verify."""
    lock_path = Path(lock_path).resolve()
    try:
        lock_bytes = lock_path.read_bytes()
        payload = json.loads(lock_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuardError("cannot read a valid recorded run lock") from error
    if not isinstance(payload, dict) or payload.get("guarded_run_schema") not in {2, 3}:
        raise GuardError("lock predates the reconciliation metadata contract")
    schema = int(payload["guarded_run_schema"])

    run_raw = payload.get("run_directory")
    if not isinstance(run_raw, str) or not Path(run_raw).is_absolute():
        raise GuardError("lock is missing an absolute recorded run directory")
    run_directory = Path(run_raw).resolve()
    recorded_lock = _recorded_path(payload, "lock_path", run_directory)
    if recorded_lock != lock_path:
        raise GuardError("supplied lock does not match its recorded lock path")
    result_path = _recorded_path(payload, "result_path", run_directory)
    stdout_path = _recorded_path(payload, "stdout_path", run_directory)
    stderr_path = _recorded_path(payload, "stderr_path", run_directory)
    reconciliation_path = _recorded_path(
        payload, "reconciliation_result_path", run_directory
    )

    owner_pid = payload.get("owner_pid")
    root_pid = payload.get("root_pid")
    if not isinstance(owner_pid, int) or owner_pid <= 0:
        raise GuardError("lock has no valid recorded owner PID")
    if not isinstance(root_pid, int) or root_pid <= 0:
        raise GuardError("primary process identity was not durably recorded")
    if process_probe(owner_pid):
        raise GuardError(f"owner PID {owner_pid} is still running")
    if process_probe(root_pid):
        raise GuardError(f"root PID {root_pid} is still running")

    recovery_command = _validate_command(payload.get("recovery_command"), "recovery_command")
    state_changing = bool(payload.get("state_changing", False)) if schema >= 3 else False
    postcondition_command = (
        _validate_command(payload.get("postcondition_command"), "postcondition_command")
        if schema >= 3
        else []
    )
    if state_changing and (not recovery_command or not postcondition_command):
        raise GuardError(
            "state-changing lock lacks exact recovery or independent postcondition metadata"
        )
    owned_docker_containers = payload.get("owned_docker_containers", [])
    if not isinstance(owned_docker_containers, list) or not all(
        isinstance(name, str) and name.strip() for name in owned_docker_containers
    ):
        raise GuardError("recorded owned_docker_containers is not a JSON string array")
    owned_docker_containers = list(dict.fromkeys(owned_docker_containers))
    recovery_timeout = payload.get("recovery_timeout_seconds")
    if not isinstance(recovery_timeout, (int, float)) or recovery_timeout <= 0:
        raise GuardError("recorded recovery timeout is invalid")
    postcondition_timeout = payload.get("postcondition_timeout_seconds", 120)
    if not isinstance(postcondition_timeout, (int, float)) or postcondition_timeout <= 0:
        raise GuardError("recorded postcondition timeout is invalid")
    cwd_raw = payload.get("cwd", "")
    if not isinstance(cwd_raw, str):
        raise GuardError("recorded cwd is invalid")
    cwd = Path(cwd_raw).resolve() if cwd_raw else None

    inventory = _inventory([lock_path, result_path, stdout_path, stderr_path])
    recovery: dict[str, Any] = {
        "attempted": False,
        "command": recovery_command,
        "exit_code": None,
        "timed_out": False,
    }
    if recovery_command:
        recovery_stdout = stdout_path.with_name(
            stdout_path.stem + "_abandoned_recovery" + stdout_path.suffix
        )
        recovery_stderr = stderr_path.with_name(
            stderr_path.stem + "_abandoned_recovery" + stderr_path.suffix
        )
        recovery = _execute_once(
            recovery_command,
            float(recovery_timeout),
            recovery_stdout,
            recovery_stderr,
            cwd,
        )
        recovery["attempted"] = True

    owned_docker_cleanup = docker_inspector(owned_docker_containers)

    postcondition: dict[str, Any] = {
        "attempted": False,
        "command": postcondition_command,
        "exit_code": None,
        "timed_out": False,
    }
    if postcondition_command:
        postcondition_stdout = stdout_path.with_name(
            stdout_path.stem + "_abandoned_postcondition" + stdout_path.suffix
        )
        postcondition_stderr = stderr_path.with_name(
            stderr_path.stem + "_abandoned_postcondition" + stderr_path.suffix
        )
        postcondition = _execute_once(
            postcondition_command,
            float(postcondition_timeout),
            postcondition_stdout,
            postcondition_stderr,
            cwd,
        )
        postcondition["attempted"] = True

    recovery_ok = (
        not recovery.get("attempted")
        or _command_result_is_clean(recovery)
    )
    postcondition_ok = bool(
        not postcondition.get("attempted")
        or _command_result_is_clean(postcondition)
    )
    recovery_ok = bool(
        recovery_ok and owned_docker_cleanup.get("clean") and postcondition_ok
    )
    result: dict[str, Any] = {
        "inventory": inventory,
        "lock_path": str(lock_path),
        "owner_pid": owner_pid,
        "owner_proven_dead": True,
        "reconciled_at": _utc_now(),
        "recorded_run_directory": str(run_directory),
        "recovery": recovery,
        "postcondition": postcondition,
        "owned_docker_containers": owned_docker_containers,
        "owned_docker_cleanup": owned_docker_cleanup,
        "root_pid": root_pid,
        "root_proven_dead": True,
        "status": "ABANDONED_RECOVERY_COMPLETE" if recovery_ok else "ABANDONED_RECOVERY_FAILED",
    }
    _write_json_atomic(reconciliation_path, result)
    if not recovery_ok:
        return result

    if lock_path.read_bytes() != lock_bytes:
        raise GuardError("run lock changed during reconciliation")
    if process_probe(owner_pid) or process_probe(root_pid):
        raise GuardError("recorded process identity became live during reconciliation")
    lock_path.unlink()
    result["status"] = "ABANDONED_RECONCILED"
    result["lock_removed"] = True
    _write_json_atomic(reconciliation_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = reconcile_abandoned(args.lock_file)
    except GuardError as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "ABANDONED_RECONCILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
