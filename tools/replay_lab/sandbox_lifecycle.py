#!/usr/bin/env python3
"""Launch Windows Sandbox and prove its real lifecycle plus completion marker."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from .preflight import collect_windows_sandbox_state
except ImportError:  # pragma: no cover - direct script execution
    from preflight import collect_windows_sandbox_state


class SandboxLifecycleError(RuntimeError):
    pass


MANAGED_VM_NAME = "ManagedWindowsVM.exe"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_running(state: dict[str, Any]) -> bool:
    return bool(state.get("running_ids") or state.get("running_processes"))


def _require_reliable_probe(state: dict[str, Any]) -> None:
    errors = [
        str(state.get("probe_error", "")).strip(),
        str(state.get("process_probe_error", "")).strip(),
    ]
    errors = [error for error in errors if error]
    if errors:
        raise SandboxLifecycleError("Windows Sandbox state probe failed: " + "; ".join(errors))


def _managed_vm_identity(record: dict[str, Any]) -> tuple[str, int, str]:
    name = str(record.get("name", "")).strip()
    try:
        pid = int(record.get("pid", 0))
    except (TypeError, ValueError) as exc:
        raise SandboxLifecycleError("ManagedWindowsVM process identity has an invalid PID") from exc
    creation_date = str(record.get("creation_date", "")).strip()
    if name.casefold() != MANAGED_VM_NAME.casefold() or pid <= 0 or not creation_date:
        raise SandboxLifecycleError("ManagedWindowsVM process identity is incomplete")
    return name.casefold(), pid, creation_date


def _collect_managed_vm_processes() -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    script = (
        "$rows = @(Get-CimInstance Win32_Process "
        "-Filter \"Name = 'ManagedWindowsVM.exe'\" | "
        "ForEach-Object { [pscustomobject]@{"
        "name=[string]$_.Name;pid=[int]$_.ProcessId;"
        "creation_date=[string]$_.CreationDate} }); "
        "ConvertTo-Json -InputObject $rows -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxLifecycleError("ManagedWindowsVM identity probe failed") from exc
    if completed.returncode != 0:
        raise SandboxLifecycleError("ManagedWindowsVM identity probe failed")
    try:
        decoded = json.loads(completed.stdout.strip() or "[]")
    except json.JSONDecodeError as exc:
        raise SandboxLifecycleError("ManagedWindowsVM identity probe returned invalid JSON") from exc
    rows = decoded if isinstance(decoded, list) else [decoded]
    records: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise SandboxLifecycleError("ManagedWindowsVM identity probe returned invalid data")
        identity = _managed_vm_identity(row)
        records.append(
            {
                "name": MANAGED_VM_NAME,
                "pid": identity[1],
                "creation_date": identity[2],
            }
        )
    return sorted(records, key=lambda record: int(record["pid"]))


def _terminate_managed_vm_process(record: dict[str, Any]) -> None:
    _, pid, creation_date = _managed_vm_identity(record)
    if not re.fullmatch(r"[0-9A-Za-z:+./ -]{1,128}", creation_date):
        raise SandboxLifecycleError("ManagedWindowsVM creation identity is unsafe")
    expected = creation_date.replace("'", "''")
    script = (
        f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\"; "
        "if ($null -eq $p) { exit 3 }; "
        f"if ([string]$p.Name -ne '{MANAGED_VM_NAME}') {{ exit 4 }}; "
        f"if ([string]$p.CreationDate -ne '{expected}') {{ exit 5 }}; "
        f"Stop-Process -Id {pid} -Force -ErrorAction Stop"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxLifecycleError(
            "exact run-owned ManagedWindowsVM termination failed"
        ) from exc
    if completed.returncode != 0:
        raise SandboxLifecycleError(
            "exact run-owned ManagedWindowsVM termination failed "
            f"with exit code {completed.returncode}"
        )


def _fresh_marker(
    completion_marker: Path,
    started_at_ns: int,
) -> dict[str, Any] | None:
    marker = Path(completion_marker)
    if not marker.is_file():
        return None
    marker_stat = marker.stat()
    if marker_stat.st_ctime_ns < started_at_ns:
        return None
    if marker_stat.st_mtime_ns < started_at_ns:
        return None
    if marker_stat.st_mtime_ns > time.time_ns() + 300_000_000_000:
        return None
    return {
        "completion_marker": str(marker),
        "completion_marker_fresh": True,
        "completion_marker_mtime_ns": marker_stat.st_mtime_ns,
        "completion_marker_size": marker_stat.st_size,
    }


def monitor_sandbox_lifecycle(
    collect_state: Callable[[], dict[str, Any]],
    completion_marker: Path,
    started_at_ns: int,
    startup_timeout_seconds: float,
    shutdown_timeout_seconds: float,
    poll_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    collect_managed_vm_processes: Callable[[], list[dict[str, Any]]] | None = None,
    terminate_managed_vm_process: Callable[[dict[str, Any]], None] | None = None,
    baseline_managed_vm_processes: list[dict[str, Any]] | None = None,
    post_clean_stabilization_seconds: float = 0,
) -> dict[str, Any]:
    """Require a running Sandbox signal, a later clean state, and a fresh marker."""
    startup_deadline = monotonic() + startup_timeout_seconds
    startup_state: dict[str, Any] | None = None
    last_state: dict[str, Any] = {}
    while startup_state is None:
        last_state = collect_state()
        _require_reliable_probe(last_state)
        if _is_running(last_state):
            startup_state = last_state
            break
        if monotonic() >= startup_deadline:
            raise SandboxLifecycleError(
                "Windows Sandbox did not start before the startup deadline"
            )
        sleep(poll_seconds)

    owned_managed_vm: dict[str, Any] | None = None
    if collect_managed_vm_processes is not None:
        startup_records = collect_managed_vm_processes()
        if len(startup_records) == 1:
            _managed_vm_identity(startup_records[0])
            owned_managed_vm = dict(startup_records[0])

    shutdown_deadline = monotonic() + shutdown_timeout_seconds
    managed_vm_reconciliation: dict[str, Any] = {"attempted": False}
    clean_since: float | None = None
    stabilization_resets = 0
    clean_observations = 0
    while True:
        last_state = collect_state()
        _require_reliable_probe(last_state)
        if not _is_running(last_state):
            clean_observations += 1
            if clean_since is None:
                clean_since = monotonic()
            if (
                monotonic() - clean_since
                >= max(0.0, post_clean_stabilization_seconds)
            ):
                break
            sleep(poll_seconds)
            continue
        if clean_since is not None:
            stabilization_resets += 1
            clean_since = None
        if (
            owned_managed_vm is None
            and baseline_managed_vm_processes == []
            and collect_managed_vm_processes is not None
        ):
            delayed_records = collect_managed_vm_processes()
            if len(delayed_records) > 1:
                raise SandboxLifecycleError(
                    "multiple ManagedWindowsVM processes appeared after a clean baseline"
                )
            if len(delayed_records) == 1:
                _managed_vm_identity(delayed_records[0])
                owned_managed_vm = dict(delayed_records[0])
        only_managed_vm_remains = {
            str(name).casefold().removesuffix(".exe")
            for name in last_state.get("running_processes", [])
        } == {"managedwindowsvm"}
        if (
            not last_state.get("running_ids")
            and only_managed_vm_remains
            and owned_managed_vm is not None
            and not managed_vm_reconciliation["attempted"]
            and _fresh_marker(completion_marker, started_at_ns) is not None
            and collect_managed_vm_processes is not None
            and terminate_managed_vm_process is not None
        ):
            current_records = collect_managed_vm_processes()
            if (
                len(current_records) == 1
                and _managed_vm_identity(current_records[0])
                == _managed_vm_identity(owned_managed_vm)
            ):
                terminate_managed_vm_process(dict(owned_managed_vm))
                managed_vm_reconciliation = {
                    "attempted": True,
                    "creation_date": str(owned_managed_vm["creation_date"]),
                    "name": str(owned_managed_vm["name"]),
                    "pid": int(owned_managed_vm["pid"]),
                }
                continue
        if monotonic() >= shutdown_deadline:
            raise SandboxLifecycleError(
                "Windows Sandbox did not shut down before the lifecycle deadline"
            )
        sleep(poll_seconds)

    marker = Path(completion_marker)
    marker_evidence = _fresh_marker(marker, started_at_ns)
    if not marker.is_file():
        raise SandboxLifecycleError(f"completion marker was not created: {marker}")
    if marker_evidence is None:
        raise SandboxLifecycleError(
            f"completion marker was not refreshed by this run: {marker}"
        )

    return {
        "startup_observed": True,
        "shutdown_observed": True,
        "startup_state": startup_state,
        "final_state": last_state,
        "managed_vm_reconciliation": managed_vm_reconciliation,
        "post_clean_stabilization": {
            "completed": True,
            "seconds": max(0.0, post_clean_stabilization_seconds),
            "clean_observations": clean_observations,
            "resets": stabilization_resets,
        },
        **marker_evidence,
    }


def launch_and_monitor(
    sandbox_executable: Path,
    configuration: Path,
    completion_marker: Path,
    startup_timeout_seconds: float,
    shutdown_timeout_seconds: float,
    poll_seconds: float,
    post_clean_stabilization_seconds: float = 10,
) -> dict[str, Any]:
    sandbox = Path(sandbox_executable).resolve()
    config = Path(configuration).resolve()
    if not sandbox.is_file():
        raise SandboxLifecycleError(f"Windows Sandbox executable is missing: {sandbox}")
    if not config.is_file():
        raise SandboxLifecycleError(f"Sandbox configuration is missing: {config}")
    baseline_managed_vm = _collect_managed_vm_processes()
    if baseline_managed_vm:
        raise SandboxLifecycleError(
            "refusing to launch with a pre-existing ManagedWindowsVM process"
        )

    marker = Path(completion_marker).resolve()
    if marker.exists():
        if not marker.is_file():
            raise SandboxLifecycleError(
                "pre-existing completion marker is not a regular file"
            )
        try:
            marker.unlink()
        except OSError as exc:
            raise SandboxLifecycleError(
                "could not remove the pre-existing completion marker"
            ) from exc

    started_at_ns = time.time_ns()
    started_at = _utc_now()
    launcher = subprocess.Popen([str(sandbox), str(config)])
    lifecycle = monitor_sandbox_lifecycle(
        collect_windows_sandbox_state,
        marker,
        started_at_ns,
        startup_timeout_seconds,
        shutdown_timeout_seconds,
        poll_seconds,
        collect_managed_vm_processes=_collect_managed_vm_processes,
        terminate_managed_vm_process=_terminate_managed_vm_process,
        baseline_managed_vm_processes=baseline_managed_vm,
        post_clean_stabilization_seconds=post_clean_stabilization_seconds,
    )
    try:
        launcher_exit_code = launcher.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise SandboxLifecycleError(
            "WindowsSandbox.exe launcher remained alive after Sandbox shutdown"
        ) from exc
    if launcher_exit_code != 0:
        raise SandboxLifecycleError(
            f"WindowsSandbox.exe launcher exited {launcher_exit_code}"
        )

    return {
        "success": True,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "sandbox_executable": str(sandbox),
        "configuration": str(config),
        "launcher_pid": launcher.pid,
        "launcher_exit_code": launcher_exit_code,
        **lifecycle,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox-executable", type=Path, required=True)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--completion-marker", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--startup-timeout-seconds", type=float, default=60)
    parser.add_argument("--shutdown-timeout-seconds", type=float, required=True)
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument(
        "--post-clean-stabilization-seconds",
        type=float,
        default=10,
    )
    args = parser.parse_args(argv)

    try:
        payload = launch_and_monitor(
            args.sandbox_executable,
            args.configuration,
            args.completion_marker,
            args.startup_timeout_seconds,
            args.shutdown_timeout_seconds,
            args.poll_seconds,
            args.post_clean_stabilization_seconds,
        )
    except (OSError, subprocess.SubprocessError, SandboxLifecycleError) as exc:
        payload = {
            "success": False,
            "finished_at": _utc_now(),
            "sandbox_executable": str(args.sandbox_executable),
            "configuration": str(args.configuration),
            "completion_marker": str(args.completion_marker),
            "error": str(exc),
        }

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if payload.get("success") else 2


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    raise SystemExit(main())
