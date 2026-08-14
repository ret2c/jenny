#!/usr/bin/env python3
"""Run one owned command with an exclusive lock and bounded tree cleanup."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from .preflight import (
        collect_sandbox_launch_resources,
        collect_windows_sandbox_state,
    )
except ImportError:  # Direct script execution.
    from preflight import collect_sandbox_launch_resources, collect_windows_sandbox_state


class GuardError(RuntimeError):
    pass


ACTIVE_TARGET_LONG_RUN_HEARTBEAT_SECONDS = 480


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path = Path(path)
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


def build_run_lock_metadata(
    command: list[str],
    cwd: Path | None,
    lock_file: Path,
    result_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    recovery_command: list[str] | None,
    recovery_timeout_seconds: float,
    owned_docker_containers: list[str] | None = None,
    state_changing: bool = False,
    postcondition_command: list[str] | None = None,
    postcondition_timeout_seconds: float = 120,
) -> dict[str, Any]:
    """Record every input a later reconciler may use, without inference."""
    lock_file = Path(lock_file).resolve()
    result_path = Path(result_path).resolve()
    stdout_path = Path(stdout_path).resolve()
    stderr_path = Path(stderr_path).resolve()
    run_directory = Path(
        os.path.commonpath(
            [
                str(lock_file.parent),
                str(result_path.parent),
                str(stdout_path.parent),
                str(stderr_path.parent),
            ]
        )
    ).resolve()
    reconciliation_result = result_path.with_name(
        result_path.stem + "_abandoned_reconciliation" + result_path.suffix
    )
    return {
        "command": list(command),
        "cwd": str(Path(cwd).resolve()) if cwd else "",
        "guarded_run_schema": 3,
        "lock_path": str(lock_file),
        "reconciliation_result_path": str(reconciliation_result),
        "recovery_command": list(recovery_command or []),
        "recovery_timeout_seconds": float(recovery_timeout_seconds),
        "state_changing": bool(state_changing),
        "postcondition_command": list(postcondition_command or []),
        "postcondition_timeout_seconds": float(postcondition_timeout_seconds),
        "owned_docker_containers": list(owned_docker_containers or []),
        "result_path": str(result_path),
        "root_pid": None,
        "run_directory": str(run_directory),
        "stderr_path": str(stderr_path),
        "stdout_path": str(stdout_path),
    }


def resolve_owned_docker_containers(
    command: list[str], declared_names: list[str] | None
) -> list[str]:
    """Return exact run-owned Docker names and fail closed for unnamed docker run."""
    names = [name.strip() for name in (declared_names or []) if name.strip()]
    executable = Path(command[0]).name.lower() if command else ""
    is_docker_run = executable in {"docker", "docker.exe"} and len(command) > 1 and command[1].lower() == "run"
    if is_docker_run:
        discovered: list[str] = []
        index = 2
        while index < len(command):
            part = command[index]
            if part == "--name":
                if index + 1 >= len(command) or not command[index + 1].strip():
                    raise GuardError("direct docker run requires a non-empty exact --name")
                discovered.append(command[index + 1].strip())
                index += 2
                continue
            if part.startswith("--name="):
                value = part.partition("=")[2].strip()
                if not value:
                    raise GuardError("direct docker run requires a non-empty exact --name")
                discovered.append(value)
            index += 1
        names.extend(discovered)
        if not names:
            raise GuardError(
                "direct docker run requires an exact --name or --owned-docker-container"
            )
    return list(dict.fromkeys(names))


def inspect_owned_docker_containers(
    names: list[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Inspect only declared Docker objects; absence is the sole clean result."""
    surviving: list[dict[str, str]] = []
    absent: list[str] = []
    errors: list[dict[str, str]] = []
    for name in names:
        try:
            completed = runner(
                [
                    "docker",
                    "container",
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    name,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            errors.append({"name": name, "error": str(error)})
            continue
        message = (completed.stderr or completed.stdout or "").strip()
        if completed.returncode == 0:
            surviving.append({"name": name, "status": completed.stdout.strip() or "present"})
        elif "no such container" in message.lower() or "no such object" in message.lower():
            absent.append(name)
        else:
            errors.append(
                {
                    "name": name,
                    "error": message or f"docker inspect exited {completed.returncode}",
                }
            )
    return {
        "clean": not surviving and not errors,
        "surviving": surviving,
        "absent": absent,
        "errors": errors,
    }


def cleanup_owned_docker_containers(
    names: list[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    timeout_seconds: float = 15,
    settle_seconds: float = 2,
    poll_interval_seconds: float = 0.25,
) -> dict[str, Any]:
    """Remove only exact declared containers and prove stable absence."""
    names = list(dict.fromkeys(names))
    if not names:
        return {
            "clean": True,
            "attempted": [],
            "removed": [],
            "surviving": [],
            "absent": [],
            "errors": [],
        }
    for name in names:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None:
            raise GuardError(f"invalid exact Docker container name: {name!r}")
    if timeout_seconds <= 0 or settle_seconds < 0 or poll_interval_seconds <= 0:
        raise GuardError("Docker cleanup timing values are invalid")

    deadline = clock() + timeout_seconds
    quiet_since: float | None = None
    attempted: list[str] = []
    removed: list[str] = []
    removal_counts = {name: 0 for name in names}
    last_probe: dict[str, Any] = {
        "clean": False,
        "surviving": [],
        "absent": [],
        "errors": [],
    }
    cleanup_errors: list[dict[str, str]] = []
    while clock() <= deadline:
        last_probe = inspect_owned_docker_containers(names, runner=runner)
        if last_probe["errors"]:
            cleanup_errors.extend(last_probe["errors"])
            break
        if last_probe["surviving"]:
            quiet_since = None
            for survivor in last_probe["surviving"]:
                name = survivor["name"]
                removal_counts[name] += 1
                attempted.append(name)
                if removal_counts[name] > 3:
                    cleanup_errors.append(
                        {
                            "name": name,
                            "error": "container reappeared after three exact-name removals",
                        }
                    )
                    break
                try:
                    completed = runner(
                        ["docker", "container", "rm", "--force", name],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    cleanup_errors.append({"name": name, "error": str(error)})
                    break
                message = (completed.stderr or completed.stdout or "").strip()
                if completed.returncode == 0:
                    if name not in removed:
                        removed.append(name)
                elif (
                    "no such container" not in message.lower()
                    and "no such object" not in message.lower()
                ):
                    cleanup_errors.append(
                        {
                            "name": name,
                            "error": message
                            or f"docker rm --force exited {completed.returncode}",
                        }
                    )
                    break
            if cleanup_errors:
                break
        else:
            now = clock()
            if quiet_since is None:
                quiet_since = now
            if now - quiet_since >= settle_seconds:
                return {
                    "clean": True,
                    "attempted": attempted,
                    "removed": removed,
                    "surviving": [],
                    "absent": list(last_probe["absent"]),
                    "errors": [],
                }
        sleeper(poll_interval_seconds)

    errors = [*cleanup_errors]
    if not errors and not last_probe["clean"]:
        errors.append(
            {
                "name": ",".join(names),
                "error": "exact-name Docker cleanup did not stabilize before timeout",
            }
        )
    return {
        "clean": False,
        "attempted": attempted,
        "removed": removed,
        "surviving": list(last_probe["surviving"]),
        "absent": list(last_probe["absent"]),
        "errors": errors,
    }


class RunLock:
    """Atomic lock file removed only by the process that created its token."""

    def __init__(self, path: Path, metadata: dict[str, Any] | None = None):
        self.path = Path(path)
        self.token = uuid.uuid4().hex
        self.metadata = dict(metadata or {})
        self.acquired = False

    def __enter__(self) -> "RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            **self.metadata,
            "owner_pid": os.getpid(),
            "owner_token": self.token,
            "created_at": _utc_now(),
        }
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            try:
                existing = self.path.read_text(encoding="utf-8").strip()
            except OSError:
                existing = "unreadable"
            raise GuardError(f"run lock already exists: {self.path}: {existing}") from exc

        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
        except BaseException:
            self.path.unlink(missing_ok=True)
            raise
        self.acquired = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if not self.acquired:
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if payload.get("owner_token") == self.token:
            self.path.unlink(missing_ok=True)
        self.acquired = False

    def update(self, fields: dict[str, Any]) -> None:
        """Atomically extend the current lock only when this owner token matches."""
        if not self.acquired:
            raise GuardError("cannot update an unowned run lock")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise GuardError("cannot read owned run lock for update") from error
        if payload.get("owner_token") != self.token:
            raise GuardError("run lock owner token changed during update")
        payload.update(fields)
        _write_json_atomic(self.path, payload)


def ensure_no_sandbox(state: dict[str, Any]) -> None:
    if state.get("probe_error") or state.get("process_probe_error"):
        raise GuardError("Windows Sandbox state could not be proven clean")
    running = list(state.get("running_ids", [])) + list(
        state.get("running_processes", [])
    )
    if running:
        raise GuardError(f"Windows Sandbox is already running: {running}")


def evaluate_resource_pressure(resources: dict[str, Any]) -> list[str]:
    pressure: list[str] = []
    docker = resources.get("docker", {})
    if docker.get("installed") and not docker.get("healthy"):
        pressure.append("DOCKER_ENGINE_UNHEALTHY")

    available = resources.get("available_memory_gb")
    minimum = float(resources.get("minimum_free_memory_gb", 0))
    if available is None:
        pressure.append("MEMORY_STATE_UNKNOWN")
    elif float(available) < minimum:
        pressure.append("LOW_AVAILABLE_MEMORY")
    return pressure


def ensure_resource_capacity(
    resources: dict[str, Any], allow_pressure: bool
) -> list[str]:
    pressure = evaluate_resource_pressure(resources)
    if pressure and not allow_pressure:
        raise GuardError("sandbox resource pressure: " + ", ".join(pressure))
    return pressure


def build_guard_error_result(
    command: list[str],
    error: BaseException,
    sandbox_state: dict[str, Any] | None = None,
    sandbox_resources: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preserve the evidence that caused a guarded launch to be refused."""
    return {
        "command": command,
        "guard_error": str(error),
        "timed_out": False,
        "exit_code": None,
        "root_exited": True,
        "owned_tree_clean": True,
        "detached_descendants_found": [],
        "detached_descendants_terminated": [],
        "detached_descendants_surviving": [],
        "descendant_cleanup_error": "",
        "recovery": {"attempted": False, "exit_code": None},
        "sandbox_state": sandbox_state,
        "sandbox_launch_resources": sandbox_resources,
        "resource_pressure": (
            evaluate_resource_pressure(sandbox_resources)
            if sandbox_resources is not None
            else []
        ),
        "resource_pressure_overridden": [],
    }


def _windows_process_snapshot() -> dict[int, int]:
    """Return PID -> parent PID without spawning another native process."""
    if sys.platform != "win32":
        return {}

    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    process_next.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_snapshot(0x00000002, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    processes: dict[int, int] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not process_first(handle, ctypes.byref(entry)):
            raise OSError(ctypes.get_last_error(), "Process32FirstW failed")
        while True:
            processes[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            if not process_next(handle, ctypes.byref(entry)):
                break
    finally:
        close_handle(handle)
    return processes


def _new_descendants(
    root_pid: int,
    baseline_pids: set[int],
    snapshot: dict[int, int],
) -> list[int]:
    owned = {root_pid}
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent_pid in snapshot.items():
            if pid in baseline_pids or pid in owned or parent_pid not in owned:
                continue
            owned.add(pid)
            descendants.add(pid)
            changed = True
    return sorted(descendants)


def _cleanup_detached_windows_descendants(
    root_pid: int,
    baseline_pids: set[int],
) -> dict[str, Any]:
    try:
        snapshot = _windows_process_snapshot()
        found = _new_descendants(root_pid, baseline_pids, snapshot)
    except OSError as error:
        return {
            "found": [],
            "terminated": [],
            "surviving": [],
            "error": str(error),
            "clean": False,
        }

    errors: list[str] = []
    top_level = [pid for pid in found if snapshot.get(pid) not in found]
    for pid in top_level:
        try:
            completed = subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if completed.returncode not in (0, 128):
                errors.append(
                    completed.stderr.strip()
                    or completed.stdout.strip()
                    or f"taskkill failed for PID {pid}"
                )
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(f"PID {pid}: {error}")

    remaining = set(found)
    deadline = time.monotonic() + 5
    while remaining and time.monotonic() < deadline:
        try:
            current = _windows_process_snapshot()
        except OSError as error:
            errors.append(str(error))
            break
        remaining = {pid for pid in remaining if pid in current}
        if remaining:
            time.sleep(0.1)

    terminated = sorted(set(found) - remaining)
    return {
        "found": found,
        "terminated": terminated,
        "surviving": sorted(remaining),
        "error": "; ".join(error for error in errors if error),
        "clean": not remaining and not errors,
    }


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    attempted = True
    error = ""
    if process.poll() is not None:
        return {"attempted": attempted, "error": error, "root_exited": True}

    try:
        if sys.platform == "win32":
            completed = subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if completed.returncode not in (0, 128):
                error = completed.stderr.strip() or completed.stdout.strip()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except (OSError, subprocess.SubprocessError) as exc:
        error = str(exc)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if sys.platform == "win32":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            error = error or str(exc)

    return {
        "attempted": attempted,
        "error": error,
        "root_exited": process.poll() is not None,
    }


def _execute_once(
    command: list[str],
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    cwd: Path | None = None,
    on_started: Callable[[int], None] | None = None,
    heartbeat_callback: Callable[[], Any] | None = None,
    heartbeat_interval_seconds: float = 480,
) -> dict[str, Any]:
    if not command:
        raise GuardError("command must not be empty")
    if heartbeat_callback is not None and heartbeat_interval_seconds <= 0:
        raise GuardError("heartbeat interval must be positive")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = _utc_now()
    started = time.monotonic()
    popen_options: dict[str, Any] = {}
    baseline_pids: set[int] = set()
    if sys.platform == "win32":
        baseline_pids = set(_windows_process_snapshot())
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_options["start_new_session"] = True

    with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
        process = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            stdout=stdout_stream,
            stderr=stderr_stream,
            **popen_options,
        )
        if on_started is not None:
            try:
                on_started(process.pid)
            except BaseException:
                _terminate_process_tree(process)
                if sys.platform == "win32":
                    _cleanup_detached_windows_descendants(
                        process.pid, baseline_pids
                    )
                raise
        timed_out = False
        heartbeats: dict[str, Any] = {"attempted": 0, "errors": []}
        termination = {"attempted": False, "error": "", "root_exited": False}
        deadline = started + timeout_seconds
        next_heartbeat = started + heartbeat_interval_seconds
        while process.poll() is None:
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                timed_out = True
                termination = _terminate_process_tree(process)
                break
            wait_for = remaining
            if heartbeat_callback is not None:
                wait_for = min(wait_for, max(0.01, next_heartbeat - now))
            try:
                process.wait(timeout=wait_for)
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if (
                    heartbeat_callback is not None
                    and process.poll() is None
                    and now >= next_heartbeat
                ):
                    heartbeats["attempted"] += 1
                    try:
                        heartbeat_callback()
                    except Exception as error:
                        heartbeats["errors"].append(str(error))
                    next_heartbeat = time.monotonic() + heartbeat_interval_seconds

        if sys.platform == "win32":
            descendants = _cleanup_detached_windows_descendants(
                process.pid, baseline_pids
            )
        else:
            descendants = {
                "found": [],
                "terminated": [],
                "surviving": [],
                "error": "",
                "clean": process.poll() is not None,
            }

    return {
        "command": command,
        "pid": process.pid,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out,
        "exit_code": process.returncode,
        "tree_termination_attempted": termination["attempted"],
        "tree_termination_error": termination["error"],
        "root_exited": process.poll() is not None,
        "owned_tree_clean": descendants["clean"],
        "detached_descendants_found": descendants["found"],
        "detached_descendants_terminated": descendants["terminated"],
        "detached_descendants_surviving": descendants["surviving"],
        "descendant_cleanup_error": descendants["error"],
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "activity_heartbeats": heartbeats,
    }


def _command_result_is_clean(result: dict[str, Any]) -> bool:
    return bool(
        result.get("exit_code") == 0
        and not result.get("timed_out")
        and result.get("root_exited")
        and result.get("owned_tree_clean")
    )


def _run_postcondition(
    command: list[str] | None,
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    cwd: Path | None,
    label: str,
) -> dict[str, Any]:
    if not command:
        return {
            "attempted": False,
            "command": [],
            "exit_code": None,
            "timed_out": False,
        }
    postcondition_stdout = Path(stdout_path).with_name(
        Path(stdout_path).stem + f"_postcondition_{label}" + Path(stdout_path).suffix
    )
    postcondition_stderr = Path(stderr_path).with_name(
        Path(stderr_path).stem + f"_postcondition_{label}" + Path(stderr_path).suffix
    )
    result = _execute_once(
        command,
        timeout_seconds,
        postcondition_stdout,
        postcondition_stderr,
        cwd,
    )
    result["attempted"] = True
    return result


def run_owned(
    command: list[str],
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    cwd: Path | None = None,
    recovery_command: list[str] | None = None,
    recovery_timeout_seconds: float = 120,
    on_started: Callable[[int], None] | None = None,
    owned_docker_containers: list[str] | None = None,
    heartbeat_callback: Callable[[], Any] | None = None,
    heartbeat_interval_seconds: float = 480,
    postcondition_command: list[str] | None = None,
    postcondition_timeout_seconds: float = 120,
) -> dict[str, Any]:
    result = _execute_once(
        command,
        timeout_seconds,
        Path(stdout_path),
        Path(stderr_path),
        Path(cwd) if cwd else None,
        on_started,
        heartbeat_callback,
        heartbeat_interval_seconds,
    )
    owned_docker_containers = list(owned_docker_containers or [])
    docker_cleanup = cleanup_owned_docker_containers(owned_docker_containers)
    result["owned_docker_containers"] = owned_docker_containers
    result["owned_docker_cleanup"] = docker_cleanup
    primary_process_clean = bool(
        result["root_exited"]
        and not result["detached_descendants_surviving"]
        and not result["descendant_cleanup_error"]
    )
    result["owned_tree_clean"] = bool(primary_process_clean and docker_cleanup["clean"])
    initial_postcondition = _run_postcondition(
        postcondition_command,
        postcondition_timeout_seconds,
        Path(stdout_path),
        Path(stderr_path),
        Path(cwd) if cwd else None,
        "initial",
    )
    recovery = {"attempted": False, "exit_code": None, "timed_out": False}
    if recovery_command and (
        result["timed_out"]
        or result["exit_code"] != 0
        or not result["owned_tree_clean"]
        or (
            initial_postcondition.get("attempted")
            and not _command_result_is_clean(initial_postcondition)
        )
    ):
        recovery_stdout = Path(stdout_path).with_name(
            Path(stdout_path).stem + "_recovery" + Path(stdout_path).suffix
        )
        recovery_stderr = Path(stderr_path).with_name(
            Path(stderr_path).stem + "_recovery" + Path(stderr_path).suffix
        )
        recovery = _execute_once(
            recovery_command,
            recovery_timeout_seconds,
            recovery_stdout,
            recovery_stderr,
            Path(cwd) if cwd else None,
            heartbeat_callback=heartbeat_callback,
            heartbeat_interval_seconds=heartbeat_interval_seconds,
        )
        recovery["attempted"] = True
        docker_cleanup = cleanup_owned_docker_containers(owned_docker_containers)
        result["owned_docker_cleanup"] = docker_cleanup
    final_postcondition = (
        _run_postcondition(
            postcondition_command,
            postcondition_timeout_seconds,
            Path(stdout_path),
            Path(stderr_path),
            Path(cwd) if cwd else None,
            "final",
        )
        if recovery.get("attempted")
        else dict(initial_postcondition)
    )
    recovery_clean = bool(
        not recovery.get("attempted") or _command_result_is_clean(recovery)
    )
    postcondition_clean = bool(
        not final_postcondition.get("attempted")
        or _command_result_is_clean(final_postcondition)
    )
    result["owned_tree_clean"] = bool(
        primary_process_clean
        and docker_cleanup["clean"]
        and recovery_clean
        and postcondition_clean
    )
    result["recovery"] = recovery
    result["postcondition"] = {
        "command": list(postcondition_command or []),
        "initial": initial_postcondition,
        "final": final_postcondition,
    }
    return result


def run_preflight_then_owned(
    preflight_command: list[str],
    command: list[str],
    *,
    preflight_timeout_seconds: float,
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    cwd: Path | None = None,
    recovery_command: list[str] | None = None,
    recovery_timeout_seconds: float = 120,
    on_started: Callable[[int], None] | None = None,
    owned_docker_containers: list[str] | None = None,
    heartbeat_callback: Callable[[], Any] | None = None,
    heartbeat_interval_seconds: float = 480,
    postcondition_command: list[str] | None = None,
    postcondition_timeout_seconds: float = 120,
) -> dict[str, Any]:
    """Run a non-mutating gate and launch the child only after a clean PASS."""
    stdout_path = Path(stdout_path)
    stderr_path = Path(stderr_path)
    preflight_stdout = stdout_path.with_name(
        stdout_path.stem + "_preflight" + stdout_path.suffix
    )
    preflight_stderr = stderr_path.with_name(
        stderr_path.stem + "_preflight" + stderr_path.suffix
    )
    preflight = _execute_once(
        preflight_command,
        preflight_timeout_seconds,
        preflight_stdout,
        preflight_stderr,
        Path(cwd) if cwd else None,
    )
    clean = bool(
        not preflight["timed_out"]
        and preflight["exit_code"] == 0
        and preflight["owned_tree_clean"]
    )
    if not clean:
        return {
            "command": command,
            "preflight": preflight,
            "exit_code": 2,
            "timed_out": False,
            "owned_tree_clean": bool(preflight["owned_tree_clean"]),
            "guard_error": "state-changing preflight failed closed; child was not launched",
            "recovery": {"attempted": False, "exit_code": None, "timed_out": False},
        }
    result = run_owned(
        command,
        timeout_seconds,
        stdout_path,
        stderr_path,
        cwd,
        recovery_command,
        recovery_timeout_seconds,
        on_started,
        owned_docker_containers,
        heartbeat_callback,
        heartbeat_interval_seconds,
        postcondition_command,
        postcondition_timeout_seconds,
    )
    result["preflight"] = preflight
    return result


def _read_command_file(path: Path | None) -> list[str] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload or not all(
        isinstance(part, str) and part for part in payload
    ):
        raise GuardError("command file must contain a non-empty JSON string array")
    return payload


def _build_mailbox_activity_callbacks(
    workspace: Path,
    worker: str,
    session_hash: str,
) -> tuple[Callable[[], Any], Callable[[], Any]]:
    """Bind one guarded run's heartbeat and exact terminal cleanup."""
    review_dir = workspace / "tools" / "review_mailbox"
    if str(review_dir) not in sys.path:
        sys.path.insert(0, str(review_dir))
    from review_mailbox import Mailbox  # type: ignore

    mailbox = Mailbox(
        workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
        workspace,
    )
    status = mailbox.status()
    current = next(
        (entry for entry in status["workers"] if entry["worker"] == worker),
        None,
    )
    if current is None or current["state"] != "WORKING":
        raise GuardError(
            f"{worker} must have an existing WORKING check-in before timer heartbeats"
        )
    target = str(current.get("activity_target") or "")
    task_hash = hashlib.sha256(str(current["task"]).encode("utf-8")).hexdigest()
    detail_hash = hashlib.sha256(str(current["detail"]).encode("utf-8")).hexdigest()

    def heartbeat() -> dict[str, Any]:
        semantic = mailbox.activity_heartbeat(
            worker,
            source="guarded-run",
            minimum_age_seconds=0,
            expected_task_hash=task_hash,
            expected_detail_hash=detail_hash,
        )
        activity = mailbox.record_worker_activity(
            worker,
            category="LONG COMMAND",
            detail=f"{target or 'active target'} - owned long command still running",
            source="guarded-run",
            session_hash=session_hash,
            target=target,
        )
        activity["semantic"] = semantic
        return activity

    def cleanup() -> dict[str, Any]:
        return mailbox.clear_worker_activity(
            worker,
            category="LONG COMMAND",
            source="guarded-run",
            session_hash=session_hash,
        )

    return heartbeat, cleanup


def require_active_target_long_run_heartbeat(
    workspace: Path,
    *,
    timeout_seconds: float,
    heartbeat_worker: str | None,
) -> None:
    """Fail closed when an active-target long run lacks a Hunter heartbeat."""
    if (
        timeout_seconds <= ACTIVE_TARGET_LONG_RUN_HEARTBEAT_SECONDS
        or heartbeat_worker == "hunter"
    ):
        return
    lifecycle_db = (
        Path(workspace)
        / "notes"
        / "target_lifecycle"
        / "target_lifecycle.sqlite3"
    )
    if not lifecycle_db.is_file():
        return
    try:
        uri = lifecycle_db.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            rows = connection.execute(
                "SELECT slug FROM targets WHERE status = 'ACTIVE' ORDER BY slug"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise GuardError(
            "cannot verify active-target heartbeat requirement: "
            f"{error}"
        ) from error
    active_slugs = [str(row[0]) for row in rows]
    if active_slugs:
        raise GuardError(
            "active-target guarded commands with a timeout above "
            f"{ACTIVE_TARGET_LONG_RUN_HEARTBEAT_SECONDS} seconds require "
            "--heartbeat-worker hunter after a current semantic WORKING check-in; "
            "active target: "
            + ", ".join(active_slugs)
        )


def _build_mailbox_heartbeat_callback(
    workspace: Path,
    worker: str,
) -> Callable[[], Any]:
    """Backward-compatible heartbeat-only helper for existing callers and tests."""
    heartbeat, _cleanup = _build_mailbox_activity_callbacks(
        workspace,
        worker,
        "0" * 64,
    )
    return heartbeat


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one owned command with a lock and full-tree timeout cleanup."
    )
    parser.add_argument("--lock-file", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--cwd", type=Path)
    parser.add_argument("--require-no-sandbox", action="store_true")
    parser.add_argument("--minimum-free-memory-gb", type=float, default=0.0)
    parser.add_argument("--allow-resource-pressure", action="store_true")
    parser.add_argument("--recovery-command-file", type=Path)
    parser.add_argument("--recovery-timeout-seconds", type=float, default=120)
    parser.add_argument("--postcondition-command-file", type=Path)
    parser.add_argument("--postcondition-timeout-seconds", type=float, default=120)
    parser.add_argument("--state-changing", action="store_true")
    parser.add_argument("--preflight-command-file", type=Path)
    parser.add_argument("--preflight-timeout-seconds", type=float, default=120)
    parser.add_argument("--owned-docker-container", action="append", default=[])
    parser.add_argument("--heartbeat-worker", choices=["hunter"])
    parser.add_argument("--heartbeat-seconds", type=float, default=480)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    result: dict[str, Any]
    sandbox_state = None
    sandbox_final_state = None
    sandbox_final_error = ""
    sandbox_resources = None
    overridden_pressure: list[str] = []
    activity_cleanup_callback: Callable[[], Any] | None = None
    activity_cleanup: dict[str, Any] = {
        "attempted": False,
        "cleared": False,
        "error": "",
        "reason": "NOT_ARMED",
    }
    try:
        if args.require_no_sandbox:
            sandbox_state = collect_windows_sandbox_state()
            ensure_no_sandbox(sandbox_state)
            sandbox_resources = collect_sandbox_launch_resources(
                args.minimum_free_memory_gb
            )
            overridden_pressure = ensure_resource_capacity(
                sandbox_resources, args.allow_resource_pressure
            )
        recovery_command = _read_command_file(args.recovery_command_file)
        postcondition_command = _read_command_file(args.postcondition_command_file)
        preflight_command = _read_command_file(args.preflight_command_file)
        if args.state_changing:
            missing = []
            if preflight_command is None:
                missing.append("--preflight-command-file")
            if recovery_command is None:
                missing.append("--recovery-command-file")
            if postcondition_command is None:
                missing.append("--postcondition-command-file")
            if missing:
                raise GuardError(
                    "--state-changing requires " + ", ".join(missing)
                )
            invalid_timeouts = [
                name
                for name, value in (
                    ("--timeout-seconds", args.timeout_seconds),
                    ("--preflight-timeout-seconds", args.preflight_timeout_seconds),
                    ("--recovery-timeout-seconds", args.recovery_timeout_seconds),
                    ("--postcondition-timeout-seconds", args.postcondition_timeout_seconds),
                )
                if value <= 0
            ]
            if invalid_timeouts:
                raise GuardError(
                    "--state-changing timeout values must be positive: "
                    + ", ".join(invalid_timeouts)
                )
        require_active_target_long_run_heartbeat(
            Path(__file__).resolve().parents[2],
            timeout_seconds=args.timeout_seconds,
            heartbeat_worker=args.heartbeat_worker,
        )
        if args.heartbeat_worker and args.heartbeat_seconds < 60:
            raise GuardError("CLI heartbeat interval must be at least 60 seconds")
        heartbeat_callback = None
        if args.heartbeat_worker:
            activity_session_hash = hashlib.sha256(
                str(args.lock_file.resolve()).encode("utf-8")
            ).hexdigest()
            heartbeat_callback, activity_cleanup_callback = (
                _build_mailbox_activity_callbacks(
                    Path(__file__).resolve().parents[2],
                    args.heartbeat_worker,
                    activity_session_hash,
                )
            )
        owned_docker_containers = resolve_owned_docker_containers(
            command, args.owned_docker_container
        )
        lock_metadata = build_run_lock_metadata(
            command,
            args.cwd,
            args.lock_file,
            args.result,
            args.stdout,
            args.stderr,
            recovery_command,
            args.recovery_timeout_seconds,
            owned_docker_containers,
            state_changing=args.state_changing,
            postcondition_command=postcondition_command,
            postcondition_timeout_seconds=args.postcondition_timeout_seconds,
        )
        lock_metadata["heartbeat_worker"] = args.heartbeat_worker or ""
        lock_metadata["heartbeat_interval_seconds"] = (
            args.heartbeat_seconds if args.heartbeat_worker else 0
        )
        lock_metadata["state_changing"] = bool(args.state_changing)
        lock_metadata["preflight_command"] = list(preflight_command or [])
        with RunLock(args.lock_file, lock_metadata) as run_lock:
            run_arguments = {
                "timeout_seconds": args.timeout_seconds,
                "stdout_path": args.stdout,
                "stderr_path": args.stderr,
                "cwd": args.cwd,
                "recovery_command": recovery_command,
                "recovery_timeout_seconds": args.recovery_timeout_seconds,
                "on_started": lambda pid: run_lock.update(
                    {"root_pid": pid, "root_started_at": _utc_now()}
                ),
                "owned_docker_containers": owned_docker_containers,
                "heartbeat_callback": heartbeat_callback,
                "heartbeat_interval_seconds": args.heartbeat_seconds,
                "postcondition_command": postcondition_command,
                "postcondition_timeout_seconds": args.postcondition_timeout_seconds,
            }
            if args.state_changing:
                assert preflight_command is not None
                result = run_preflight_then_owned(
                    preflight_command,
                    command,
                    preflight_timeout_seconds=args.preflight_timeout_seconds,
                    **run_arguments,
                )
            else:
                result = run_owned(command, **run_arguments)
        if args.require_no_sandbox:
            sandbox_final_state = collect_windows_sandbox_state()
            try:
                ensure_no_sandbox(sandbox_final_state)
            except GuardError as error:
                sandbox_final_error = str(error)
                result["owned_tree_clean"] = False
        result["sandbox_state"] = sandbox_state
        result["sandbox_final_state"] = sandbox_final_state
        result["sandbox_launch_resources"] = sandbox_resources
        result["resource_pressure"] = (
            evaluate_resource_pressure(sandbox_resources)
            if sandbox_resources is not None
            else []
        )
        result["resource_pressure_overridden"] = overridden_pressure
        guard_errors: list[str] = []
        if result.get("guard_error"):
            guard_errors.append(str(result["guard_error"]))
        if sandbox_final_error:
            guard_errors.append(
                "Windows Sandbox final state could not be proven clean: "
                + sandbox_final_error
            )
        docker_cleanup = result.get("owned_docker_cleanup", {})
        process_tree_clean = bool(
            result.get("root_exited", False)
            and not result.get("detached_descendants_surviving", [])
            and not result.get("descendant_cleanup_error", "")
            and docker_cleanup.get("clean", True)
        )
        if not process_tree_clean:
            process_detail = str(result.get("descendant_cleanup_error", ""))
            guard_errors.append(
                (
                    "owned process tree could not be proven clean: "
                    + process_detail
                    + ("; " if process_detail and docker_cleanup else "")
                    + (json.dumps(docker_cleanup, sort_keys=True) if docker_cleanup else "")
                ).rstrip()
            )
        recovery = result.get("recovery", {})
        if recovery.get("attempted") and not _command_result_is_clean(recovery):
            guard_errors.append(
                "recorded recovery did not complete with a clean process tree"
            )
        postcondition = result.get("postcondition", {})
        final_postcondition = postcondition.get("final", {})
        if final_postcondition.get("attempted") and not _command_result_is_clean(
            final_postcondition
        ):
            guard_errors.append(
                "independent postcondition did not prove the final state clean"
            )
        result["guard_error"] = "; ".join(guard_errors)
    except (GuardError, OSError, json.JSONDecodeError) as exc:
        result = build_guard_error_result(
            command,
            exc,
            sandbox_state,
            sandbox_resources,
        )
    finally:
        if activity_cleanup_callback is not None:
            activity_cleanup["attempted"] = True
            try:
                cleanup_outcome = activity_cleanup_callback()
                activity_cleanup.update(cleanup_outcome)
            except Exception as error:
                activity_cleanup["error"] = str(error)
                activity_cleanup["reason"] = "CLEANUP_ERROR"

    result["activity_cleanup"] = activity_cleanup

    rendered = json.dumps(result, indent=2, sort_keys=True)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if result.get("guard_error"):
        return 2
    if result.get("timed_out"):
        return 124
    return int(result.get("exit_code") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
