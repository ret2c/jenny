#!/usr/bin/env python3
"""Read-only Docker replay preflight for the Windows research host."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WINDOWS_SANDBOX_PROCESS_NAMES = {
    "managedwindowsvm",
    "vmmemwindowssandbox",
    "windowssandbox",
    "windowssandboxclient",
    "windowssandboxremotesession",
    "windowssandboxserver",
}


def _run(command: list[str], timeout: int = 5) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "stdout": "", "error": str(exc)}

    stderr = completed.stderr.strip()
    return {
        "ok": completed.returncode == 0,
        "stdout": completed.stdout.strip(),
        "error": stderr if completed.returncode else "",
    }


def parse_hcsdiag(output: str) -> list[str]:
    """Return IDs for running Windows Sandbox compute systems."""
    running: list[str] = []
    current_id = ""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if re.fullmatch(r"[0-9A-Fa-f-]{4,}", line):
            current_id = line.upper()
            continue
        if current_id and "Running" in line and "WindowsSandbox" in line:
            running.append(current_id)
    return running


def parse_process_names(output: str) -> list[str]:
    """Return recognized Windows Sandbox process names from plain text."""
    recognized: dict[str, str] = {}
    for raw_line in output.splitlines():
        name = raw_line.strip()
        if name and name.casefold() in WINDOWS_SANDBOX_PROCESS_NAMES:
            recognized[name.casefold()] = name
    return sorted(recognized.values(), key=str.casefold)


def collect_windows_sandbox_state() -> dict[str, Any]:
    """Collect independent compute-system and process signals for Sandbox."""
    if platform.system() != "Windows":
        return {
            "running_ids": [],
            "running_processes": [],
            "probe_error": "",
            "process_probe_error": "",
        }

    compute_probe = _run(["hcsdiag", "list"])
    process_probe = _run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-Process -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty ProcessName",
        ]
    )
    return {
        "running_ids": (
            parse_hcsdiag(compute_probe["stdout"]) if compute_probe["ok"] else []
        ),
        "running_processes": (
            parse_process_names(process_probe["stdout"]) if process_probe["ok"] else []
        ),
        "probe_error": compute_probe["error"] if not compute_probe["ok"] else "",
        "process_probe_error": (
            process_probe["error"] if not process_probe["ok"] else ""
        ),
    }


def available_physical_memory_gb() -> float:
    """Return currently available physical memory in GiB."""
    if platform.system() == "Windows":
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError(ctypes.get_last_error(), "GlobalMemoryStatusEx failed")
        return round(status.ullAvailPhys / (1024**3), 2)

    if hasattr(os, "sysconf"):
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return round((pages * page_size) / (1024**3), 2)
    raise OSError("available physical memory probe is unsupported")


def collect_sandbox_launch_resources(minimum_free_memory_gb: float) -> dict[str, Any]:
    """Collect only the host pressure signals needed before Sandbox launch."""
    memory_error = ""
    try:
        available_memory = available_physical_memory_gb()
    except (OSError, ValueError) as exc:
        available_memory = None
        memory_error = str(exc)

    docker_installed = shutil.which("docker") is not None
    version = {"ok": False, "stdout": "", "error": ""}
    inventory = {"ok": False, "stdout": "", "error": ""}
    if docker_installed:
        version = _run(["docker", "version", "--format", "{{.Server.Version}}"])
        inventory = _run(["docker", "ps", "-a", "--format", "{{.Names}}"])

    return {
        "available_memory_gb": available_memory,
        "minimum_free_memory_gb": minimum_free_memory_gb,
        "memory_error": memory_error,
        "docker": {
            "installed": docker_installed,
            "healthy": docker_installed and version["ok"] and inventory["ok"],
            "server_version": version["stdout"] if version["ok"] else "",
            "container_count": (
                len(inventory["stdout"].splitlines()) if inventory["ok"] else 0
            ),
            "version_error": version["error"] if docker_installed else "",
            "inventory_error": inventory["error"] if docker_installed else "",
        },
    }


def evaluate_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    fatal: list[str] = []
    warnings: list[str] = []

    if not snapshot["docker"]["healthy"]:
        fatal.append("DOCKER_ENGINE_UNHEALTHY")
    if (
        snapshot["windows_sandbox"].get("running_ids")
        or snapshot["windows_sandbox"].get("running_processes")
    ):
        fatal.append("WINDOWS_SANDBOX_RUNNING")
    if snapshot["disk"]["free_gb"] < snapshot["disk"]["minimum_gb"]:
        fatal.append("LOW_DISK_SPACE")
    if snapshot["resources"]["conflicts"]:
        fatal.append("RESOURCE_PREFIX_COLLISION")

    if (
        snapshot["windows_sandbox"].get("probe_error")
        or snapshot["windows_sandbox"].get("process_probe_error")
    ):
        warnings.append("WINDOWS_SANDBOX_STATE_UNKNOWN")

    return {"ready": not fatal, "fatal": fatal, "warnings": warnings, "snapshot": snapshot}


def evaluate_sandbox_status(state: dict[str, Any]) -> dict[str, Any]:
    """Fail closed before claiming that Windows Sandbox is fully stopped."""
    fatal: list[str] = []
    if state.get("running_ids") or state.get("running_processes"):
        fatal.append("WINDOWS_SANDBOX_RUNNING")
    if state.get("probe_error") or state.get("process_probe_error"):
        fatal.append("WINDOWS_SANDBOX_STATE_UNKNOWN")
    return {"ready": not fatal, "fatal": fatal, "warnings": []}


def collect_snapshot(prefix: str, minimum_free_gb: float) -> dict[str, Any]:
    version = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    inventory = _run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    docker_healthy = version["ok"] and inventory["ok"]

    names = inventory["stdout"].splitlines() if inventory["ok"] else []
    conflicts = sorted(name for name in names if prefix and name.startswith(prefix))

    sandbox_state = collect_windows_sandbox_state()

    disk_root = Path.cwd().anchor or os.sep
    disk = shutil.disk_usage(disk_root)

    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "cwd": str(Path.cwd())},
        "docker": {
            "healthy": docker_healthy,
            "server_version": version["stdout"] if version["ok"] else "",
            "version_error": version["error"],
            "inventory_error": inventory["error"],
            "container_count": len(names),
        },
        "windows_sandbox": sandbox_state,
        "disk": {
            "root": disk_root,
            "free_gb": round(disk.free / (1024**3), 2),
            "minimum_gb": minimum_free_gb,
        },
        "resources": {"prefix": prefix, "conflicts": conflicts},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed before a Docker-backed replay if the host lab is not ready."
    )
    parser.add_argument("--prefix", help="Owned Docker resource prefix for this replay")
    parser.add_argument("--minimum-free-gb", type=float, default=15.0)
    parser.add_argument(
        "--sandbox-status-only",
        action="store_true",
        help="Check only that Windows Sandbox process and HCS signals are clean",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON evidence path")
    args = parser.parse_args()

    if args.sandbox_status_only:
        sandbox_state = collect_windows_sandbox_state()
        result = evaluate_sandbox_status(sandbox_state)
        result["snapshot"] = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "windows_sandbox": sandbox_state,
        }
    else:
        if not args.prefix:
            parser.error("--prefix is required unless --sandbox-status-only is used")
        result = evaluate_snapshot(collect_snapshot(args.prefix, args.minimum_free_gb))
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    sys.exit(main())
