#!/usr/bin/env python3
"""Inspect one Docker container without requesting or displaying process arguments."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from typing import Any


SCHEMA = "jenny.safe-process-inspection.v1"
CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PROCESS_STATE = re.compile(r"^[A-Za-z+<]+$")
ELAPSED_TIME = re.compile(r"^(?:\d+-)?(?:\d{1,2}:)?\d{2}:\d{2}$")
DOCKER_TOP_COLUMNS = "pid,stat,pcpu,pmem,etime"
DOCKER_TOP_HEADER = ["PID", "STAT", "%CPU", "%MEM", "ELAPSED"]


def _digest(value: str) -> dict[str, object]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _parse_processes(output: str) -> tuple[list[dict[str, object]], int]:
    processes: list[dict[str, object]] = []
    invalid_rows = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if fields == DOCKER_TOP_HEADER:
            continue
        if len(fields) != 5:
            invalid_rows += 1
            continue
        pid_text, state, cpu_text, memory_text, elapsed = fields
        try:
            pid = int(pid_text)
            cpu_percent = float(cpu_text)
            memory_percent = float(memory_text)
        except ValueError:
            invalid_rows += 1
            continue
        if (
            pid <= 0
            or not PROCESS_STATE.fullmatch(state)
            or cpu_percent < 0
            or memory_percent < 0
            or memory_percent > 100
            or not ELAPSED_TIME.fullmatch(elapsed)
        ):
            invalid_rows += 1
            continue
        processes.append(
            {
                "cpu_percent": cpu_percent,
                "elapsed": elapsed,
                "memory_percent": memory_percent,
                "pid": pid,
                "state": state,
            }
        )
    return processes, invalid_rows


def inspect_docker_processes(
    container: str,
    *,
    timeout_seconds: int = 5,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, object]:
    if not CONTAINER_NAME.fullmatch(container):
        raise ValueError("invalid container name")
    if not 1 <= timeout_seconds <= 30:
        raise ValueError("timeout_seconds must be between 1 and 30")

    command = [
        "docker",
        "top",
        container,
        "-eo",
        DOCKER_TOP_COLUMNS,
    ]
    base: dict[str, object] = {
        "backend": "docker",
        "container": container,
        "processes": [],
        "schema": SCHEMA,
    }
    try:
        completed = runner(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return {**base, "status": "docker_unavailable"}
    except subprocess.TimeoutExpired:
        return {
            **base,
            "status": "timeout",
            "timeout_seconds": timeout_seconds,
        }

    if completed.returncode != 0:
        stderr = _digest(completed.stderr or "")
        return {
            **base,
            "returncode": int(completed.returncode),
            "status": "docker_error",
            "stderr_length": stderr["length"],
            "stderr_sha256": stderr["sha256"],
        }

    processes, invalid_rows = _parse_processes(completed.stdout or "")
    if invalid_rows:
        return {
            **base,
            "invalid_row_count": invalid_rows,
            "status": "invalid_output",
        }
    return {
        **base,
        "process_count": len(processes),
        "processes": processes,
        "status": "ok",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=5)
    args = parser.parse_args()
    try:
        result = inspect_docker_processes(
            args.container,
            timeout_seconds=args.timeout_seconds,
        )
    except ValueError as error:
        result = {
            "error": str(error),
            "schema": SCHEMA,
            "status": "invalid_request",
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
