#!/usr/bin/env python3
"""Run one recursive rg search with an internal timeout and tree cleanup."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

try:
    from .guarded_run import GuardError, RunLock, run_owned
except ImportError:  # Direct script execution.
    from guarded_run import GuardError, RunLock, run_owned


def _console_safe(text: str, stream: object) -> str:
    """Replace characters the active Windows console encoding cannot print."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run rg through the bounded process guard")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--rg-executable", default="rg")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("rg_arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    rg_arguments = list(args.rg_arguments)
    if rg_arguments and rg_arguments[0] == "--":
        rg_arguments.pop(0)
    if not rg_arguments:
        parser.error("rg arguments are required after --")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")

    workspace = Path(__file__).resolve().parents[2]
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else workspace
        / "scratch"
        / "replay_lab"
        / "guarded_rg"
        / uuid.uuid4().hex
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / "stdout.txt"
    stderr_path = output_dir / "stderr.txt"
    result_path = output_dir / "result.json"
    lock_path = output_dir.parent / "guarded_rg.lock"
    command = [args.rg_executable, *rg_arguments]

    try:
        with RunLock(lock_path, {"command": command}):
            result = run_owned(
                command,
                args.timeout_seconds,
                stdout_path,
                stderr_path,
                workspace,
            )
    except (GuardError, OSError) as error:
        result = {
            "command": command,
            "guard_error": str(error),
            "timed_out": False,
            "exit_code": None,
            "owned_tree_clean": True,
        }

    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if stdout_path.exists():
        sys.stdout.write(
            _console_safe(
                stdout_path.read_text(encoding="utf-8", errors="replace"), sys.stdout
            )
        )
    if stderr_path.exists():
        sys.stderr.write(
            _console_safe(
                stderr_path.read_text(encoding="utf-8", errors="replace"), sys.stderr
            )
        )

    if result.get("guard_error") or not result.get("owned_tree_clean", True):
        return 2
    if result.get("timed_out"):
        return 124
    return int(result.get("exit_code") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
