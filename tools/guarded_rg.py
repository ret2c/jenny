from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path


TIMEOUT_EXIT = 124


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_guarded_rg(arguments: list[str], timeout_seconds: float) -> int:
    if not arguments:
        print("ripgrep arguments are required", file=sys.stderr)
        return 2
    executable = shutil.which("rg")
    if executable is None:
        print("ripgrep executable was not found", file=sys.stderr)
        return 127
    creationflags = (
        subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    )
    process = subprocess.Popen(
        [executable, *arguments],
        cwd=Path.cwd(),
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _terminate_tree(process)
        print(
            f"ripgrep timed out after {timeout_seconds:g} seconds; process tree terminated",
            file=sys.stderr,
        )
        return TIMEOUT_EXIT


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ripgrep with a bounded timeout and owned process-tree cleanup"
    )
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("rg_args", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 0 < args.timeout_seconds <= 3600:
        print("timeout must be greater than zero and at most 3600 seconds", file=sys.stderr)
        return 2
    rg_args = list(args.rg_args)
    if rg_args[:1] == ["--"]:
        rg_args = rg_args[1:]
    return run_guarded_rg(rg_args, args.timeout_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
