#!/usr/bin/env python3
"""Run resource-bounded, local-only Git history queries."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Sequence


MIN_FREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_COUNT = 500
MAX_SINCE_DAYS = 3650
MAX_PICKAXE_LENGTH = 256
MAX_OUTPUT_BYTES = 1024 * 1024
OUTPUT_FORMATS = {
    "summary": "%H%x09%cI%x09%an%x09%s",
    "authors": "%H%x09%an%x09%ae",
    "hashes": "%H",
}


class HistoryQueryError(RuntimeError):
    """One guarded Git-history validation or execution failure."""


def _safe_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _validate_paths(paths: Sequence[str]) -> list[str]:
    if not paths:
        raise HistoryQueryError("at least one repository-relative path is required")
    validated: list[str] = []
    for value in paths:
        if not isinstance(value, str) or not value.strip():
            raise HistoryQueryError("history path must be a non-empty string")
        path = Path(value.strip())
        if (
            path.is_absolute()
            or path.drive
            or path.root
            or path == Path(".")
            or ".." in path.parts
        ):
            raise HistoryQueryError(
                f"history path must stay repository-relative and bounded: {value}"
            )
        validated.append(path.as_posix())
    return validated


def _base_command(git_executable: str, repository: Path) -> list[str]:
    return [
        git_executable,
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-C",
        str(repository),
    ]


def run_history_query(
    repository: str | Path,
    *,
    paths: Sequence[str],
    since_days: int = 730,
    max_count: int = 50,
    pickaxe_literal: str | None = None,
    output_format: str = "summary",
    timeout_seconds: int = 120,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    disk_usage: Callable[[Path], object] = shutil.disk_usage,
    git_executable: str | None = None,
) -> dict[str, object]:
    bounded_paths = _validate_paths(paths)
    if not isinstance(since_days, int) or not 1 <= since_days <= MAX_SINCE_DAYS:
        raise HistoryQueryError(
            f"since_days must be between 1 and {MAX_SINCE_DAYS}"
        )
    if not isinstance(max_count, int) or not 1 <= max_count <= MAX_COUNT:
        raise HistoryQueryError(f"max_count must be between 1 and {MAX_COUNT}")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 300:
        raise HistoryQueryError("timeout_seconds must be between 1 and 300")
    if output_format not in OUTPUT_FORMATS:
        raise HistoryQueryError("unsupported history output format")
    if pickaxe_literal is not None and (
        not isinstance(pickaxe_literal, str)
        or not pickaxe_literal
        or len(pickaxe_literal) > MAX_PICKAXE_LENGTH
        or "\0" in pickaxe_literal
        or "\n" in pickaxe_literal
        or "\r" in pickaxe_literal
    ):
        raise HistoryQueryError(
            f"pickaxe literal must be 1-{MAX_PICKAXE_LENGTH} single-line characters"
        )

    repository_path = Path(repository).resolve()
    if not repository_path.is_dir():
        raise HistoryQueryError(f"repository directory is missing: {repository_path}")
    free_bytes = int(getattr(disk_usage(repository_path), "free"))
    if free_bytes < MIN_FREE_BYTES:
        raise HistoryQueryError(
            "insufficient free space for guarded history query: "
            f"required={MIN_FREE_BYTES} available={free_bytes}"
        )

    executable = git_executable or shutil.which("git")
    if not executable:
        raise HistoryQueryError("git is unavailable")
    environment = _safe_environment()
    base = _base_command(executable, repository_path)
    common = {
        "capture_output": True,
        "check": False,
        "encoding": "utf-8",
        "env": environment,
        "errors": "replace",
        "stdin": subprocess.DEVNULL,
        "text": True,
        "timeout": timeout_seconds,
    }
    try:
        root_result = runner([*base, "rev-parse", "--show-toplevel"], **common)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HistoryQueryError(f"cannot validate Git repository: {error}") from error
    if root_result.returncode != 0:
        raise HistoryQueryError("history query requires a valid Git repository root")
    reported_root = Path(root_result.stdout.strip()).resolve()
    if reported_root != repository_path:
        raise HistoryQueryError(
            f"--repo must name the checkout root exactly: {reported_root}"
        )

    try:
        promisor_result = runner(
            [
                *base,
                "config",
                "--get-regexp",
                r"^remote\..*\.promisor$",
            ],
            **common,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HistoryQueryError(f"cannot inspect partial-clone state: {error}") from error
    if promisor_result.returncode not in {0, 1}:
        raise HistoryQueryError("cannot inspect partial-clone promisor configuration")
    partial_clone = bool(promisor_result.stdout.strip())

    command = [
        *base,
        "--no-pager",
        "log",
        "--no-ext-diff",
        f"--max-count={max_count}",
        f"--since={since_days} days ago",
        f"--format={OUTPUT_FORMATS[output_format]}",
    ]
    if pickaxe_literal is not None:
        command.append(f"-S{pickaxe_literal}")
    command.extend(["--", *bounded_paths])
    try:
        completed = runner(command, **common)
    except subprocess.TimeoutExpired as error:
        raise HistoryQueryError(
            f"history query exceeded {timeout_seconds} seconds"
        ) from error
    except OSError as error:
        raise HistoryQueryError(f"history query could not start: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Git history query failed").strip()
        if len(detail) > 1200:
            detail = detail[-1200:]
        if partial_clone:
            detail += "; lazy fetch is disabled; narrow the window/path or explicitly hydrate under operator control"
        raise HistoryQueryError(detail)
    output = completed.stdout
    if len(output.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise HistoryQueryError("history query output exceeded the 1 MiB safety limit")
    return {
        "schema": "jenny.guarded-git-history.v1",
        "repository": str(repository_path),
        "partial_clone": partial_clone,
        "since_days": since_days,
        "max_count": max_count,
        "paths": bounded_paths,
        "output": output,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a local-only, resource-bounded Git history query."
    )
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--path", action="append", required=True)
    parser.add_argument("--since-days", type=int, default=730)
    parser.add_argument("--max-count", type=int, default=50)
    parser.add_argument("--pickaxe-literal")
    parser.add_argument("--format", choices=sorted(OUTPUT_FORMATS), default="summary")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = run_history_query(
            args.repo,
            paths=args.path,
            since_days=args.since_days,
            max_count=args.max_count,
            pickaxe_literal=args.pickaxe_literal,
            output_format=args.format,
            timeout_seconds=args.timeout_seconds,
        )
    except HistoryQueryError as error:
        print(json.dumps({"event": "ERROR", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
