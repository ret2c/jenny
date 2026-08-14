from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "jenny.secret-safe-search.v1"
SECRET_CLASSES = {
    "authorization": re.compile(r"authorization", re.I),
    "credential": re.compile(r"credential", re.I),
    "identity": re.compile(r"identity", re.I),
    "key": re.compile(r"(?:api[_-]?key|private[_-]?key|secret[_-]?key|\bkey\b)", re.I),
    "password": re.compile(r"(?:password|passwd|pwd)", re.I),
    "secret": re.compile(r"secret", re.I),
    "token": re.compile(r"token", re.I),
}


class SearchError(RuntimeError):
    pass


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _line_bytes(lines: dict[str, Any]) -> bytes:
    text = lines.get("text")
    if isinstance(text, str):
        return text.encode("utf-8", errors="replace")
    encoded = lines.get("bytes")
    if isinstance(encoded, str):
        return base64.b64decode(encoded, validate=True)
    return b""


def search(
    workspace: str | Path,
    paths: list[str | Path],
    pattern: str,
) -> dict[str, Any]:
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise SearchError(f"workspace does not exist: {root}")
    if not isinstance(pattern, str) or not pattern:
        raise SearchError("a non-empty search pattern is required")
    resolved: list[Path] = []
    for value in paths:
        candidate = Path(value).resolve()
        if not _within(candidate, root):
            raise SearchError("every search path must stay inside the workspace")
        if not candidate.exists():
            raise SearchError(f"search path does not exist: {candidate}")
        resolved.append(candidate)
    if not resolved:
        raise SearchError("at least one search path is required")
    executable = shutil.which("rg")
    if executable is None:
        raise SearchError("rg is unavailable")
    completed = subprocess.run(
        [executable, "--json", "--line-number", "-e", pattern, *map(str, resolved)],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise SearchError(
            "rg failed; stderr metadata: "
            f"length={len(completed.stderr)} "
            f"sha256={hashlib.sha256(completed.stderr).hexdigest()}"
        )

    matches: dict[tuple[str, int], dict[str, Any]] = {}
    for raw_event in completed.stdout.splitlines():
        try:
            event = json.loads(raw_event)
        except json.JSONDecodeError as error:
            raise SearchError("rg emitted invalid JSON") from error
        if event.get("type") != "match":
            continue
        data = event.get("data", {})
        path_data = data.get("path", {})
        path_value = path_data.get("text")
        if not isinstance(path_value, str):
            continue
        path = Path(path_value).resolve()
        if not _within(path, root):
            raise SearchError("rg returned a path outside the workspace")
        line_number = int(data.get("line_number") or 0)
        line = _line_bytes(data.get("lines", {}))
        searchable = line.decode("utf-8", errors="replace")
        classes = sorted(
            label for label, expression in SECRET_CLASSES.items()
            if expression.search(searchable)
        )
        key = (path.relative_to(root).as_posix(), line_number)
        matches[key] = {
            "path": key[0],
            "line": line_number,
            "classes": classes or ["secret-like-match"],
            "line_length": len(line),
            "line_sha256": hashlib.sha256(line).hexdigest(),
        }
    ordered = [matches[key] for key in sorted(matches)]
    return {
        "schema": SCHEMA,
        "pattern_sha256": hashlib.sha256(pattern.encode("utf-8")).hexdigest(),
        "match_count": len(ordered),
        "matches": ordered,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search secret-bearing material without emitting matched values"
    )
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--pattern", required=True)
    parser.add_argument("--path", action="append", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = search(args.workspace, args.path, args.pattern)
    except (OSError, ValueError, SearchError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
