from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROMPTS = Path(__file__).resolve().parent / "prompts"
ROLE_TASKS = {
    "hunter": PROMPTS / "HUNTER_TASK.txt",
    "midlane": PROMPTS / "MIDLANE_LOOP_TASK.txt",
    "final": PROMPTS / "FINAL_REVIEWER_TASK.txt",
    "final-goal": PROMPTS / "FINAL_REVIEWER_GOAL_TASK.txt",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load_task(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
) -> dict[str, str]:
    task_path = Path(path).resolve()
    data = task_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None:
        expected = expected_sha256.strip().lower()
        if not SHA256.fullmatch(expected):
            raise ValueError("expected_sha256 must be a 64-character lowercase SHA-256")
        if expected == digest:
            return {
                "event": "TASK_UNCHANGED",
                "path": str(task_path),
                "sha256": digest,
            }
    task = task_path.read_text(encoding="utf-8", errors="strict")
    return {
        "event": "TASK_LOADED",
        "path": str(task_path),
        "sha256": digest,
        "task": task,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Load a canonical role task only when its bytes changed."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--role", choices=sorted(ROLE_TASKS))
    source.add_argument("--path", type=Path)
    parser.add_argument("--expected-sha256")
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    path = ROLE_TASKS[args.role] if args.role else args.path
    try:
        result = load_task(path, expected_sha256=args.expected_sha256)
    except (OSError, UnicodeError, ValueError) as error:
        print(json.dumps({"event": "ERROR", "error": str(error)}, sort_keys=True))
        return 2

    header = {key: value for key, value in result.items() if key != "task"}
    print(json.dumps(header, sort_keys=True))
    if result["event"] == "TASK_LOADED":
        print("--- TASK START ---")
        print(result["task"], end="" if result["task"].endswith("\n") else "\n")
        print("--- TASK END ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
