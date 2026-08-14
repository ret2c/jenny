from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


class AICovTrialError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    argv: list[str],
    cwd: Path,
    timeout_seconds: int = 1200,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def _sanitize_transcript_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitize_transcript_value(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_transcript_value(child) for child in value]
    if isinstance(value, str):
        return value.translate(
            {
                0x00: None,
                0x07: "a",
                0x08: "b",
                0x0B: "v",
                0x0C: "f",
            }
        )
    return value


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _stream_codex_backfill(
    *,
    source: Path,
    session_id: str,
    timeout_seconds: int,
    session_finder=None,
    record_payloads=None,
    event_builder=None,
    event_appender=None,
) -> dict[str, int | str]:
    if session_finder is None:
        from aicov.transcripts import find_codex_session_matches

        session_finder = find_codex_session_matches
    if record_payloads is None:
        from aicov.codex_transcript import payloads_from_codex_record

        record_payloads = payloads_from_codex_record
    if event_builder is None:
        from aicov.hooks import events_from_payload

        event_builder = events_from_payload
    if event_appender is None:
        from aicov.storage import append_events

        event_appender = append_events

    matches = [Path(path).resolve() for path in session_finder(session_id)]
    if len(matches) != 1:
        raise AICovTrialError(
            f"expected one exact Codex transcript for {session_id}, found {len(matches)}"
        )
    transcript = matches[0]
    deadline = time.monotonic() + timeout_seconds
    counts = {
        "records_read": 0,
        "records_malformed": 0,
        "payloads_rejected": 0,
        "events_without_file": 0,
        "events_outside_source": 0,
        "events_imported": 0,
    }
    pending: list[object] = []

    def flush() -> None:
        if not pending:
            return
        counts["events_imported"] += int(
            event_appender(pending, root=source, dedupe=True)
        )
        pending.clear()

    with transcript.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if time.monotonic() > deadline:
                raise AICovTrialError(
                    f"Codex transcript backfill exceeded {timeout_seconds} seconds"
                )
            counts["records_read"] += 1
            try:
                record = _sanitize_transcript_value(json.loads(line))
            except json.JSONDecodeError:
                counts["records_malformed"] += 1
                continue
            try:
                payloads = record_payloads(record)
            except (OSError, TypeError, ValueError):
                counts["payloads_rejected"] += 1
                continue
            for payload in payloads:
                try:
                    event_root, events = event_builder(
                        _sanitize_transcript_value(payload)
                    )
                except (OSError, TypeError, ValueError):
                    counts["payloads_rejected"] += 1
                    continue
                for event in events:
                    file_value = getattr(event, "file", None)
                    if not file_value:
                        counts["events_without_file"] += 1
                        continue
                    try:
                        event_path = Path(str(file_value))
                        if not event_path.is_absolute():
                            event_path = Path(event_root) / event_path
                        event_path = event_path.resolve()
                    except (OSError, ValueError):
                        counts["payloads_rejected"] += 1
                        continue
                    if not _is_within(event_path, source):
                        counts["events_outside_source"] += 1
                        continue
                    event.file = event_path.relative_to(source).as_posix()
                    event.repo_root = str(source)
                    event.cwd = str(source)
                    pending.append(event)
                    if len(pending) >= 500:
                        flush()
    flush()
    return {"transcript": str(transcript), **counts}


def collect(
    *,
    source_root: Path,
    output_dir: Path,
    session_id: str,
    executable: str = "aicov",
    runner: Callable[[list[str], Path], subprocess.CompletedProcess[str]] = _run,
    step_timeout_seconds: int = 1200,
) -> dict[str, object]:
    source = source_root.resolve()
    output = output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    terminal_path = output / "terminal_result.json"
    started = time.monotonic()

    def remaining_budget() -> int:
        remaining = step_timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise AICovTrialError(
                f"aicov telemetry budget of {step_timeout_seconds} seconds was exhausted"
            )
        return max(1, math.ceil(remaining))

    def write_terminal(status: str, *, error: Exception | None = None) -> None:
        payload: dict[str, object] = {
            "schema": "jenny.aicov-terminal.v1",
            "status": status,
            "generated_at": datetime.now(UTC).isoformat(),
            "source_root": str(source),
            "elapsed_seconds": round(max(0.0, time.monotonic() - started), 3),
            "unread_present": (output / "unread.txt").is_file(),
            "completion_authority": False,
            "proof_authority": False,
        }
        if error is not None:
            payload["error_type"] = type(error).__name__
            payload["error"] = str(error)[:1000]
        temporary = terminal_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        temporary.replace(terminal_path)

    coverage = output / "coverage.json"
    summary = output / "summary.txt"
    unread = output / "unread.txt"
    try:
        if not source.is_dir():
            raise AICovTrialError(f"source root does not exist: {source}")
        if not session_id.strip():
            raise AICovTrialError("session id is required")
        if step_timeout_seconds < 1:
            raise AICovTrialError("telemetry budget must be positive")
        command_prefix = [executable]
        native_backfill = runner is _run
        if native_backfill:
            resolved = shutil.which(executable)
            if resolved is not None:
                command_prefix = [resolved]
            elif executable == "aicov" and importlib.util.find_spec("aicov") is not None:
                command_prefix = [sys.executable, "-m", "aicov"]
            else:
                raise AICovTrialError(
                    "aicov is not installed; install trailofbits/aicov explicitly before this opt-in trial"
                )
        backfill: dict[str, object]
        if native_backfill:
            backfill = _stream_codex_backfill(
                source=source,
                session_id=session_id,
                timeout_seconds=remaining_budget(),
            )
            remaining_budget()

            def execute(
                argv: list[str], cwd: Path
            ) -> subprocess.CompletedProcess[str]:
                return _run(argv, cwd, remaining_budget())

            commands: list[list[str]] = []
        else:
            backfill = {"mode": "injected-runner"}
            execute = runner
            commands = [
                [
                    *command_prefix,
                    "--root",
                    str(source),
                    "backfill",
                    "--agent",
                    "auto",
                    "--session-id",
                    session_id,
                ]
            ]
        commands.extend(
            [
                [
                    *command_prefix,
                    "--root",
                    str(source),
                    "report",
                    "--format",
                    "json",
                    "--out",
                    str(coverage),
                ],
                [*command_prefix, "--root", str(source), "summary"],
                [*command_prefix, "--root", str(source), "unread", "--limit", "200"],
            ]
        )
        for index, argv in enumerate(commands):
            remaining_budget()
            result = execute(argv, source)
            remaining_budget()
            if result.returncode != 0:
                raise AICovTrialError(
                    f"aicov step {index + 1} failed with exit {result.returncode}"
                )
            if "summary" in argv:
                summary.write_text(result.stdout, encoding="utf-8", newline="\n")
            elif "unread" in argv:
                unread.write_text(result.stdout, encoding="utf-8", newline="\n")
        if not coverage.is_file():
            raise AICovTrialError("aicov did not produce coverage.json")
        if not unread.is_file():
            raise AICovTrialError(
                "aicov did not produce unread.txt within the telemetry budget"
            )
        result_path = output / "trial_result.json"
        payload: dict[str, object] = {
            "schema": "jenny.aicov-trial.v1",
            "status": "TELEMETRY_ONLY",
            "generated_at": datetime.now(UTC).isoformat(),
            "source_root": str(source),
            "coverage_sha256": _sha256(coverage),
            "summary_sha256": _sha256(summary),
            "unread_sha256": _sha256(unread),
            "backfill": backfill,
            "completion_authority": False,
            "proof_authority": False,
            "allowed_use": "prioritize source blind spots for independent review",
        }
        result_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        write_terminal("COMPLETE")
        return {**payload, "result_path": str(result_path)}
    except Exception as error:
        write_terminal("FAILED", error=error)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Opt-in aicov source-attention telemetry; never a proof gate"
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--executable", default="aicov")
    parser.add_argument(
        "--step-timeout-seconds",
        type=int,
        default=1200,
        help="total telemetry budget retained under the legacy option name",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = collect(
            source_root=args.source_root,
            output_dir=args.output_dir,
            session_id=args.session_id,
            executable=args.executable,
            step_timeout_seconds=args.step_timeout_seconds,
        )
    except (AICovTrialError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
