from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class RolloutArchiveError(RuntimeError):
    pass


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            length += len(chunk)
    return digest.hexdigest(), length


def _hash_gzip(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    length = 0
    with gzip.open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            length += len(chunk)
    return digest.hexdigest(), length


def archive_rollout(
    *,
    rollout: Path,
    archive_dir: Path,
    sessions_root: Path,
    truncate_after_verify: bool = False,
    expected_sha256: str | None = None,
    confirm_completed: bool = False,
) -> dict[str, Any]:
    source = rollout.resolve()
    allowed_root = sessions_root.resolve()
    destination_root = archive_dir.resolve()
    if not source.is_file() or not _is_within(source, allowed_root):
        raise RolloutArchiveError(
            "rollout must be one exact existing file under the configured sessions root"
        )
    if truncate_after_verify and (
        not confirm_completed
        or expected_sha256 is None
        or len(expected_sha256) != 64
    ):
        raise RolloutArchiveError(
            "truncation requires --confirm-completed and --expected-sha256"
        )

    source_hash, source_length = _hash_file(source)
    if expected_sha256 is not None and source_hash != expected_sha256.lower():
        raise RolloutArchiveError("source rollout does not match expected SHA-256")
    destination_root.mkdir(parents=True, exist_ok=True)
    archive = destination_root / f"{source.name}.gz"
    if archive.exists():
        raise RolloutArchiveError(f"archive already exists: {archive}")
    temporary = destination_root / f".{archive.name}.{uuid.uuid4().hex}.tmp"
    try:
        with source.open("rb") as source_stream, gzip.open(
            temporary, "wb", compresslevel=6
        ) as archive_stream:
            shutil.copyfileobj(source_stream, archive_stream, 1024 * 1024)
        archived_hash, archived_length = _hash_gzip(temporary)
        if (archived_hash, archived_length) != (source_hash, source_length):
            raise RolloutArchiveError("gzip round-trip hash or length mismatch")
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)

    truncated = False
    if truncate_after_verify:
        current_hash, current_length = _hash_file(source)
        if (current_hash, current_length) != (source_hash, source_length):
            raise RolloutArchiveError("source rollout changed before truncation")
        with source.open("r+b") as stream:
            stream.truncate(0)
            stream.flush()
            os.fsync(stream.fileno())
        truncated = True

    payload: dict[str, Any] = {
        "schema": "jenny.completed-rollout-archive.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "source": str(source),
        "source_sha256": source_hash,
        "source_length": source_length,
        "archive": str(archive),
        "archive_roundtrip_sha256": archived_hash,
        "archive_roundtrip_length": archived_length,
        "source_truncated": truncated,
    }
    manifest = archive.with_suffix(archive.suffix + ".manifest.json")
    manifest.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {**payload, "manifest": str(manifest)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Archive one exact completed Codex rollout with round-trip verification"
    )
    parser.add_argument("--rollout", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument(
        "--sessions-root",
        type=Path,
        default=Path.home() / ".codex" / "sessions",
    )
    parser.add_argument("--truncate-after-verify", action="store_true")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--confirm-completed", action="store_true")
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = archive_rollout(
            rollout=args.rollout,
            archive_dir=args.archive_dir,
            sessions_root=args.sessions_root,
            truncate_after_verify=args.truncate_after_verify,
            expected_sha256=args.expected_sha256,
            confirm_completed=args.confirm_completed,
        )
    except (OSError, RolloutArchiveError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
