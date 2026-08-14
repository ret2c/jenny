from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


def _decode_line(line: bytes) -> str:
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        return line.decode("cp1252", errors="replace")


def read_tail(path: str | Path, count: int = 80) -> list[str]:
    if count < 1:
        raise ValueError("tail count must be positive")
    raw = Path(path).read_bytes()
    return [_decode_line(line) for line in raw.splitlines()[-count:]]


def append_ascii(path: str | Path, text: str) -> None:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    if not normalized:
        raise ValueError("signoff entry must not be empty")
    try:
        payload = normalized.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("signoff append input must be ASCII") from error
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    prefix = b""
    if destination.exists() and destination.stat().st_size:
        with destination.open("rb") as handle:
            handle.seek(-1, 2)
            if handle.read(1) not in {b"\n", b"\r"}:
                prefix = b"\n"
    with destination.open("ab") as handle:
        handle.write(prefix + payload + b"\n")
        handle.flush()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repair_invalid_utf8(raw: bytes) -> tuple[bytes, list[dict[str, object]]]:
    output = bytearray()
    repairs: list[dict[str, object]] = []
    position = 0
    while position < len(raw):
        remaining = raw[position:]
        try:
            remaining.decode("utf-8")
        except UnicodeDecodeError as error:
            valid_end = position + error.start
            invalid_end = position + error.end
            output.extend(raw[position:valid_end])
            invalid = raw[valid_end:invalid_end]
            replacement_text = invalid.decode("cp1252")
            replacement = replacement_text.encode("utf-8")
            output.extend(replacement)
            repairs.append(
                {
                    "offset": valid_end,
                    "replacement_text": replacement_text,
                    "source_hex": invalid.hex(),
                    "target_hex": replacement.hex(),
                }
            )
            position = invalid_end
        else:
            output.extend(remaining)
            break
    normalized = bytes(output)
    normalized.decode("utf-8")
    return normalized, repairs


def normalize_utf8(path: str | Path, backup_path: str | Path) -> dict[str, object]:
    source = Path(path).resolve()
    backup = Path(backup_path).resolve()
    if source == backup:
        raise ValueError("backup path must differ from the signoff path")
    raw = source.read_bytes()
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        normalized, repairs = _repair_invalid_utf8(raw)
    else:
        return {
            "changed": False,
            "normalized_sha256": _sha256(raw),
            "path": str(source),
            "repair_count": 0,
            "repairs": [],
            "source_sha256": _sha256(raw),
        }

    if not repairs:
        raise ValueError("invalid UTF-8 was detected but no repair was produced")
    source_newlines = re.findall(br"\r\n|\r|\n", raw)
    normalized_newlines = re.findall(br"\r\n|\r|\n", normalized)
    if normalized_newlines != source_newlines:
        raise ValueError("normalization changed the newline sequence")
    if backup.exists():
        raise FileExistsError(f"backup already exists: {backup}")
    temporary = source.with_name(f".{source.name}.{os.getpid()}.utf8.tmp")
    if temporary.exists():
        raise FileExistsError(f"temporary normalization file already exists: {temporary}")

    backup.parent.mkdir(parents=True, exist_ok=True)
    with backup.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    if backup.read_bytes() != raw:
        raise OSError("backup verification failed")

    try:
        with temporary.open("xb") as handle:
            handle.write(normalized)
            handle.flush()
            os.fsync(handle.fileno())
        verified = temporary.read_bytes()
        verified.decode("utf-8")
        if verified != normalized:
            raise OSError("temporary normalization file verification failed")
        os.replace(temporary, source)
    finally:
        if temporary.exists():
            temporary.unlink()

    final = source.read_bytes()
    final.decode("utf-8")
    if final != normalized:
        raise OSError("normalized signoff verification failed")
    return {
        "backup_path": str(backup),
        "backup_sha256": _sha256(raw),
        "changed": True,
        "newline_count": len(source_newlines),
        "normalized_sha256": _sha256(final),
        "normalized_size": len(final),
        "path": str(source),
        "repair_count": len(repairs),
        "repairs": repairs,
        "source_sha256": _sha256(raw),
        "source_size": len(raw),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely read, append, or explicitly normalize signoff.txt"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    tail = commands.add_parser("tail")
    tail.add_argument("--path", type=Path, required=True)
    tail.add_argument("--count", type=int, default=80)
    append = commands.add_parser("append-ascii")
    append.add_argument("--path", type=Path, required=True)
    append.add_argument("--input", type=Path, required=True)
    normalize = commands.add_parser("normalize-utf8")
    normalize.add_argument("--path", type=Path, required=True)
    normalize.add_argument("--backup", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "tail":
            output = {"lines": read_tail(args.path, args.count)}
        elif args.command == "append-ascii":
            text = args.input.read_bytes().decode("ascii")
            append_ascii(args.path, text)
            output = {"appended": True, "path": str(args.path.resolve())}
        else:
            output = normalize_utf8(args.path, args.backup)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
