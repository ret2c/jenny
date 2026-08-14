#!/usr/bin/env python3
"""Inspect private HTTP-style headers without printing their values."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


DEFAULT_HEADERS = (
    "Authorization",
    "Cookie",
    "Proxy-Authorization",
    "Set-Cookie",
    "X-API-Key",
)


def _parse_headers(raw: bytes) -> dict[str, list[bytes]]:
    header_block = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    parsed: dict[str, list[bytes]] = {}
    current_name: str | None = None
    for index, line in enumerate(header_block.replace(b"\r\n", b"\n").split(b"\n")):
        if index == 0 and line.startswith(b"HTTP/"):
            continue
        if line[:1] in {b" ", b"\t"} and current_name and parsed[current_name]:
            parsed[current_name][-1] += b" " + line.strip()
            continue
        if b":" not in line:
            current_name = None
            continue
        name_raw, value = line.split(b":", 1)
        try:
            name = name_raw.decode("ascii").strip().casefold()
        except UnicodeDecodeError:
            current_name = None
            continue
        if not name:
            current_name = None
            continue
        parsed.setdefault(name, []).append(value.strip())
        current_name = name
    return parsed


def inspect_headers(path: Path, requested_headers: list[str]) -> dict[str, object]:
    raw = path.read_bytes()
    parsed = _parse_headers(raw)
    names = {name.casefold() for name in DEFAULT_HEADERS}
    names.update(name.strip().casefold() for name in requested_headers if name.strip())
    headers: dict[str, object] = {}
    for name in sorted(names):
        values = parsed.get(name, [])
        headers[name] = {
            "count": len(values),
            "present": bool(values),
            "value_lengths": [len(value) for value in values],
            "value_sha256": [hashlib.sha256(value).hexdigest() for value in values],
        }
    return {
        "byte_length": len(raw),
        "headers": headers,
        "input_name": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--header", action="append", default=[])
    args = parser.parse_args()
    if not args.input.is_file():
        print(json.dumps({"error": "input is not a regular file"}))
        return 2
    result = inspect_headers(args.input, args.header)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

