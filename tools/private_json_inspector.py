#!/usr/bin/env python3
"""Inspect private JSON while emitting only allowlisted metadata values."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SECRET_NAME = re.compile(
    r"(?:auth|bearer|cookie|credential|key|license|pass|private|secret|session|token)",
    re.IGNORECASE,
)
JWT_LIKE = re.compile(r"^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}$")
OPAQUE_SECRET = re.compile(
    r"^(?:sk-(?:proj-)?|gh[pousr]_|xox[baprs]-|AKIA)[A-Za-z0-9._-]{12,}$",
    re.IGNORECASE,
)


def _scalar_bytes(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _looks_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return (
        stripped.casefold().startswith("bearer ")
        or "-----begin " in stripped.casefold()
        or bool(JWT_LIKE.fullmatch(stripped))
        or bool(OPAQUE_SECRET.fullmatch(stripped))
    )


def _redacted_scalar(value: Any) -> dict[str, Any]:
    raw = _scalar_bytes(value)
    return {
        "byte_length": len(raw),
        "redacted": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "type": _type_name(value),
    }


def _inspect(
    value: Any,
    allow_fields: set[str],
    field_name: str = "",
    path: tuple[str, ...] = (),
    secret_context: bool = False,
) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _inspect(
                child,
                allow_fields,
                str(key),
                (*path, str(key)),
                secret_context or bool(SECRET_NAME.search(str(key))),
            )
            for key, child in sorted(value.items(), key=lambda item: str(item[0]).casefold())
        }
    if isinstance(value, list):
        return {
            "count": len(value),
            "item_types": sorted({_type_name(item) for item in value}),
            "type": "array",
        }
    normalized_name = field_name.casefold()
    normalized_path = ".".join(component.casefold() for component in path)
    explicitly_allowed = normalized_path in allow_fields or (
        len(path) == 1 and normalized_name in allow_fields
    )
    if (
        explicitly_allowed
        and not secret_context
        and not SECRET_NAME.search(field_name)
        and not _looks_secret(value)
    ):
        return {"type": _type_name(value), "value": value}
    return _redacted_scalar(value)


def inspect_json(path: Path, allowed_fields: list[str]) -> dict[str, Any]:
    raw = path.read_bytes()
    document = json.loads(raw.decode("utf-8-sig"))
    allow_fields = {field.strip().casefold() for field in allowed_fields if field.strip()}
    return {
        "byte_length": len(raw),
        "document": _inspect(document, allow_fields),
        "input_name": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--allow-field", action="append", default=[])
    args = parser.parse_args()
    if not args.input.is_file():
        print(json.dumps({"error": "input is not a regular file"}))
        return 2
    try:
        result = inspect_json(args.input, args.allow_field)
    except (UnicodeDecodeError, json.JSONDecodeError):
        print(json.dumps({"error": "input is not valid UTF-8 JSON"}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
