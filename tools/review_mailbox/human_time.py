from __future__ import annotations

from datetime import datetime


UNITS = (
    ("y", 365 * 24 * 60 * 60),
    ("mo", 30 * 24 * 60 * 60),
    ("w", 7 * 24 * 60 * 60),
    ("d", 24 * 60 * 60),
    ("h", 60 * 60),
    ("m", 60),
)


def format_duration(seconds: int) -> str:
    remaining = max(0, int(seconds))
    if remaining < 60 * 60:
        minutes, seconds_part = divmod(remaining, 60)
        return f"{minutes}m {seconds_part}s"

    parts: list[str] = []
    first_nonzero_index: int | None = None
    for index, (suffix, unit_seconds) in enumerate(UNITS):
        value, remaining = divmod(remaining, unit_seconds)
        if value:
            if first_nonzero_index is None:
                first_nonzero_index = index
            parts.append(f"{value}{suffix}")
            if len(parts) == 2:
                break
    if len(parts) == 1 and first_nonzero_index is not None:
        next_suffix = UNITS[first_nonzero_index + 1][0]
        parts.append(f"0{next_suffix}")
    return " ".join(parts) if parts else "0m"


def format_local_time(value: datetime) -> str:
    return value.strftime("%I:%M:%S %p").lstrip("0")
