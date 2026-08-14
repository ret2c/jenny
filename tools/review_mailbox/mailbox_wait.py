from __future__ import annotations

import ctypes
import hashlib
import os
import sqlite3
from pathlib import Path


OWNER_GONE_DETAIL = (
    "The launching tool controller exited; the waiter stopped to avoid "
    "leaving a detached background process."
)
DEFAULT_TRANSIENT_IO_ERROR_LIMIT = 12


def is_transient_sqlite_io_error(error: sqlite3.Error) -> bool:
    error_code = getattr(error, "sqlite_errorcode", None)
    if isinstance(error_code, int) and error_code & 0xFF == sqlite3.SQLITE_IOERR:
        return True
    return str(error).strip().casefold() == "disk i/o error"


def connect_read_only(database: Path) -> sqlite3.Connection:
    uri = f"{database.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection
    except Exception:
        connection.close()
        raise


def file_signature(path: Path) -> tuple[int, int, str]:
    data = path.read_bytes()
    stat = path.stat()
    return stat.st_mtime_ns, len(data), hashlib.sha256(data).hexdigest()


def process_is_alive(pid: int) -> bool:
    if pid < 1:
        return False
    if os.name == "nt":
        process_query_limited_information = 0x1000
        synchronize = 0x00100000
        wait_timeout = 0x00000102
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
            process_query_limited_information | synchronize,
            False,
            pid,
        )
        if not handle:
            return False
        try:
            return (
                ctypes.windll.kernel32.WaitForSingleObject(handle, 0)  # type: ignore[attr-defined]
                == wait_timeout
            )
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
