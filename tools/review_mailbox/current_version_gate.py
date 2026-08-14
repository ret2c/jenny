from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import multiprocessing
import re
import socket
import sqlite3
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable


SOURCE_SCHEMA = "jenny.current-version-source.v1"
RECEIPT_SCHEMA = "jenny.current-version-receipt.v1"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_AGE_HOURS = 16
REGEX_TIMEOUT_SECONDS = 1.0
AUTHORITY_VERSION = 2


class CurrentVersionError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _private_json_path(workspace: Path, value: str | Path, label: str) -> Path:
    path = Path(value).resolve()
    if path.suffix.casefold() != ".json":
        raise CurrentVersionError(f"{label} must use a .json filename")
    if not _is_within(path, workspace):
        raise CurrentVersionError(f"{label} must stay inside the workspace")
    for root in ((workspace / "ZDI").resolve(), (workspace / "ZDI_STAGING").resolve()):
        if _is_within(path, root):
            raise CurrentVersionError(f"{label} must stay outside package roots")
    return path


def _required_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CurrentVersionError(f"required field is missing: {field}")
    return value.strip()


def _validate_source_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as error:
        raise CurrentVersionError(f"official source URL is invalid: {error}") from error
    if parsed.scheme != "https" or not parsed.hostname:
        raise CurrentVersionError("official source URLs must use HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CurrentVersionError(
            "official source URLs cannot contain credentials, query, or fragment"
        )
    return value


def _require_public_host(hostname: str) -> None:
    try:
        records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise CurrentVersionError(
            f"official source host cannot be resolved: {error}"
        ) from error
    addresses = {record[4][0] for record in records}
    if not addresses:
        raise CurrentVersionError("official source host has no address records")
    for value in addresses:
        address = ipaddress.ip_address(value.split("%", 1)[0])
        if not address.is_global:
            raise CurrentVersionError(
                "official source host resolves to a non-public address"
            )


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise CurrentVersionError("official version sources cannot redirect")


def _default_fetch(url: str) -> bytes:
    parsed = urllib.parse.urlsplit(_validate_source_url(url))
    assert parsed.hostname is not None
    _require_public_host(parsed.hostname)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "JENNY-current-version-gate/1"},
    )
    try:
        opener = urllib.request.build_opener(_RejectRedirects())
        with opener.open(request, timeout=20) as response:
            data = response.read(MAX_SOURCE_BYTES + 1)
    except CurrentVersionError:
        raise
    except Exception as error:
        raise CurrentVersionError(f"cannot fetch official source: {error}") from error
    if len(data) > MAX_SOURCE_BYTES:
        raise CurrentVersionError("official source exceeds the 4 MiB capture limit")
    return data


def _json_field(payload: Any, field: str) -> str:
    current = payload
    for component in field.split("."):
        if not component or not isinstance(current, dict) or component not in current:
            raise CurrentVersionError(f"JSON version field was not found: {field}")
        current = current[component]
    if not isinstance(current, (str, int, float)) or isinstance(current, bool):
        raise CurrentVersionError("JSON version field is not a scalar")
    return str(current).strip()


def _regex_search_worker(
    pattern: str,
    text: str,
    sender: Any,
) -> None:
    try:
        match = re.search(pattern, text)
        sender.send(("MATCH", match.group("version") if match is not None else None))
    except Exception as error:
        sender.send(("ERROR", str(error)))
    finally:
        sender.close()


def _bounded_regex_search(pattern: str, text: str) -> str | None:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_regex_search_worker,
        args=(pattern, text, sender),
        daemon=True,
    )
    process.start()
    sender.close()
    process.join(REGEX_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(1)
        receiver.close()
        raise CurrentVersionError("official source regex timed out")
    if not receiver.poll():
        receiver.close()
        raise CurrentVersionError("official source regex worker failed")
    status, value = receiver.recv()
    receiver.close()
    if status == "ERROR":
        raise CurrentVersionError(f"official source regex failed: {value}")
    return value


def _resolve_version(source: dict[str, Any], body: bytes) -> str:
    kind = source.get("kind")
    if kind == "json_field":
        field = _required_text(source, "field")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CurrentVersionError(f"official JSON source is invalid: {error}") from error
        value = _json_field(payload, field)
    elif kind == "regex":
        pattern = _required_text(source, "pattern")
        try:
            compiled = re.compile(pattern)
        except re.error as error:
            raise CurrentVersionError(f"official source regex is invalid: {error}") from error
        if "version" not in compiled.groupindex:
            raise CurrentVersionError("official source regex requires a named version group")
        try:
            text = body.decode("utf-8")
        except UnicodeError as error:
            raise CurrentVersionError("official regex source is not UTF-8") from error
        matched_version = _bounded_regex_search(pattern, text)
        if matched_version is None:
            raise CurrentVersionError("official source regex did not resolve a version")
        value = matched_version.strip()
    else:
        raise CurrentVersionError("source kind must be json_field or regex")
    if not value or len(value) > 128 or any(character.isspace() for character in value):
        raise CurrentVersionError("resolved version is invalid")
    return value


def _registry_path(workspace: Path) -> Path:
    return workspace / "notes" / "current_version_gate" / "current_version_gate.sqlite3"


def _initialize_registry(database: Path) -> None:
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_path TEXT PRIMARY KEY,
                receipt_sha256 TEXT NOT NULL,
                target_slug TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                authority_version INTEGER NOT NULL DEFAULT 1,
                goal_path TEXT,
                goal_sha256 TEXT,
                source_host_count INTEGER
            )
            """
        )
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(receipts)")
        }
        migrations = {
            "authority_version": "INTEGER NOT NULL DEFAULT 1",
            "goal_path": "TEXT",
            "goal_sha256": "TEXT",
            "source_host_count": "INTEGER",
        }
        for column, declaration in migrations.items():
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE receipts ADD COLUMN {column} {declaration}"
                )


def _normalize_now(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        raise CurrentVersionError("current time must include a timezone")
    return value.astimezone(UTC)


def _active_goal_authority(
    workspace: Path,
    *,
    target_slug: str,
    product: str,
    version: str,
) -> tuple[Path, str, str]:
    lifecycle = workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
    if not lifecycle.is_file():
        raise CurrentVersionError("current-version capture requires one ACTIVE target")
    try:
        with closing(sqlite3.connect(lifecycle, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT slug, product, current_version, mirror_path, goal_sha256
                FROM targets WHERE status = 'ACTIVE'
                """
            ).fetchall()
    except sqlite3.Error as error:
        raise CurrentVersionError(
            f"cannot read active target authority: {error}"
        ) from error
    if len(rows) != 1:
        raise CurrentVersionError("current-version capture requires one ACTIVE target")
    row = rows[0]
    goal = Path(str(row["mirror_path"] or ""))
    if not goal.is_absolute():
        goal = workspace / goal
    goal = goal.resolve()
    if (
        str(row["slug"]) != target_slug
        or str(row["product"]) != product
        or str(row["current_version"] or "") != version
        or not goal.is_file()
    ):
        raise CurrentVersionError(
            "current-version identity does not match the ACTIVE target"
        )
    goal_sha256 = _sha256(goal)
    if goal_sha256 != str(row["goal_sha256"] or ""):
        raise CurrentVersionError("active GOAL authority hash changed")
    return goal, goal_sha256, goal.read_text(encoding="utf-8")


def _recorded_goal_authority(
    workspace: Path,
    *,
    target_slug: str,
    product: str,
    version: str,
) -> tuple[Path, str, str]:
    lifecycle = workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3"
    if not lifecycle.is_file():
        raise CurrentVersionError("current-version recorded target authority is unavailable")
    try:
        with closing(sqlite3.connect(lifecycle, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT slug, product, current_version, mirror_path, goal_sha256, status
                FROM targets WHERE slug = ?
                """,
                (target_slug,),
            ).fetchone()
    except sqlite3.Error as error:
        raise CurrentVersionError(
            f"cannot read recorded target authority: {error}"
        ) from error
    if row is None or str(row["status"]) not in {
        "ACTIVE",
        "PARKED_REHYDRATABLE",
    }:
        raise CurrentVersionError("current-version recorded target authority is unavailable")
    goal = Path(str(row["mirror_path"] or ""))
    if not goal.is_absolute():
        goal = workspace / goal
    goal = goal.resolve()
    if (
        str(row["product"]) != product
        or str(row["current_version"] or "") != version
        or not goal.is_file()
    ):
        raise CurrentVersionError("current-version identity does not match the recorded target")
    goal_sha256 = _sha256(goal)
    if goal_sha256 != str(row["goal_sha256"] or ""):
        raise CurrentVersionError("recorded GOAL authority hash changed")
    return goal, goal_sha256, goal.read_text(encoding="utf-8")


def _assert_claimed_final_rework_authority(
    workspace: Path,
    item_id: int,
    *,
    target_slug: str,
    product: str,
    version: str,
) -> None:
    if not isinstance(item_id, int) or item_id <= 0:
        raise CurrentVersionError("final rework item must be a positive integer")
    database = workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3"
    if not database.is_file():
        raise CurrentVersionError("claimed final rework authority is unavailable")
    try:
        with closing(sqlite3.connect(database, timeout=5)) as connection:
            row = connection.execute(
                """
                SELECT
                    wi.state,
                    wi.candidate_challenge_id,
                    wi.package_path,
                    cc.target_slug,
                    cc.product,
                    cc.version,
                    cc.package_number,
                    frr.review_scope,
                    frr.prior_candidate_challenge_id
                FROM work_items AS wi
                JOIN candidate_challenges AS cc ON cc.id = wi.candidate_challenge_id
                JOIN final_rework_requests AS frr
                  ON frr.work_item_id = wi.id AND frr.state = 'CLAIMED'
                WHERE wi.id = ?
                ORDER BY frr.id DESC
                LIMIT 1
                """,
                (item_id,),
            ).fetchone()
    except sqlite3.Error as error:
        raise CurrentVersionError(
            f"cannot read claimed final rework authority: {error}"
        ) from error
    if (
        row is None
        or row[0] != "FINAL_REWORK"
        or row[3] != target_slug
        or row[4] != product
        or row[5] != version
        or row[6] is None
        or row[7] not in {"EVIDENCE_ONLY", "SEMANTIC"}
        or row[8] != row[1]
    ):
        raise CurrentVersionError(
            "capture requires a claimed matching Final Rework item with reviewed lineage"
        )
    package_match = re.match(r"^(\d+)_", Path(str(row[2])).name)
    if package_match is None or int(package_match.group(1)) != int(row[6]):
        raise CurrentVersionError(
            "capture requires a claimed Final Rework item with matching package identity"
        )


def _refresh_claimed_final_rework_goal(
    workspace: Path,
    item_id: int,
    *,
    target_slug: str,
    product: str,
    version: str,
) -> dict[str, Any]:
    module_path = Path(__file__).resolve().parents[1] / "target_lifecycle" / "target_lifecycle.py"
    spec = importlib.util.spec_from_file_location(
        "jenny_target_lifecycle_final_rework", module_path
    )
    if spec is None or spec.loader is None:
        raise CurrentVersionError("target lifecycle Final Rework gate is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module.refresh_final_rework_goal(
            workspace / "notes" / "target_lifecycle" / "target_lifecycle.sqlite3",
            workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
            item_id,
            target_slug=target_slug,
            product=product,
            version=version,
            workspace=workspace,
        )
    except (OSError, ValueError, sqlite3.Error) as error:
        raise CurrentVersionError(
            f"claimed Final Rework GOAL refresh failed: {error}"
        ) from error


def capture_receipt(
    workspace: str | Path,
    manifest_path: str | Path,
    receipt_path: str | Path,
    *,
    fetcher: Callable[[str], bytes] | None = None,
    now: datetime | None = None,
    allow_recorded_target_authority: bool = False,
    final_rework_item_id: int | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    manifest = _private_json_path(workspace_path, manifest_path, "source manifest")
    receipt = _private_json_path(workspace_path, receipt_path, "current-version receipt")
    if not manifest.is_file():
        raise CurrentVersionError("source manifest does not exist")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CurrentVersionError(f"cannot read source manifest: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != SOURCE_SCHEMA:
        raise CurrentVersionError("source manifest schema is invalid")
    target_slug = _required_text(payload, "target_slug")
    product = _required_text(payload, "product")
    version = _required_text(payload, "claimed_version")
    if final_rework_item_id is not None:
        _assert_claimed_final_rework_authority(
            workspace_path,
            final_rework_item_id,
            target_slug=target_slug,
            product=product,
            version=version,
        )
        allow_recorded_target_authority = True
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", target_slug) is None:
        raise CurrentVersionError("target_slug format is invalid")
    target_root = (workspace_path / "targets" / target_slug).resolve()
    if not _is_within(manifest, target_root) or not _is_within(receipt, target_root):
        raise CurrentVersionError("manifest and receipt must stay under the target root")
    if final_rework_item_id is not None:
        _refresh_claimed_final_rework_goal(
            workspace_path,
            final_rework_item_id,
            target_slug=target_slug,
            product=product,
            version=version,
        )
    authority = _recorded_goal_authority if allow_recorded_target_authority else _active_goal_authority
    goal, goal_sha256, goal_text = authority(
        workspace_path, target_slug=target_slug, product=product, version=version
    )
    artifact = Path(_required_text(payload, "artifact_path")).resolve()
    if not artifact.is_file() or not _is_within(artifact, target_root):
        raise CurrentVersionError("artifact must be a file under the target root")
    sources = payload.get("sources")
    if not isinstance(sources, list) or not 2 <= len(sources) <= 4:
        raise CurrentVersionError("two to four official source resolvers are required")
    urls: set[str] = set()
    fetch = fetcher or _default_fetch
    resolved_sources: list[dict[str, str]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise CurrentVersionError("official source entry is invalid")
        url = _validate_source_url(_required_text(source, "url"))
        if url not in goal_text:
            raise CurrentVersionError(
                "official source URL is not authorized by the active GOAL"
            )
        if url in urls:
            raise CurrentVersionError("official source URLs must be distinct")
        urls.add(url)
        body = fetch(url)
        if not isinstance(body, bytes):
            raise CurrentVersionError("official source fetcher did not return bytes")
        if len(body) > MAX_SOURCE_BYTES:
            raise CurrentVersionError("official source exceeds the 4 MiB capture limit")
        resolved = _resolve_version(source, body)
        if resolved != version:
            raise CurrentVersionError(
                f"official source version {resolved!r} does not match claimed version {version!r}"
            )
        resolved_sources.append(
            {
                "kind": str(source["kind"]),
                "url": url,
                "resolved_version": resolved,
                "response_sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    hostnames = {
        str(urllib.parse.urlsplit(source["url"]).hostname).casefold()
        for source in resolved_sources
    }
    if len(hostnames) < 2:
        raise CurrentVersionError(
            "official source quorum requires two independent hostnames"
        )
    timestamp = _normalize_now(now).isoformat(timespec="seconds")
    result = {
        "schema": RECEIPT_SCHEMA,
        "target_slug": target_slug,
        "product": product,
        "claimed_version": version,
        "captured_at": timestamp,
        "manifest_path": str(manifest),
        "manifest_sha256": _sha256(manifest),
        "goal_path": str(goal),
        "goal_sha256": goal_sha256,
        "artifact": {
            "path": str(artifact),
            "size": artifact.stat().st_size,
            "sha256": _sha256(artifact),
        },
        "sources": resolved_sources,
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt.with_suffix(receipt.suffix + ".tmp")
    temporary.write_text(
        json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(receipt)
    receipt_hash = _sha256(receipt)
    database = _registry_path(workspace_path)
    _initialize_registry(database)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            """
            INSERT INTO receipts(
                receipt_path, receipt_sha256, target_slug, product, version,
                artifact_sha256, captured_at, registered_at, authority_version,
                goal_path, goal_sha256, source_host_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_path) DO UPDATE SET
                receipt_sha256 = excluded.receipt_sha256,
                target_slug = excluded.target_slug,
                product = excluded.product,
                version = excluded.version,
                artifact_sha256 = excluded.artifact_sha256,
                captured_at = excluded.captured_at,
                registered_at = excluded.registered_at,
                authority_version = excluded.authority_version,
                goal_path = excluded.goal_path,
                goal_sha256 = excluded.goal_sha256,
                source_host_count = excluded.source_host_count
            """,
            (
                str(receipt),
                receipt_hash,
                target_slug,
                product,
                version,
                result["artifact"]["sha256"],
                timestamp,
                timestamp,
                AUTHORITY_VERSION,
                str(goal),
                goal_sha256,
                len(hostnames),
            ),
        )
    return result


def validate_receipt(
    workspace: str | Path,
    receipt_path: str | Path,
    *,
    target_slug: str,
    product: str,
    version: str,
    expected_sha256: str | None = None,
    allow_registered_legacy_authority: bool = False,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
    now: datetime | None = None,
    allow_recorded_target_authority: bool = False,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    receipt = _private_json_path(workspace_path, receipt_path, "current-version receipt")
    if not receipt.is_file():
        raise CurrentVersionError("current-version receipt does not exist")
    receipt_hash = _sha256(receipt)
    if expected_sha256 is not None and receipt_hash != expected_sha256:
        raise CurrentVersionError("current-version receipt hash changed")
    database = _registry_path(workspace_path)
    if not database.is_file():
        raise CurrentVersionError("current-version receipt is not registered")
    _initialize_registry(database)
    try:
        with closing(sqlite3.connect(database, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM receipts WHERE receipt_path = ?", (str(receipt),)
            ).fetchone()
    except sqlite3.Error as error:
        raise CurrentVersionError(f"cannot read current-version registry: {error}") from error
    if row is None:
        raise CurrentVersionError("current-version receipt is not registered")
    if (
        row["receipt_sha256"] != receipt_hash
        or row["target_slug"] != target_slug
        or row["product"] != product
        or row["version"] != version
    ):
        raise CurrentVersionError("current-version registry binding is stale")
    try:
        payload = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CurrentVersionError(f"cannot read current-version receipt: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != RECEIPT_SCHEMA:
        raise CurrentVersionError("current-version receipt schema is invalid")
    if (
        payload.get("target_slug") != target_slug
        or payload.get("product") != product
        or payload.get("claimed_version") != version
    ):
        raise CurrentVersionError("current-version receipt identity is stale")
    manifest = Path(str(payload.get("manifest_path", ""))).resolve()
    target_root = (workspace_path / "targets" / target_slug).resolve()
    if not manifest.is_file() or not _is_within(manifest, target_root):
        raise CurrentVersionError("current-version source manifest is unavailable")
    if _sha256(manifest) != payload.get("manifest_sha256"):
        raise CurrentVersionError("current-version source manifest hash changed")
    authority_version = int(row["authority_version"] or 1)
    if authority_version < AUTHORITY_VERSION and not allow_registered_legacy_authority:
        raise CurrentVersionError(
            "legacy current-version receipt cannot authorize a new candidate"
        )
    goal_text = ""
    if authority_version >= AUTHORITY_VERSION:
        authority = _recorded_goal_authority if allow_recorded_target_authority else _active_goal_authority
        goal, goal_sha256, goal_text = authority(
            workspace_path, target_slug=target_slug, product=product, version=version
        )
        if (
            str(payload.get("goal_path", "")) != str(goal)
            or payload.get("goal_sha256") != goal_sha256
            or row["goal_path"] != str(goal)
            or row["goal_sha256"] != goal_sha256
        ):
            raise CurrentVersionError("current-version GOAL authority is stale")
    sources = payload.get("sources")
    if not isinstance(sources, list) or len(sources) < 2 or any(
        not isinstance(source, dict)
        or source.get("resolved_version") != version
        or not HASH_RE.fullmatch(str(source.get("response_sha256", "")))
        for source in sources
    ):
        raise CurrentVersionError("current-version source bindings are invalid")
    source_hosts = {
        str(urllib.parse.urlsplit(str(source["url"])).hostname).casefold()
        for source in sources
    }
    if authority_version >= AUTHORITY_VERSION:
        if any(str(source.get("url", "")) not in goal_text for source in sources):
            raise CurrentVersionError(
                "current-version source is no longer authorized by the active GOAL"
            )
        if len(source_hosts) < 2 or row["source_host_count"] != len(source_hosts):
            raise CurrentVersionError(
                "current-version source quorum lacks independent hostnames"
            )
    try:
        captured_at = datetime.fromisoformat(str(payload["captured_at"]))
    except (KeyError, TypeError, ValueError) as error:
        raise CurrentVersionError("current-version receipt timestamp is invalid") from error
    if captured_at.tzinfo is None:
        raise CurrentVersionError("current-version receipt timestamp lacks a timezone")
    current = _normalize_now(now)
    age = current - captured_at.astimezone(UTC)
    if age < timedelta(minutes=-5):
        raise CurrentVersionError("current-version receipt timestamp is in the future")
    if age > timedelta(hours=max_age_hours):
        raise CurrentVersionError(
            f"current-version receipt is older than {max_age_hours} hours"
        )
    artifact_record = payload.get("artifact")
    if not isinstance(artifact_record, dict):
        raise CurrentVersionError("current-version artifact binding is missing")
    artifact = Path(str(artifact_record.get("path", ""))).resolve()
    if not artifact.is_file() or not _is_within(artifact, target_root):
        raise CurrentVersionError("current-version artifact is unavailable")
    if (
        artifact.stat().st_size != artifact_record.get("size")
        or _sha256(artifact) != artifact_record.get("sha256")
        or row["artifact_sha256"] != artifact_record.get("sha256")
    ):
        raise CurrentVersionError("current-version artifact hash changed")
    result = dict(payload)
    result["receipt_path"] = str(receipt)
    result["receipt_sha256"] = receipt_hash
    result["authority_version"] = authority_version
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture and verify current-version receipts")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--manifest", type=Path, required=True)
    capture.add_argument("--receipt", type=Path, required=True)
    capture.add_argument(
        "--final-rework-item",
        type=int,
        help="allow recorded-target authority only for this claimed FINAL_REWORK item",
    )
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--target", required=True)
    verify.add_argument("--product", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--sha256")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "capture":
            result = capture_receipt(
                args.workspace,
                args.manifest,
                args.receipt,
                final_rework_item_id=args.final_rework_item,
            )
        else:
            result = validate_receipt(
                args.workspace,
                args.receipt,
                target_slug=args.target,
                product=args.product,
                version=args.version,
                expected_sha256=args.sha256,
            )
    except CurrentVersionError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "PASS", "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
