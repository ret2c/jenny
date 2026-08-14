from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable


SOURCE_SCHEMA = "jenny.public-prior-art-source.v2"
RECEIPT_SCHEMA = "jenny.public-prior-art-receipt.v2"
LEGACY_SOURCE_SCHEMA = "jenny.public-prior-art-source.v1"
LEGACY_RECEIPT_SCHEMA = "jenny.public-prior-art-receipt.v1"
DEFAULT_MAX_AGE_HOURS = 16
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REF_ROLES = ("stable", "maintenance", "release_candidate", "main")
REGISTRY_RELATIVE_PATH = Path(
    "notes/review_mailbox/public_prior_art_receipts.sqlite3"
)


class PublicPriorArtError(RuntimeError):
    pass


def _registry_path(workspace: Path) -> Path:
    return (workspace / REGISTRY_RELATIVE_PATH).resolve()


def _initialize_registry(workspace: Path) -> sqlite3.Connection:
    path = _registry_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS receipts (
            receipt_path TEXT PRIMARY KEY,
            receipt_sha256 TEXT NOT NULL,
            target_slug TEXT NOT NULL,
            product TEXT NOT NULL,
            root_family_id TEXT NOT NULL,
            repository TEXT NOT NULL,
            goal_sha256 TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            registered_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def _register_receipt(
    workspace: Path, receipt: Path, payload: dict[str, object]
) -> None:
    receipt_hash = _sha256(receipt)
    with _initialize_registry(workspace) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO receipts (
                receipt_path,
                receipt_sha256,
                target_slug,
                product,
                root_family_id,
                repository,
                goal_sha256,
                captured_at,
                registered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(receipt),
                receipt_hash,
                payload["target_slug"],
                payload["product"],
                payload["root_family_id"],
                payload["repository"],
                payload["goal_sha256"],
                payload["generated_at"],
                datetime.now(UTC).isoformat(timespec="seconds"),
            ),
        )
        connection.commit()


def _validate_registration(
    workspace: Path,
    receipt: Path,
    receipt_hash: str,
    payload: dict[str, Any],
) -> None:
    path = _registry_path(workspace)
    if not path.is_file():
        raise PublicPriorArtError(
            "public-prior-art receipt was not registered by the capture tool"
        )
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT
                receipt_sha256,
                target_slug,
                product,
                root_family_id,
                repository,
                goal_sha256,
                captured_at
            FROM receipts
            WHERE receipt_path = ?
            """,
            (str(receipt),),
        ).fetchone()
    expected = (
        receipt_hash,
        payload.get("target_slug"),
        payload.get("product"),
        payload.get("root_family_id"),
        payload.get("repository"),
        payload.get("goal_sha256"),
        payload.get("generated_at"),
    )
    if row is None:
        raise PublicPriorArtError(
            "public-prior-art receipt was not registered by the capture tool"
        )
    if row != expected:
        raise PublicPriorArtError(
            "public-prior-art receipt does not match the capture registry"
        )


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
    if path.suffix.casefold() != ".json" or not _is_within(path, workspace):
        raise PublicPriorArtError(f"{label} must be a workspace-private JSON file")
    for root in ((workspace / "ZDI").resolve(), (workspace / "ZDI_STAGING").resolve()):
        if _is_within(path, root):
            raise PublicPriorArtError(f"{label} must stay outside package roots")
    return path


def _repository_identity(url: str) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as error:
        raise PublicPriorArtError(
            "repository must be an exact https://github.com/<owner>/<repo> URL"
        ) from error
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
    ):
        raise PublicPriorArtError(
            "repository must be an exact https://github.com/<owner>/<repo> URL"
        )
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not owner or not repository:
        raise PublicPriorArtError("repository identity is invalid")
    canonical_url = f"https://github.com/{owner}/{repository}"
    return f"{owner}/{repository}", canonical_url


def _canonical_product(workspace: Path, product: str) -> tuple[str, list[str]]:
    from package_preflight import _canonical_product_identity, _load_product_aliases

    return _canonical_product_identity(product, _load_product_aliases(workspace))


def _validate_git_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"refs/[A-Za-z0-9._/-]+", value
    ):
        raise PublicPriorArtError(f"{label} must be an exact full refs/... name")
    if (
        ".." in value
        or "//" in value
        or value.endswith(("/", ".", ".lock"))
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise PublicPriorArtError(f"{label} must be an exact full refs/... name")
    return value


def _required_refs(source: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    value = source.get("required_refs")
    if not isinstance(value, dict) or set(value) != set(REF_ROLES):
        raise PublicPriorArtError(
            "required_refs must name stable, maintenance, release_candidate, and main"
        )
    normalized: dict[str, list[dict[str, str]]] = {}
    remote_seen: set[str] = set()
    local_seen: set[str] = set()
    for role in REF_ROLES:
        rows = value[role]
        if not isinstance(rows, list) or len(rows) > 8:
            raise PublicPriorArtError(f"required_refs.{role} must be a bounded list")
        normalized[role] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"remote_ref", "local_ref"}:
                raise PublicPriorArtError(
                    f"required_refs.{role} entries require remote_ref and local_ref"
                )
            remote_ref = _validate_git_ref(row["remote_ref"], "remote_ref")
            local_ref = _validate_git_ref(row["local_ref"], "local_ref")
            if remote_ref in remote_seen or local_ref in local_seen:
                raise PublicPriorArtError("required_refs contains a duplicate ref")
            remote_seen.add(remote_ref)
            local_seen.add(local_ref)
            normalized[role].append(
                {"remote_ref": remote_ref, "local_ref": local_ref}
            )
    if not normalized["stable"] or not normalized["main"]:
        raise PublicPriorArtError(
            "required_refs must include at least one stable and one main ref"
        )
    return normalized


def _checkout_path(workspace: Path, value: object) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise PublicPriorArtError("checkout_path is required")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise PublicPriorArtError("checkout_path must be workspace-relative")
    checkout = (workspace / relative).resolve()
    if not _is_within(checkout, workspace) or any(
        _is_within(checkout, root)
        for root in ((workspace / "ZDI").resolve(), (workspace / "ZDI_STAGING").resolve())
    ):
        raise PublicPriorArtError("checkout_path must stay in the private workspace")
    if not checkout.is_dir():
        raise PublicPriorArtError("checkout_path does not exist")
    return checkout


def _default_remote_ref_reader(
    repository_url: str, refs: list[str]
) -> dict[str, str]:
    executable = shutil.which("git")
    if executable is None:
        raise PublicPriorArtError("Git is required for source-ref currentness checks")
    try:
        result = subprocess.run(
            [
                executable,
                "ls-remote",
                "--refs",
                "--exit-code",
                repository_url,
                *refs,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=60,
        )
    except subprocess.SubprocessError as error:
        raise PublicPriorArtError(f"git ls-remote failed: {error}") from error
    if result.returncode != 0:
        raise PublicPriorArtError(
            f"git ls-remote could not resolve every requested ref (exit {result.returncode})"
        )
    requested = set(refs)
    resolved: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2 or parts[1] not in requested or not GIT_OID_RE.fullmatch(parts[0]):
            continue
        resolved[parts[1]] = parts[0]
    if set(resolved) != requested:
        missing = sorted(requested - set(resolved))
        raise PublicPriorArtError(
            "git ls-remote omitted requested ref(s): " + ", ".join(missing)
        )
    return resolved


def _default_local_ref_reader(checkout: Path, refs: list[str]) -> dict[str, str]:
    executable = shutil.which("git")
    if executable is None:
        raise PublicPriorArtError("Git is required for source-ref currentness checks")
    resolved: dict[str, str] = {}
    for ref in refs:
        try:
            result = subprocess.run(
                [
                    executable,
                    "-C",
                    str(checkout),
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    ref,
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=20,
            )
        except subprocess.SubprocessError as error:
            raise PublicPriorArtError(f"git rev-parse failed: {error}") from error
        oid = result.stdout.strip()
        if result.returncode != 0 or not GIT_OID_RE.fullmatch(oid):
            raise PublicPriorArtError(f"local checkout is missing requested ref: {ref}")
        resolved[ref] = oid
    return resolved


def _capture_source_currentness(
    workspace: Path,
    source: dict[str, Any],
    repository_url: str,
    remote_ref_reader: Callable[[str, list[str]], dict[str, str]],
    local_ref_reader: Callable[[Path, list[str]], dict[str, str]],
) -> dict[str, object]:
    checkout = _checkout_path(workspace, source.get("checkout_path"))
    requested = _required_refs(source)
    remote_names = [
        row["remote_ref"] for role in REF_ROLES for row in requested[role]
    ]
    local_names = [
        row["local_ref"] for role in REF_ROLES for row in requested[role]
    ]
    advertised = remote_ref_reader(repository_url, remote_names)
    local = local_ref_reader(checkout, local_names)
    if set(advertised) != set(remote_names) or any(
        not GIT_OID_RE.fullmatch(value) for value in advertised.values()
    ):
        raise PublicPriorArtError("remote ref reader returned an incomplete result")
    if set(local) != set(local_names) or any(
        not GIT_OID_RE.fullmatch(value) for value in local.values()
    ):
        raise PublicPriorArtError("local ref reader returned an incomplete result")
    rows: list[dict[str, object]] = []
    mismatches: list[str] = []
    for role in REF_ROLES:
        for ref in requested[role]:
            remote_oid = advertised[ref["remote_ref"]]
            local_oid = local[ref["local_ref"]]
            matches = remote_oid == local_oid
            rows.append(
                {
                    "role": role,
                    "remote_ref": ref["remote_ref"],
                    "local_ref": ref["local_ref"],
                    "advertised_oid": remote_oid,
                    "local_oid": local_oid,
                    "matches": matches,
                }
            )
            if not matches:
                mismatches.append(f"{ref['local_ref']} != {ref['remote_ref']}")
    if mismatches:
        raise PublicPriorArtError(
            "local ref does not match advertised remote ref: " + ", ".join(mismatches)
        )
    return {
        "status": "MATCH",
        "checkout_path": str(checkout),
        "required_refs": requested,
        "refs": rows,
    }


def _default_search(repository: str, kind: str, token: str) -> dict[str, object]:
    executable = shutil.which("gh")
    if executable is None:
        raise PublicPriorArtError(
            "GitHub CLI is required for machine-verified issue and pull-request searches"
        )
    query = f'repo:{repository} is:{kind} "{token}" in:title,body'
    rows: list[dict[str, object]] = []
    total_count: int | None = None
    incomplete = False
    page_count = 0
    for page in range(1, 11):
        argv = [
            executable,
            "api",
            "--method",
            "GET",
            "search/issues",
            "-f",
            f"q={query}",
            "-f",
            "per_page=100",
            "-f",
            f"page={page}",
        ]
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=45,
            )
        except subprocess.SubprocessError as error:
            raise PublicPriorArtError(f"GitHub {kind} search failed: {error}") from error
        if result.returncode != 0:
            raise PublicPriorArtError(
                f"GitHub {kind} search failed with exit {result.returncode}"
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise PublicPriorArtError(
                f"GitHub {kind} search returned invalid JSON"
            ) from error
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise PublicPriorArtError(f"GitHub {kind} search result is invalid")
        if total_count is None:
            value = payload.get("total_count")
            if not isinstance(value, int) or value < 0:
                raise PublicPriorArtError(f"GitHub {kind} search result is invalid")
            total_count = value
        incomplete = incomplete or payload.get("incomplete_results") is True
        items = [item for item in payload["items"] if isinstance(item, dict)]
        rows.extend(
            {
                "number": row.get("number"),
                "title": row.get("title"),
                "url": row.get("html_url"),
                "state": row.get("state"),
                "updated_at": row.get("updated_at"),
            }
            for row in items
        )
        page_count += 1
        if len(items) < 100 or len(rows) >= total_count:
            break
    assert total_count is not None
    truncated = incomplete or len(rows) < total_count
    return {
        "complete": not truncated,
        "items": rows,
        "page_count": page_count,
        "result_count": len(rows),
        "total_count": total_count,
        "truncated": truncated,
    }


def _normalize_search_result(result: object, kind: str) -> dict[str, object]:
    if isinstance(result, list):
        items = [row for row in result if isinstance(row, dict)]
        if len(items) != len(result):
            raise PublicPriorArtError(f"GitHub {kind} search result is invalid")
        return {
            "complete": True,
            "items": items,
            "page_count": 1,
            "result_count": len(items),
            "total_count": len(items),
            "truncated": False,
        }
    if not isinstance(result, dict) or not isinstance(result.get("items"), list):
        raise PublicPriorArtError(f"GitHub {kind} search result is invalid")
    normalized = dict(result)
    normalized.setdefault("result_count", len(normalized["items"]))
    return normalized


def _load_manifest(
    workspace: Path, manifest_path: str | Path
) -> tuple[Path, dict[str, Any]]:
    path = _private_json_path(workspace, manifest_path, "prior-art manifest")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PublicPriorArtError(f"cannot read prior-art manifest: {error}") from error
    if isinstance(payload, dict) and payload.get("schema") == LEGACY_SOURCE_SCHEMA:
        raise PublicPriorArtError(
            "migrate the prior-art manifest to v2 with checkout_path and the "
            "stable, maintenance, release_candidate, and main required_refs matrix"
        )
    if not isinstance(payload, dict) or payload.get("schema") != SOURCE_SCHEMA:
        raise PublicPriorArtError("prior-art manifest schema is invalid")
    for field in ("target_slug", "product", "repository", "root_family_id"):
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            raise PublicPriorArtError(f"prior-art manifest field is required: {field}")
    tokens = payload.get("root_tokens")
    if (
        not isinstance(tokens, list)
        or not 1 <= len(tokens) <= 6
        or len(set(tokens)) != len(tokens)
        or any(not isinstance(token, str) or not TOKEN_RE.fullmatch(token) for token in tokens)
    ):
        raise PublicPriorArtError("root_tokens must contain 1-6 distinct exact tokens")
    _checkout_path(workspace, payload.get("checkout_path"))
    _required_refs(payload)
    return path, payload


def _validate_searches(payload: dict[str, Any]) -> None:
    tokens = payload.get("root_tokens")
    searches = payload.get("searches")
    if not isinstance(tokens, list) or not isinstance(searches, list):
        raise PublicPriorArtError("prior-art receipt searches are invalid")
    expected = {(token, kind) for token in tokens for kind in ("issue", "pr")}
    actual: set[tuple[str, str]] = set()
    for row in searches:
        if not isinstance(row, dict):
            raise PublicPriorArtError("prior-art receipt search row is invalid")
        token = row.get("token")
        kind = row.get("kind")
        results = row.get("results")
        if (
            not isinstance(token, str)
            or kind not in {"issue", "pr"}
            or not isinstance(results, list)
        ):
            raise PublicPriorArtError("prior-art receipt search row is invalid")
        complete = row.get("complete")
        truncated = row.get("truncated")
        result_count = row.get("result_count")
        total_count = row.get("total_count")
        page_count = row.get("page_count")
        if (
            complete is not True
            or truncated is not False
            or not isinstance(result_count, int)
            or result_count != len(results)
            or not isinstance(total_count, int)
            or total_count != result_count
            or not isinstance(page_count, int)
            or page_count < 1
        ):
            raise PublicPriorArtError(
                "prior-art receipt search is incomplete or truncated"
            )
        actual.add((token, kind))
    if actual != expected or len(searches) != len(expected):
        raise PublicPriorArtError(
            "prior-art receipt requires one issue and pull-request search per root token"
        )


def _validate_source_currentness(payload: dict[str, Any]) -> None:
    value = payload.get("source_currentness")
    if not isinstance(value, dict) or value.get("status") != "MATCH":
        raise PublicPriorArtError("source-ref currentness receipt is missing or invalid")
    checkout_path = value.get("checkout_path")
    if not isinstance(checkout_path, str) or not checkout_path:
        raise PublicPriorArtError("source-ref currentness checkout is invalid")
    requested = _required_refs(value)
    rows = value.get("refs")
    if not isinstance(rows, list):
        raise PublicPriorArtError("source-ref currentness rows are invalid")
    expected = {
        (role, ref["remote_ref"], ref["local_ref"])
        for role in REF_ROLES
        for ref in requested[role]
    }
    actual: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise PublicPriorArtError("source-ref currentness row is invalid")
        role = row.get("role")
        remote_ref = row.get("remote_ref")
        local_ref = row.get("local_ref")
        advertised_oid = row.get("advertised_oid")
        local_oid = row.get("local_oid")
        if (
            role not in REF_ROLES
            or not isinstance(remote_ref, str)
            or not isinstance(local_ref, str)
            or not isinstance(advertised_oid, str)
            or not isinstance(local_oid, str)
            or not GIT_OID_RE.fullmatch(advertised_oid)
            or not GIT_OID_RE.fullmatch(local_oid)
            or row.get("matches") is not True
            or advertised_oid != local_oid
        ):
            raise PublicPriorArtError("source-ref currentness row is invalid")
        actual.add((role, remote_ref, local_ref))
    if actual != expected or len(rows) != len(expected):
        raise PublicPriorArtError("source-ref currentness rows are incomplete")


def capture_receipt(
    workspace: str | Path,
    manifest_path: str | Path,
    receipt_path: str | Path,
    *,
    searcher: Callable[[str, str, str], object] = _default_search,
    remote_ref_reader: Callable[[str, list[str]], dict[str, str]] = _default_remote_ref_reader,
    local_ref_reader: Callable[[Path, list[str]], dict[str, str]] = _default_local_ref_reader,
) -> dict[str, object]:
    workspace_path = Path(workspace).resolve()
    manifest, source = _load_manifest(workspace_path, manifest_path)
    receipt = _private_json_path(workspace_path, receipt_path, "prior-art receipt")
    target_slug = str(source["target_slug"])
    goal = (workspace_path / "targets" / target_slug / "GOAL.md").resolve()
    if not goal.is_file():
        raise PublicPriorArtError("prior-art capture requires the current target GOAL.md")
    repository, repository_url = _repository_identity(str(source["repository"]))
    goal_text = goal.read_text(encoding="utf-8", errors="replace").casefold()
    api_repository_prefix = (
        f"https://api.github.com/repos/{repository}/".casefold()
    )
    if (
        repository_url.casefold() not in goal_text
        and api_repository_prefix not in goal_text
    ):
        raise PublicPriorArtError("repository is not explicitly authorized by GOAL.md")
    source_currentness = _capture_source_currentness(
        workspace_path,
        source,
        repository_url,
        remote_ref_reader,
        local_ref_reader,
    )
    product, aliases = _canonical_product(workspace_path, str(source["product"]))
    searches: list[dict[str, object]] = []
    for token in source["root_tokens"]:
        for kind in ("issue", "pr"):
            result = _normalize_search_result(
                searcher(repository, kind, token), kind
            )
            if result.get("complete") is not True or result.get("truncated") is not False:
                raise PublicPriorArtError(
                    f"GitHub {kind} search is incomplete or truncated"
                )
            searches.append(
                {
                    "token": token,
                    "kind": kind,
                    "complete": True,
                    "truncated": False,
                    "page_count": result.get("page_count"),
                    "result_count": result.get("result_count"),
                    "total_count": result.get("total_count"),
                    "results": result["items"],
                }
            )
    payload: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "status": "COMPLETE",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "target_slug": target_slug,
        "product": product,
        "aliases": aliases,
        "repository": repository,
        "repository_url": repository_url,
        "root_family_id": str(source["root_family_id"]),
        "root_tokens": list(source["root_tokens"]),
        "goal_path": str(goal),
        "goal_sha256": _sha256(goal),
        "manifest_path": str(manifest),
        "manifest_sha256": _sha256(manifest),
        "source_currentness": source_currentness,
        "searches": searches,
    }
    _validate_searches(payload)
    _validate_source_currentness(payload)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt.with_suffix(receipt.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(receipt)
    _register_receipt(workspace_path, receipt, payload)
    return payload


def validate_receipt(
    workspace: str | Path,
    receipt_path: str | Path,
    *,
    target_slug: str,
    product: str,
    root_family_id: str,
    expected_sha256: str,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    receipt = _private_json_path(workspace_path, receipt_path, "public-prior-art receipt")
    if not receipt.is_file():
        raise PublicPriorArtError("public-prior-art receipt does not exist")
    if not HASH_RE.fullmatch(expected_sha256) or _sha256(receipt) != expected_sha256:
        raise PublicPriorArtError("public-prior-art receipt hash does not match")
    try:
        payload = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PublicPriorArtError(f"cannot read public-prior-art receipt: {error}") from error
    if isinstance(payload, dict) and payload.get("schema") == LEGACY_RECEIPT_SCHEMA:
        raise PublicPriorArtError(
            "legacy prior-art receipt must be recaptured from a v2 manifest"
        )
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != RECEIPT_SCHEMA
        or payload.get("status") != "COMPLETE"
    ):
        raise PublicPriorArtError("public-prior-art receipt is invalid")
    canonical_product, _aliases = _canonical_product(workspace_path, product)
    if (
        payload.get("target_slug") != target_slug
        or payload.get("product") != canonical_product
        or payload.get("root_family_id") != root_family_id
    ):
        raise PublicPriorArtError("public-prior-art receipt identity does not match candidate")
    goal = (workspace_path / "targets" / target_slug / "GOAL.md").resolve()
    if payload.get("goal_path") != str(goal) or payload.get("goal_sha256") != _sha256(goal):
        raise PublicPriorArtError("public-prior-art receipt does not match current goal")
    _validate_searches(payload)
    _validate_source_currentness(payload)
    _validate_registration(workspace_path, receipt, expected_sha256, payload)
    try:
        generated = datetime.fromisoformat(str(payload["generated_at"]))
    except (KeyError, TypeError, ValueError) as error:
        raise PublicPriorArtError("public-prior-art receipt time is invalid") from error
    if generated.tzinfo is None or datetime.now(UTC) - generated.astimezone(UTC) > timedelta(
        hours=max_age_hours
    ):
        raise PublicPriorArtError("public-prior-art receipt is stale")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture machine-verified GitHub issue and pull-request searches"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--workspace", type=Path, default=Path.cwd())
    capture.add_argument("--manifest", type=Path, required=True)
    capture.add_argument("--receipt", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        payload = capture_receipt(args.workspace, args.manifest, args.receipt)
    except (OSError, PublicPriorArtError) as error:
        print(json.dumps({"error": str(error)}))
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
