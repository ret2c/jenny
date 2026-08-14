from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable


PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/)[^\s\"']+")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

CATEGORY_RULES = (
    ("MECHANICAL", ("mechanical", "format", "zip", "hash", "portal", "pyc")),
    (
        "EVIDENCE_PROVENANCE",
        ("raw_evidence", "provenance", "raw evidence", "independently reviewable"),
    ),
    (
        "CURRENTNESS_ENVIRONMENT",
        ("currentness", "version", "build", "environment", "identity"),
    ),
    (
        "SUPPORTED_BOUNDARY",
        ("boundary", "supported", "attacker_position", "attacker position", "design"),
    ),
    ("IMPACT_CVSS", ("impact", "cvss", "severity", "claim strength")),
    (
        "ROOT_DUPLICATE",
        ("root", "duplicate", "sibling", "prior_art", "prior art", "lineage"),
    ),
    (
        "REPLAY_DETERMINISM",
        ("replay", "determin", "negative control", "cleanup", "restoration"),
    ),
)


class WorkflowEvalError(RuntimeError):
    pass


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def _sanitize(value: str) -> str:
    return HASH_RE.sub("<HASH>", PATH_RE.sub("<PATH>", value)).strip()


def _categories(issue_id: str, action: str) -> list[str]:
    folded = f"{issue_id} {action}".casefold()
    matched = [
        category
        for category, terms in CATEGORY_RULES
        if any(term in folded for term in terms)
    ]
    return matched or ["OTHER"]


def export_rework_corpus(
    *, db_path: str | Path, output_path: str | Path
) -> dict[str, Any]:
    database = Path(db_path).resolve()
    output = Path(output_path).resolve()
    if not database.is_file():
        raise WorkflowEvalError(f"mailbox database does not exist: {database}")
    records: list[dict[str, Any]] = []
    with closing(sqlite3.connect(database, timeout=10)) as connection:
        connection.row_factory = sqlite3.Row
        if "final_rework_requests" not in _tables(connection):
            raise WorkflowEvalError("final rework table is unavailable")
        rows = connection.execute(
            """
            SELECT r.id, r.work_item_id, r.reviewed_revision, r.summary,
                   r.issues_json, r.state, r.created_at, r.verified_at,
                   w.product, w.version, w.package_path
            FROM final_rework_requests r
            JOIN work_items w ON w.id = r.work_item_id
            ORDER BY r.id
            """
        ).fetchall()
    for row in rows:
        try:
            issues = json.loads(row["issues_json"])
        except json.JSONDecodeError:
            issues = []
        normalized_issues: list[dict[str, Any]] = []
        categories: set[str] = set()
        for issue in issues if isinstance(issues, list) else []:
            if not isinstance(issue, dict):
                continue
            issue_id = str(issue.get("id", "")).strip()
            action = _sanitize(str(issue.get("action", "")))
            issue_categories = _categories(issue_id, action)
            categories.update(issue_categories)
            normalized_issues.append(
                {
                    "id": issue_id,
                    "action": action,
                    "categories": issue_categories,
                }
            )
        records.append(
            {
                "schema": "jenny.final-rework-eval.v1",
                "request_id": int(row["id"]),
                "work_item_id": int(row["work_item_id"]),
                "product": str(row["product"]),
                "version": str(row["version"]),
                "package_name": Path(str(row["package_path"])).name,
                "reviewed_revision": int(row["reviewed_revision"]),
                "summary": _sanitize(str(row["summary"])),
                "issues": normalized_issues,
                "expected_categories": sorted(categories or {"OTHER"}),
                "request_state": str(row["state"]),
                "created_at": str(row["created_at"]),
                "verified": bool(row["verified_at"]),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    return {
        "schema": "jenny.final-rework-corpus-summary.v1",
        "records": len(records),
        "output": str(output),
        "categories": dict(
            sorted(
                Counter(
                    category
                    for record in records
                    for category in record["expected_categories"]
                ).items()
            )
        ),
    }


def _jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise WorkflowEvalError(
                    f"invalid JSONL at line {line_number}: {error}"
                ) from error
            if not isinstance(value, dict):
                raise WorkflowEvalError(
                    f"JSONL line {line_number} is not an object"
                )
            yield value


def score_replay(
    *, corpus_path: str | Path, responses_path: str | Path
) -> dict[str, Any]:
    corpus = {
        int(row["request_id"]): set(row["expected_categories"])
        for row in _jsonl(Path(corpus_path).resolve())
    }
    responses = {
        int(row["request_id"]): set(row.get("predicted_categories", []))
        for row in _jsonl(Path(responses_path).resolve())
    }
    true_positive = false_positive = false_negative = 0
    exact = 0
    for request_id, expected in corpus.items():
        predicted = responses.get(request_id, set())
        true_positive += len(expected & predicted)
        false_positive += len(predicted - expected)
        false_negative += len(expected - predicted)
        exact += predicted == expected
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    return {
        "schema": "jenny.prompt-replay-score.v1",
        "cases": len(corpus),
        "responses": len(responses),
        "exact_match_rate": exact / len(corpus) if corpus else 0.0,
        "precision": precision,
        "recall": recall,
    }


def economic_metrics(db_path: str | Path) -> dict[str, Any]:
    database = Path(db_path).resolve()
    with closing(sqlite3.connect(database, timeout=10)) as connection:
        connection.row_factory = sqlite3.Row
        tables = _tables(connection)
        item_rows = (
            connection.execute(
                "SELECT id, product, state FROM work_items ORDER BY id"
            ).fetchall()
            if "work_items" in tables
            else []
        )
        rework_rows = (
            connection.execute(
                "SELECT id, work_item_id FROM final_rework_requests"
            ).fetchall()
            if "final_rework_requests" in tables
            else []
        )
        ready_items = (
            {
                int(row[0])
                for row in connection.execute(
                    """
                    SELECT DISTINCT work_item_id FROM events
                    WHERE event_type = 'MARKED_READY_FOR_SUBMISSION'
                      AND work_item_id IS NOT NULL
                    """
                )
            }
            if "events" in tables
            else set()
        )
        accepted = (
            connection.execute(
                """
                SELECT product, amount_cents FROM accepted_acquisitions
                WHERE status = 'ACTIVE'
                """
            ).fetchall()
            if "accepted_acquisitions" in tables
            else []
        )
        challenge_rows = (
            connection.execute(
                """
                SELECT product, disposition, package_number
                FROM candidate_challenges
                WHERE state = 'DECIDED' ORDER BY id
                """
            ).fetchall()
            if "candidate_challenges" in tables
            else []
        )
    products = Counter(str(row["product"]) for row in item_rows)
    total_items = len(item_rows)
    reworked_items = {int(row["work_item_id"]) for row in rework_rows}
    dispositions = Counter(str(row["disposition"]) for row in challenge_rows)
    admitted = dispositions["ADMIT_PROOF"] + dispositions["OPERATOR_EXCEPTION"]
    return {
        "schema": "jenny.economic-metrics.v1",
        "packages": total_items,
        "candidates_challenged": len(challenge_rows),
        "candidate_admission_rate": (
            admitted / len(challenge_rows) if challenge_rows else None
        ),
        "candidate_package_conversion_rate": (
            sum(row["package_number"] is not None for row in challenge_rows)
            / len(challenge_rows)
            if challenge_rows
            else None
        ),
        "candidate_dispositions": dict(sorted(dispositions.items())),
        "final_rework_requests": len(rework_rows),
        "final_rework_rate": (
            len(reworked_items) / total_items if total_items else 0.0
        ),
        "ready_rate": len(ready_items) / total_items if total_items else 0.0,
        "accepted_offers": len(accepted),
        "accepted_usd": sum(int(row["amount_cents"]) for row in accepted) / 100,
        "research_hours_per_offer": None,
        "same_product_concentration": (
            max(products.values()) / total_items if total_items else 0.0
        ),
        "largest_product": products.most_common(1)[0][0] if products else None,
        "first_twenty_candidate_decisions_complete": len(challenge_rows) >= 20,
    }


def _parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Private workflow evaluation and economic metrics"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=workspace / "notes" / "review_mailbox" / "review_mailbox.sqlite3",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export-reworks")
    export.add_argument("--output", type=Path, required=True)
    score = commands.add_parser("score-replay")
    score.add_argument("--corpus", type=Path, required=True)
    score.add_argument("--responses", type=Path, required=True)
    commands.add_parser("metrics")
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "export-reworks":
            result = export_rework_corpus(
                db_path=args.db, output_path=args.output
            )
        elif args.command == "score-replay":
            result = score_replay(
                corpus_path=args.corpus, responses_path=args.responses
            )
        else:
            result = economic_metrics(args.db)
    except (OSError, sqlite3.Error, KeyError, TypeError, WorkflowEvalError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
