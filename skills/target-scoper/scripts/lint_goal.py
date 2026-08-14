from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen


REQUIRED_LANE_FIELDS = (
    "Attacker",
    "Supported boundary",
    "Economic outcome",
    "Expected class",
    "Conservative likely-value band",
    "Entry points",
    "Decisive discriminator",
    "Negative control",
    "Kill condition",
    "Resource prerequisite",
)
LEGACY_REQUIRED_LANE_FIELDS = tuple(
    field
    for field in REQUIRED_LANE_FIELDS
    if field not in {"Expected class", "Conservative likely-value band"}
)
EXPECTED_CLASSES = {"A_TIER", "CHAIN_COMPONENT", "TIER_B"}
LANE_HEADING = re.compile(r"^### (?:Hypothesis|Lane) \d+\b.*$", re.MULTILINE)
REQUIRED_SECTIONS = (
    "## Authority",
    "## Current identity and acquisition gate",
    "## Economic outcome",
    ("## Non-binding starting hypotheses", "## Ranked lanes"),
    "## Candidate and proof contract",
    "## Acquisition and lab contract",
    "## Durable coverage and continuity",
    "## Package and review contract",
    "## Diminishing returns and stop",
)
MAX_GOAL_LINES = 220
REPLAY_LIMIT_PATTERN = re.compile(
    r"\b(?:corrective replay|replay (?:budget|limit)|replay is allowed)\b",
    re.IGNORECASE,
)
REPLAY_ACCOUNTING_REQUIREMENTS = (
    "REPLAY ACCOUNTING:",
    "attacker-controlled input reaches the intended exact-current product path",
    "observable product response",
    "PRE_PRODUCT_BLOCKED",
    "do not count",
    "cannot establish a technical kill",
    "materially changes the route, fixture, or diagnostic",
    "do not repeat an unchanged attempt",
    "no safe materially changed route remains",
    "candidate unresolved and rehydratable",
)
CURRENTNESS_FIELDS = (
    "Latest shipped stable version and release date",
    "Exact source URLs for deterministic currentness",
    "Currentness resolver contract",
    "Exact GitHub repository for the mandatory issue/pull-request prior-art gate",
    "Public collision source, not a version resolver",
)
HANDOFF_FIELDS = (
    "Target class",
    "Exact primary artifact",
    "Full release identity",
    "Product listener posture",
    "Concrete supported attacker-facing integration",
    "Duplicate pressure",
    "Exact fix-root/variant matrix",
    "Target parking authority",
)
TARGET_CLASSES = {"GENERAL", "NATIVE_PARSER"}
LISTENER_POSTURES = {"INCLUDED", "EXCLUDED", "NOT_APPLICABLE"}
DUPLICATE_PRESSURES = {"LOW", "MEDIUM", "HIGH"}
CURRENT_GOAL_SCHEMA_VERSION = 2
LEGACY_GOAL_SCHEMA_VERSION = 1
EXACT_ARTIFACT_PATTERN = re.compile(
    r"`[^`\r\n]*(?:\d+\.)+\d+[^`\r\n]*\."
    r"(?:tar\.(?:gz|xz|bz2|zst)|tgz|zip|deb|rpm|msi|pkg|exe|dmg|jar|war|"
    r"apk|ipa|iso|img|bin|whl)`",
    re.IGNORECASE,
)
FULL_OBJECT_ID_PATTERN = re.compile(
    r"\b(?:[0-9a-f]{40}|[0-9a-f]{64})\b", re.IGNORECASE
)
MACHINE_VERSION_PATTERN = re.compile(r"\b(?:v)?\d+(?:\.\d+){1,4}(?:[-+][\w.-]+)?\b")
MATRIX_COLUMNS = (
    "Public root",
    "Affected function and sink",
    "Exact fix commit",
    "Current implementation",
    "Sibling discriminator",
)


def _field(text: str, name: str) -> str | None:
    match = re.search(
        rf"^- {re.escape(name)}:\s*(.+?)(?=\n- [A-Z]|\n#{{2,6}}\s|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    return " ".join(match.group(1).split()) if match else None


def currentness_contract(text: str) -> tuple[str | None, list[str], list[str]]:
    identity = _field(text, CURRENTNESS_FIELDS[0])
    version_match = re.search(r"\b(?:v)?(\d+(?:\.\d+){1,4}(?:[-+][\w.-]+)?)\b", identity or "")
    version = version_match.group(1) if version_match else None
    raw_sources = _field(text, CURRENTNESS_FIELDS[1]) or ""
    sources = re.findall(r"https://[^\s`]+", raw_sources)
    return version, sources, [urlparse(url).hostname or "" for url in sources]


def _goal_schema_version(text: str) -> tuple[int, bool, list[str]]:
    raw_versions = re.findall(r"^Goal schema:\s*(\d+)\s*$", text, re.MULTILINE)
    if not raw_versions:
        return LEGACY_GOAL_SCHEMA_VERSION, False, []
    if len(raw_versions) != 1:
        return LEGACY_GOAL_SCHEMA_VERSION, True, ["Goal must declare exactly one schema version"]
    version = int(raw_versions[0])
    if version not in {LEGACY_GOAL_SCHEMA_VERSION, CURRENT_GOAL_SCHEMA_VERSION}:
        return version, True, [f"Unsupported goal schema version: {version}"]
    return version, True, []


def _current_identity_section(text: str) -> str:
    match = re.search(
        r"^## Current identity and acquisition gate[^\r\n]*\r?\n"
        r"(.*?)(?=^##\s|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else ""


def _legacy_currentness_contract(text: str) -> tuple[str | None, list[str], list[str]]:
    version, sources, hostnames = currentness_contract(text)
    if version and len(sources) >= 2 and len(set(hostnames)) >= 2:
        return version, sources, hostnames

    section = _current_identity_section(text)
    version_match = MACHINE_VERSION_PATTERN.search(section)
    version = version_match.group(0).lstrip("v") if version_match else None
    resolver_match = re.search(
        r"(?:official\s+)?currentness\s+(?:resolvers?|sources?)\s*:\s*"
        r"(.+?)(?=\n-\s|\n\n|\Z)",
        section,
        re.IGNORECASE | re.DOTALL,
    )
    resolver_text = resolver_match.group(1) if resolver_match else section
    sources = re.findall(r"https://[^\s`]+", resolver_text)
    if len({urlparse(url.rstrip(".,;:!?")).hostname or "" for url in sources}) < 2:
        sources = re.findall(r"https://[^\s`]+", section)
    sources = [url.rstrip(".,;:!?") for url in sources]
    return version, sources, [urlparse(url).hostname or "" for url in sources]


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "JENNY-goal-lint/1"})
    with urlopen(request, timeout=20) as response:  # noqa: S310 - operator-declared HTTPS only
        return response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")


def lane_sections(text: str) -> list[tuple[str, str]]:
    matches = list(LANE_HEADING.finditer(text))
    sections: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.append((match.group(0), text[match.end() : end]))
    return sections


def _is_concrete(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().casefold()
    return bool(normalized) and not any(
        marker in normalized
        for marker in (
            "{{",
            "}}",
            "tbd",
            "to be determined",
            "latest stable",
            "unknown",
        )
    )


def _heading_anchor(heading: str) -> str:
    anchor = re.sub(r"[^a-z0-9 -]", "", heading.casefold())
    return re.sub(r"[ -]+", "-", anchor).strip("-")


def _matrix_section(path: Path, pointer: str) -> tuple[str | None, str | None]:
    normalized = pointer.strip().strip("`")
    if "#" not in normalized:
        return None, "must point to EVIDENCE_APPENDIX.md with an exact heading anchor"
    raw_file, anchor = normalized.split("#", 1)
    if Path(raw_file).name != "EVIDENCE_APPENDIX.md" or not anchor:
        return None, "must point to EVIDENCE_APPENDIX.md with an exact heading anchor"
    appendix = path.parent / Path(raw_file).name
    if not appendix.is_file():
        return None, f"points to missing appendix {appendix.name}"
    appendix_text = appendix.read_text(encoding="utf-8")
    headings = list(re.finditer(r"^(#{2,6})\s+(.+?)\s*$", appendix_text, re.MULTILINE))
    for index, match in enumerate(headings):
        if _heading_anchor(match.group(2)) != anchor:
            continue
        level = len(match.group(1))
        end = len(appendix_text)
        for later in headings[index + 1 :]:
            if len(later.group(1)) <= level:
                end = later.start()
                break
        return appendix_text[match.end() : end], None
    return None, f"appendix has no heading for anchor #{anchor}"


def _lint_schema_handoff(path: Path, text: str, schema_version: int) -> list[str]:
    if path.name == "standalone-goal-template.md":
        return []
    if schema_version < CURRENT_GOAL_SCHEMA_VERSION:
        return []
    values = {field: _field(text, field) for field in HANDOFF_FIELDS}

    errors: list[str] = []
    for field, value in values.items():
        if not _is_concrete(value):
            errors.append(f"Goal handoff requires concrete field: {field}")

    target_class = values["Target class"] or ""
    if target_class not in TARGET_CLASSES:
        errors.append("Goal handoff Target class must be GENERAL or NATIVE_PARSER")
        return errors

    listener = values["Product listener posture"] or ""
    if listener not in LISTENER_POSTURES:
        errors.append(
            "Goal handoff Product listener posture must be INCLUDED, "
            "EXCLUDED, or NOT_APPLICABLE"
        )
    pressure = values["Duplicate pressure"] or ""
    if pressure not in DUPLICATE_PRESSURES:
        errors.append("Goal handoff Duplicate pressure must be LOW, MEDIUM, or HIGH")
    if values["Target parking authority"] != "OPERATOR_ONLY":
        errors.append("Goal handoff Target parking authority must be OPERATOR_ONLY")

    if target_class == "NATIVE_PARSER":
        artifact = values["Exact primary artifact"] or ""
        if not EXACT_ARTIFACT_PATTERN.search(artifact):
            errors.append(
                "Native-parser handoff exact primary artifact must name a "
                "versioned artifact filename"
            )
        identity = values["Full release identity"] or ""
        if not (
            MACHINE_VERSION_PATTERN.search(identity)
            and FULL_OBJECT_ID_PATTERN.search(identity)
        ):
            errors.append(
                "Native-parser handoff full release identity must include the "
                "machine-readable version and a full commit or artifact digest"
            )
        ingress = values["Concrete supported attacker-facing integration"] or ""
        if listener == "EXCLUDED" and (
            not _is_concrete(ingress)
            or re.search(r"\b(?:or|equivalent|generic)\b", ingress, re.IGNORECASE)
        ):
            errors.append(
                "Native-parser handoff with an excluded product listener must name "
                "one concrete supported attacker-facing integration"
            )

    if pressure == "HIGH":
        pointer = values["Exact fix-root/variant matrix"] or ""
        section, pointer_error = _matrix_section(path, pointer)
        if pointer_error:
            errors.append(
                "Goal handoff exact fix-root/variant matrix " + pointer_error
            )
        elif section is not None:
            missing_columns = [column for column in MATRIX_COLUMNS if column not in section]
            if missing_columns:
                errors.append(
                    "Goal handoff exact fix-root/variant matrix is missing "
                    "columns: " + ", ".join(missing_columns)
                )
    return errors


def lint_goal(
    path: Path,
    *,
    resolve_currentness: bool = False,
    fetch_text: Callable[[str], str] = _fetch_text,
    required_schema_version: int | None = None,
) -> list[str]:
    text = path.read_text(encoding="utf-8")
    template_mode = path.name == "standalone-goal-template.md"
    errors: list[str] = []
    schema_version, _, schema_errors = _goal_schema_version(text)
    errors.extend(schema_errors)
    if required_schema_version is not None and schema_version != required_schema_version:
        errors.append(
            f"Goal schema {required_schema_version} is required; "
            f"found {'legacy ' if schema_version == LEGACY_GOAL_SCHEMA_VERSION else ''}"
            f"schema {schema_version}"
        )
    if errors:
        return errors
    line_count = len(text.splitlines())
    if line_count > MAX_GOAL_LINES:
        errors.append(
            f"Goal has {line_count} lines; compact operational contract must "
            f"be at most {MAX_GOAL_LINES} lines"
        )
    if not re.search(r"^Evidence appendix:\s+`[^`]+EVIDENCE_APPENDIX\.md`", text, re.MULTILINE):
        errors.append("Evidence appendix pointer is missing")
    for section in REQUIRED_SECTIONS:
        if isinstance(section, tuple):
            if not any(candidate in text for candidate in section):
                errors.append(f"Missing required section: {section[0]}")
        elif section not in text:
            errors.append(f"Missing required section: {section}")
    if schema_version >= CURRENT_GOAL_SCHEMA_VERSION:
        for field in CURRENTNESS_FIELDS:
            if _field(text, field) is None:
                errors.append(f"Missing currentness field: {field}")
        version, sources, hostnames = currentness_contract(text)
        if not template_mode:
            if version is None:
                errors.append("Latest shipped identity must contain a machine-readable version")
            if len(sources) < 2 or len(set(hostnames)) < 2:
                errors.append("Currentness requires two HTTPS resolvers on distinct official hostnames")
            if any(
                parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                for parsed in (urlparse(source) for source in sources)
            ):
                errors.append(
                    "Currentness resolver URLs cannot contain credentials, query, or fragment"
                )
        repository = _field(text, CURRENTNESS_FIELDS[3]) or ""
        canonical_repository = re.search(
            r"https://github\.com/[^/\s`]+/[^/\s`]+/?(?=$|[\s`.,;:!?])",
            repository,
        )
        if not template_mode and canonical_repository is None:
            errors.append("Prior-art gate must name one canonical GitHub repository root")
        collision = _field(text, CURRENTNESS_FIELDS[4]) or ""
        collision_urls = re.findall(r"https://[^\s`]+", collision)
        if not template_mode and (not collision_urls or any(url in sources for url in collision_urls)):
            errors.append("Collision-only source must be explicit and separate from currentness resolvers")
    else:
        version, sources, hostnames = _legacy_currentness_contract(text)
        legacy_identity = _current_identity_section(text)
        if version is None:
            errors.append("Legacy goal schema 1 requires a machine-readable current version")
        if (
            (len(sources) < 2 or len(set(hostnames)) < 2)
            and FULL_OBJECT_ID_PATTERN.search(legacy_identity) is None
        ):
            errors.append(
                "Legacy goal schema 1 requires either two explicit HTTPS "
                "currentness sources on distinct hostnames or a full recorded "
                "commit or artifact digest"
            )
    if resolve_currentness and version and len(sources) >= 2:
        for source in sources:
            try:
                body = fetch_text(source)
            except Exception as exc:  # network and decoding failures are a closed gate
                errors.append(f"Currentness resolver failed for {source}: {type(exc).__name__}")
                continue
            if version.casefold() not in body.casefold():
                errors.append(
                    f"Currentness resolver {source} does not state declared version {version}"
                )
    if not re.search(r"^- Primary outcome:\s+\S", text, re.MULTILINE):
        errors.append("Economic outcome must name one primary outcome")
    if schema_version >= CURRENT_GOAL_SCHEMA_VERSION and REPLAY_LIMIT_PATTERN.search(text):
        normalized_text = " ".join(text.split()).casefold()
        missing = [
            requirement
            for requirement in REPLAY_ACCOUNTING_REQUIREMENTS
            if requirement.casefold() not in normalized_text
        ]
        if missing:
            errors.append(
                "Replay accounting invariant is missing or incomplete: "
                + ", ".join(missing)
            )

    errors.extend(_lint_schema_handoff(path, text, schema_version))

    sections = lane_sections(text)
    if not sections:
        errors.append("No starting hypotheses found")
        return errors

    required_lane_fields = (
        REQUIRED_LANE_FIELDS
        if schema_version >= CURRENT_GOAL_SCHEMA_VERSION
        else LEGACY_REQUIRED_LANE_FIELDS
    )
    for heading, body in sections:
        for field in required_lane_fields:
            match = re.search(
                rf"^- {re.escape(field)}:\s*(\S.*)$",
                body,
                re.MULTILINE,
            )
            if match is None:
                errors.append(f"{heading}: missing {field}")
        expected_class = re.search(
            r"^- Expected class:\s*(\S+)\s*$",
            body,
            re.MULTILINE,
        )
        if (
            expected_class is not None
            and expected_class.group(1) not in EXPECTED_CLASSES
            and expected_class.group(1) != "{{EXPECTED_CLASS}}"
        ):
            errors.append(
                f"{heading}: invalid Expected class; use A_TIER, "
                "CHAIN_COMPONENT, or TIER_B"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--resolve-currentness", action="store_true")
    parser.add_argument("--require-current-schema", action="store_true")
    args = parser.parse_args()

    errors = lint_goal(
        args.input,
        resolve_currentness=args.resolve_currentness,
        required_schema_version=(
            CURRENT_GOAL_SCHEMA_VERSION if args.require_current_schema else None
        ),
    )
    if errors:
        print("INVALID")
        for error in errors:
            print(error)
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
