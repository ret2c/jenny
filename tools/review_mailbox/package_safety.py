from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
import zipfile
import zlib
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


MAX_ZIP_FILENAME_CHARS = 86
MAX_ZIP_MEMBERS = 2_048
MAX_ZIP_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 500.0
MIN_RATIO_CHECK_BYTES = 1024 * 1024
EXTRACTION_FREE_SPACE_HEADROOM = 512 * 1024 * 1024
EVIDENCE_ROOT = "folder_of_everything_necessary"
_OUTER_HASH_LINE = re.compile(r"^(?P<hash>[A-Fa-f0-9]{64})[ \t]+(?P<path>.+?)$")
_GENERIC_ARCHIVE_STEMS = {
    "archive",
    "attachment",
    "attachments",
    "evidence",
    "evidence_zip",
    "files",
    "folder_of_everything_necessary",
    "package",
}
_GENERIC_NAME_TOKENS = {
    "archive",
    "attachment",
    "attachments",
    "evidence",
    "files",
    "folder",
    "necessary",
    "package",
    "submission",
    "vulnerability",
    "zip",
}

_PRIVATE_MARKERS = (
    ("payout language", re.compile(r"\b(?:zero[- ]payout|payout|payment bundl(?:e|ing))\b", re.I)),
    ("researcher risk acceptance", re.compile(r"\bresearcher risk acceptance\b", re.I)),
    ("local package number", re.compile(r"\b(?:local\s+)?package\s*#\s*\d+\b", re.I)),
    ("Midlane workflow state", re.compile(r"\b(?:MIDLANE|READY_FOR_MIDLANE|ZDI_STAGING|review mailbox)\b", re.I)),
)

_INCLUSION_VERBS = re.compile(
    r"\b(?:add|create|document|include|insert|put|require|state|write)\b", re.I
)


def private_marker(text: str) -> str | None:
    for label, pattern in _PRIVATE_MARKERS:
        if pattern.search(text):
            return label
    return None


def question_requires_private_content(text: str) -> bool:
    return bool(_INCLUSION_VERBS.search(text) and private_marker(text))


def _is_generated_python_artifact(parts: tuple[str, ...]) -> bool:
    normalized = tuple(part.casefold() for part in parts)
    return "__pycache__" in normalized or (
        bool(normalized) and normalized[-1].endswith(".pyc")
    )


def validate_external_package(package: Path) -> None:
    package = package.resolve()
    failures: list[str] = []
    generated_artifacts = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*")
        if _is_generated_python_artifact(path.relative_to(package).parts)
    }
    for archive in package.rglob("*.zip"):
        if len(archive.name) > MAX_ZIP_FILENAME_CHARS:
            failures.append(
                f"ZIP filename exceeds {MAX_ZIP_FILENAME_CHARS} characters: {archive.name}"
            )
        try:
            with zipfile.ZipFile(archive, "r") as handle:
                for name in handle.namelist():
                    parts = tuple(
                        part for part in name.replace("\\", "/").split("/") if part
                    )
                    if _is_generated_python_artifact(parts):
                        generated_artifacts.add(
                            f"{archive.relative_to(package).as_posix()}!{name}"
                        )
        except (OSError, zipfile.BadZipFile) as error:
            failures.append(
                f"cannot inspect ZIP {archive.relative_to(package).as_posix()}: {error}"
            )
    if generated_artifacts:
        failures.append(
            "external package contains generated Python bytecode/cache artifacts: "
            + ", ".join(sorted(generated_artifacts))
        )
    markdown_files = [path.relative_to(package).as_posix() for path in package.rglob("*.md")]
    if markdown_files:
        failures.append("external package contains Markdown files: " + ", ".join(markdown_files))
    for path in package.rglob("*.txt"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            failures.append(f"cannot inspect {path.relative_to(package)}: {error}")
            continue
        marker = private_marker(text)
        if marker:
            failures.append(
                f"private workflow language ({marker}) in "
                f"{path.relative_to(package).as_posix()}"
            )
        if "description" in path.name.lower() and "```" in text:
            failures.append(
                f"external description contains Markdown code fences: "
                f"{path.relative_to(package).as_posix()}"
            )
    if failures:
        raise ValueError("; ".join(failures))


def validate_modern_package_shape(package: Path) -> None:
    package = package.resolve()
    failures: list[str] = []
    if not package.is_dir():
        raise ValueError(f"package directory does not exist: {package}")

    top_files = [path for path in package.iterdir() if path.is_file()]
    descriptions = [
        path
        for path in top_files
        if re.search(r"description.*\.txt$|_description\.txt$", path.name, re.I)
    ]
    archives = [path for path in top_files if path.suffix.casefold() == ".zip"]
    loose_evidence = package / "folder_of_everything_necessary"

    if not descriptions:
        failures.append("missing top-level description txt")
    elif len(descriptions) > 1:
        failures.append("multiple top-level description txt files")
    if not archives:
        failures.append("missing top-level evidence zip")
    elif len(archives) > 1:
        failures.append("multiple top-level evidence zip files")
    outer_hashes = package / "PACKAGE_HASHES.txt"
    if not outer_hashes.is_file():
        failures.append("modern package missing PACKAGE_HASHES.txt")
    if not loose_evidence.is_dir():
        failures.append("missing folder_of_everything_necessary directory")
    elif not (loose_evidence / "SHA256SUMS.txt").is_file():
        failures.append("missing folder_of_everything_necessary/SHA256SUMS.txt")

    if not failures:
        try:
            _validate_archive_filename(package, archives[0])
            _verify_zip_matches_source(loose_evidence, archives[0])
            _validate_outer_hashes(
                package, outer_hashes, descriptions[0], archives[0]
            )
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            failures.append(str(error))

    if failures:
        raise ValueError("; ".join(failures))


def validate_submission_package(package: Path) -> None:
    validate_external_package(package)
    validate_modern_package_shape(package)


def _source_files(source: Path, output: Path, temporary: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(source.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_symlink():
            raise ValueError(f"source contains a symbolic link: {path}")
        if path.is_file() and path.resolve() not in {output, temporary}:
            files.append(path)
    return files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _meaningful_name_tokens(value: str) -> set[str]:
    return {
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9]+", value)
        if len(token) >= 2
        and not token.isdigit()
        and token.casefold() not in _GENERIC_NAME_TOKENS
    }


def _validate_archive_filename(package: Path, archive: Path) -> None:
    stem = archive.stem.casefold()
    if stem in _GENERIC_ARCHIVE_STEMS:
        raise ValueError(
            "evidence ZIP filename must be descriptive; generic placeholder "
            f"name is forbidden: {archive.name}"
        )
    package_tokens = _meaningful_name_tokens(package.name)
    archive_tokens = _meaningful_name_tokens(archive.stem)
    if not package_tokens.intersection(archive_tokens):
        raise ValueError(
            "evidence ZIP filename must be aligned with the package vendor, "
            f"product, or finding: {archive.name}"
        )


def _validate_zip_resources(infos: list[zipfile.ZipInfo]) -> int:
    if len(infos) > MAX_ZIP_MEMBERS:
        raise ValueError(
            f"ZIP member count exceeds limit: {len(infos)} > {MAX_ZIP_MEMBERS}"
        )
    total = 0
    for info in infos:
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            raise ValueError(
                "ZIP member size exceeds limit: "
                f"{info.filename} ({info.file_size} > {MAX_ZIP_MEMBER_BYTES})"
            )
        total += info.file_size
        if total > MAX_ZIP_TOTAL_BYTES:
            raise ValueError(
                "ZIP total uncompressed size exceeds limit: "
                f"{total} > {MAX_ZIP_TOTAL_BYTES}"
            )
        if (
            info.file_size >= MIN_RATIO_CHECK_BYTES
            and info.file_size / max(info.compress_size, 1)
            > MAX_ZIP_COMPRESSION_RATIO
        ):
            ratio = info.file_size / max(info.compress_size, 1)
            raise ValueError(
                "ZIP member compression ratio exceeds limit: "
                f"{info.filename} ({ratio:.1f} > {MAX_ZIP_COMPRESSION_RATIO:.1f})"
            )
    return total


def _stream_sha256(handle: Any) -> str:
    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _zip_file_hashes(archive: Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    roots: set[str] = set()
    try:
        with zipfile.ZipFile(archive, "r") as handle:
            infos = handle.infolist()
            _validate_zip_resources(infos)
            seen: set[str] = set()
            for info in infos:
                name = info.filename
                original_name = info.orig_filename
                if "\\" in original_name:
                    raise ValueError(
                        f"ZIP members must use forward slashes only: {original_name}"
                    )
                if name in seen:
                    raise ValueError(f"ZIP contains duplicate member: {name}")
                seen.add(name)
                if not name or name.startswith("/") or "//" in name:
                    raise ValueError(f"ZIP contains unsafe member path: {name!r}")
                normalized = name[:-1] if info.is_dir() else name
                parts = PurePosixPath(normalized).parts
                if not parts or any(part in {"", ".", ".."} for part in parts):
                    raise ValueError(f"ZIP contains unsafe member path: {name}")
                roots.add(parts[0])
                unix_mode = info.external_attr >> 16
                if stat.S_IFMT(unix_mode) == stat.S_IFLNK:
                    raise ValueError(f"ZIP contains a symbolic link: {name}")
                if info.is_dir():
                    continue
                if len(parts) < 2:
                    raise ValueError(
                        "ZIP must contain exactly one enclosing root named "
                        f"{EVIDENCE_ROOT}"
                    )
                with handle.open(info, "r") as member:
                    observed[name] = _stream_sha256(member)
    except (zipfile.BadZipFile, zlib.error, RuntimeError, EOFError, OSError) as error:
        raise ValueError(
            f"ZIP failed integrity verification: {type(error).__name__}"
        ) from error
    if roots != {EVIDENCE_ROOT}:
        rendered = ", ".join(sorted(roots)) or "<none>"
        raise ValueError(
            "ZIP must contain exactly one enclosing root named "
            f"{EVIDENCE_ROOT}; observed roots: {rendered}"
        )
    return observed


def extract_validated_zip(archive: str | Path, destination: str | Path) -> dict[str, int]:
    archive_path = Path(archive).resolve()
    destination_path = Path(destination).resolve()
    if destination_path.exists() and any(destination_path.iterdir()):
        raise ValueError("ZIP extraction destination must be absent or empty")

    # This performs path, link, duplicate, CRC, root, and resource validation
    # while hashing each member through a bounded streaming reader.
    hashes = _zip_file_hashes(archive_path)
    with zipfile.ZipFile(archive_path, "r") as handle:
        infos = handle.infolist()
        total = _validate_zip_resources(infos)
        capacity_root = destination_path.parent
        while not capacity_root.exists() and capacity_root != capacity_root.parent:
            capacity_root = capacity_root.parent
        required = total + EXTRACTION_FREE_SPACE_HEADROOM
        available = shutil.disk_usage(capacity_root).free
        if available < required:
            raise ValueError(
                "insufficient free space for ZIP extraction: "
                f"required={required} available={available}"
            )

        created = not destination_path.exists()
        destination_path.mkdir(parents=True, exist_ok=True)
        try:
            for info in infos:
                normalized = info.filename[:-1] if info.is_dir() else info.filename
                target = destination_path.joinpath(*PurePosixPath(normalized).parts)
                resolved = target.resolve()
                try:
                    resolved.relative_to(destination_path)
                except ValueError as error:
                    raise ValueError(
                        f"ZIP contains unsafe extraction path: {info.filename}"
                    ) from error
                if info.is_dir():
                    resolved.mkdir(parents=True, exist_ok=True)
                    continue
                resolved.parent.mkdir(parents=True, exist_ok=True)
                with handle.open(info, "r") as source, resolved.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        except Exception:
            if created and destination_path.exists():
                shutil.rmtree(destination_path)
            raise
    return {"file_count": len(hashes), "total_uncompressed_bytes": total}


def _verify_zip_matches_source(source: Path, archive: Path) -> None:
    if source.name != EVIDENCE_ROOT:
        raise ValueError(f"loose source directory must be named {EVIDENCE_ROOT}")
    expected = {
        f"{EVIDENCE_ROOT}/{path.relative_to(source).as_posix()}": _sha256(path)
        for path in _source_files(source, archive, archive)
    }
    observed = _zip_file_hashes(archive)
    if set(observed) != set(expected):
        raise ValueError("ZIP file list does not match the loose evidence tree")
    if observed != expected:
        raise ValueError("ZIP bytes do not match the loose evidence tree")


def _validate_outer_hashes(
    package: Path,
    manifest: Path,
    description: Path,
    archive: Path,
) -> None:
    records: dict[str, str] = {}
    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        match = _OUTER_HASH_LINE.fullmatch(line)
        if match is None:
            raise ValueError(
                f"PACKAGE_HASHES.txt invalid line {line_number}; expected SHA-256 and filename"
            )
        relative = match.group("path").strip()
        if (
            not relative
            or "/" in relative
            or "\\" in relative
            or Path(relative).name != relative
        ):
            raise ValueError(
                f"PACKAGE_HASHES.txt target must be a top-level filename: {relative}"
            )
        if relative in records:
            raise ValueError(f"PACKAGE_HASHES.txt duplicate target: {relative}")
        records[relative] = match.group("hash").casefold()

    required = {description.name, archive.name}
    if set(records) != required:
        raise ValueError(
            "PACKAGE_HASHES.txt must contain exactly the description and ZIP"
        )
    for relative, expected in records.items():
        actual = _sha256(package / relative)
        if actual != expected:
            raise ValueError(
                f"outer hash mismatch for {relative}: expected={expected} actual={actual}"
            )


def atomic_rebuild_zip(source: str | Path, output: str | Path) -> dict[str, Any]:
    source_path = Path(source).resolve()
    output_path = Path(output).resolve()
    if not source_path.is_dir():
        raise ValueError(f"loose source directory does not exist: {source_path}")
    if source_path.name != EVIDENCE_ROOT:
        raise ValueError(f"loose source directory must be named {EVIDENCE_ROOT}")
    if output_path.suffix.lower() != ".zip":
        raise ValueError("output must use a .zip extension")
    if len(output_path.name) > MAX_ZIP_FILENAME_CHARS:
        raise ValueError(
            f"ZIP filename must be at most {MAX_ZIP_FILENAME_CHARS} characters"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        files = _source_files(source_path, output_path, temporary)
        with zipfile.ZipFile(
            temporary, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as handle:
            for path in files:
                handle.write(
                    path,
                    f"{EVIDENCE_ROOT}/{path.relative_to(source_path).as_posix()}",
                )
        _verify_zip_matches_source(source_path, temporary)
        os.replace(temporary, output_path)
        return {
            "file_count": len(files),
            "output": str(output_path),
            "sha256": _sha256(output_path),
        }
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_reseal_package(package: str | Path) -> dict[str, Any]:
    package_path = Path(package).resolve()
    if not package_path.is_dir():
        raise ValueError(f"package directory does not exist: {package_path}")
    descriptions = [
        path
        for path in package_path.iterdir()
        if path.is_file()
        and re.search(r"description.*\.txt$|_description\.txt$", path.name, re.I)
    ]
    archives = [path for path in package_path.iterdir() if path.suffix.lower() == ".zip"]
    if len(descriptions) != 1 or len(archives) != 1:
        raise ValueError("reseal requires exactly one description and one evidence ZIP")
    loose = package_path / EVIDENCE_ROOT
    if not loose.is_dir():
        raise ValueError(f"reseal requires {EVIDENCE_ROOT}")
    inner_manifest = loose / "SHA256SUMS.txt"
    evidence_files = [
        path
        for path in _source_files(loose, archives[0], archives[0])
        if path.resolve() != inner_manifest.resolve()
    ]
    inner_text = "".join(
        f"{_sha256(path)}  {path.relative_to(loose).as_posix()}\n"
        for path in evidence_files
    )
    _atomic_write_text(inner_manifest, inner_text)
    archive_result = atomic_rebuild_zip(loose, archives[0])
    outer_text = (
        f"{_sha256(descriptions[0])}  {descriptions[0].name}\n"
        f"{_sha256(archives[0])}  {archives[0].name}\n"
    )
    _atomic_write_text(package_path / "PACKAGE_HASHES.txt", outer_text)
    validate_submission_package(package_path)
    return {
        "package": str(package_path),
        "file_count": len(evidence_files),
        "archive_sha256": archive_result["sha256"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Package hygiene and atomic ZIP helper")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--package", type=Path, required=True)
    rebuild = commands.add_parser("rebuild-zip")
    rebuild.add_argument("--source", type=Path, required=True)
    rebuild.add_argument("--output", type=Path, required=True)
    reseal = commands.add_parser("reseal")
    reseal.add_argument("--package", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "validate":
            validate_submission_package(args.package)
            output: dict[str, Any] = {"package": str(args.package.resolve()), "valid": True}
        elif args.command == "rebuild-zip":
            output = atomic_rebuild_zip(args.source, args.output)
        else:
            output = atomic_reseal_package(args.package)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
