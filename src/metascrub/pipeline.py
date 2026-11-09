from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .db import Database
from .detector import EXTENSION_MAP, detect_file
from .extractor import ExifDump, build_scan_result, extract_many
from .models import DetectedType, ScanResult, ScrubOptions, ScrubResult
from .scrubber import scrub_file

SKIP_SUFFIXES = {".xmp", ".db", ".db-wal", ".db-shm", ".py", ".pyc", ".md", ".txt"}
SKIP_DIR_NAMES = {".git", ".venv", "__pycache__", "node_modules", ".tools"}


@dataclass
class ScanOutcome:
    file_id: int
    scan: ScanResult


def _is_excluded(path: Path, exclude_roots: Iterable[Path]) -> bool:
    resolved = path.resolve()
    for root in exclude_roots:
        try:
            if resolved == root or resolved.is_relative_to(root):
                return True
        except (OSError, ValueError):
            continue
    return False


def collect_files(
    paths: Iterable[str | Path],
    recursive: bool = True,
    exclude_roots: Iterable[str | Path] = (),
) -> list[Path]:
    excludes = [Path(p).resolve() for p in exclude_roots]
    files: list[Path] = []
    seen: set[Path] = set()

    for raw in paths:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            continue
        candidates: list[Path] = []
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            iterator = path.rglob("*") if recursive else path.iterdir()
            candidates = [p for p in iterator if p.is_file() and not p.is_symlink()]
        for candidate in candidates:
            if candidate.suffix.lower() in SKIP_SUFFIXES:
                continue
            if any(part in SKIP_DIR_NAMES for part in candidate.parts):
                continue
            if _is_excluded(candidate, excludes):
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(resolved)

    return sorted(files)


def scan_paths(
    paths: Iterable[str | Path],
    db: Database,
    recursive: bool = True,
    exclude_roots: Iterable[str | Path] = (),
) -> tuple[list[ScanOutcome], list[str]]:
    files = collect_files(paths, recursive=recursive, exclude_roots=exclude_roots)
    known: list[tuple[Path, DetectedType]] = []
    skipped: list[str] = []

    for path in files:
        detected = detect_file(path)
        if detected.file_type == "UNKNOWN":
            skipped.append(str(path))
            continue
        known.append((path, detected))

    if not known:
        return [], skipped

    dumps = extract_many([path for path, _ in known])
    outcomes: list[ScanOutcome] = []
    for path, detected in known:
        dump = dumps.get(
            path.resolve(),
            ExifDump(path=path, error="ExifTool did not return data for this file"),
        )
        scan = build_scan_result(path, dump, detected)
        file_id = db.upsert_file(scan)
        outcomes.append(ScanOutcome(file_id=file_id, scan=scan))

    return outcomes, skipped


def relative_root_for(source: Path, inputs: Iterable[str | Path]) -> Path:
    source = source.resolve()
    directories: list[Path] = []
    files: list[Path] = []
    for raw in inputs:
        path = Path(raw).expanduser().resolve()
        if path.is_dir():
            directories.append(path)
        elif path.is_file():
            files.append(path)

    for directory in directories:
        try:
            if source.is_relative_to(directory):
                return directory
        except ValueError:
            continue

    if source in files:
        parents = [path.parent for path in files]
        if parents:
            try:
                return Path(os.path.commonpath([str(path) for path in parents]))
            except ValueError:
                pass
        return source.parent

    return source.parent


def scrub_paths(
    paths: Iterable[str | Path],
    db: Database,
    options: ScrubOptions,
    recursive: bool = True,
) -> tuple[list[ScrubResult], list[str]]:
    input_list = [Path(p).expanduser().resolve() for p in paths]
    options.output_root = options.output_root.expanduser().resolve()
    if options.output_root.exists() and not options.output_root.is_dir():
        raise ValueError(f"Output path is not a directory: {options.output_root}")
    outcomes, skipped = scan_paths(
        input_list,
        db,
        recursive=recursive,
        exclude_roots=[options.output_root],
    )

    results: list[ScrubResult] = []
    for outcome in outcomes:
        relative_root = relative_root_for(outcome.scan.path, input_list)
        result = scrub_file(outcome.scan, options, relative_to=relative_root)
        db.record_scrub(outcome.file_id, result, options.output_root)
        results.append(result)

    return results, skipped


def image_files(paths: Iterable[str | Path], recursive: bool = True) -> list[Path]:
    files = collect_files(paths, recursive=recursive)
    return [path for path in files if path.suffix.lower() in EXTENSION_MAP]
