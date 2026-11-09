from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .db import Database
from .extractor import ExifToolNotFound, exiftool_version, find_exiftool
from .models import ScanResult, ScrubOptions, ScrubResult
from .pipeline import scan_paths, scrub_paths

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="metascrub",
        description="Extract, index, and erase image metadata with ExifTool and SQLite.",
    )
    parser.add_argument("--version", action="version", version=f"metascrub {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check ExifTool and environment")
    doctor.add_argument("--db", default="metascrub.db", help="Database path")

    scan = sub.add_parser("scan", help="Scan images and store metadata")
    scan.add_argument("paths", nargs="+", help="Files or directories")
    scan.add_argument("--db", default="metascrub.db", help="Database path")
    scan.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recurse into directories (default: true)",
    )
    scan.add_argument("--json", action="store_true", help="Output JSON")

    scrub = sub.add_parser("scrub", help="Copy images to an output dir and erase metadata")
    scrub.add_argument("paths", nargs="+", help="Files or directories")
    scrub.add_argument("--out", required=True, help="Output directory for scrubbed copies")
    scrub.add_argument("--db", default="metascrub.db", help="Database path")
    scrub.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recurse into directories (default: true)",
    )
    scrub.add_argument("--dry-run", action="store_true", help="Plan only, write nothing")
    scrub.add_argument(
        "--allow-raw-scrub",
        action="store_true",
        help="Allow metadata stripping on RAW files (may break rendering)",
    )
    scrub.add_argument("--overwrite", action="store_true", help="Replace existing output files")
    scrub.add_argument(
        "--scrub-sidecars",
        action="store_true",
        help="Copy and strip XMP sidecars instead of omitting them",
    )
    scrub.add_argument(
        "--neutralize-times",
        action="store_true",
        help="Set output file timestamps to a neutral fixed time",
    )
    scrub.add_argument("--json", action="store_true", help="Output JSON")

    report = sub.add_parser("report", help="Summarise the metadata database")
    report.add_argument("--db", default="metascrub.db", help="Database path")
    report.add_argument(
        "--format", choices=("table", "json", "csv"), default="table", help="Output format"
    )
    report.add_argument("--pii-only", action="store_true", help="Only list files with PII")

    gui = sub.add_parser("gui", help="Start the local web UI")
    gui.add_argument("--db", default="metascrub.db", help="Database path")
    gui.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    gui.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    gui.add_argument(
        "--upload-dir",
        default=None,
        help="Directory for files uploaded via drag and drop (default: uploads next to the database)",
    )

    return parser


def _scan_to_dict(outcome) -> dict:
    scan: ScanResult = outcome.scan
    return {
        "file_id": outcome.file_id,
        "path": str(scan.path),
        "type": scan.detected.file_type,
        "mime_type": scan.detected.mime_type,
        "size_bytes": scan.size_bytes,
        "width": scan.width,
        "height": scan.height,
        "captured_at": scan.captured_at,
        "sha256": scan.sha256,
        "pii_count": len(scan.pii_fields),
        "pii_categories": scan.pii_categories,
        "pii_fields": [
            {
                "group": field.group,
                "tag": field.tag,
                "category": field.pii_category,
                "severity": field.severity,
            }
            for field in scan.pii_fields
        ],
        "warnings": scan.warnings,
        "error": scan.error,
    }


def _scrub_to_dict(result: ScrubResult) -> dict:
    return {
        "source": str(result.source),
        "output": str(result.output) if result.output else None,
        "status": result.status,
        "fields_removed": result.fields_removed,
        "verified_clean": result.verified_clean,
        "image_hash_before": result.image_hash_before,
        "image_hash_after": result.image_hash_after,
        "residual_fields": result.residual_fields,
        "notes": result.notes,
        "error": result.error,
    }


def cmd_doctor(args: argparse.Namespace) -> int:
    exiftool = find_exiftool()
    version = exiftool_version()
    checks: list[tuple[str, bool, str]] = []
    checks.append(
        (
            "ExifTool",
            exiftool is not None and version is not None,
            f"{exiftool} (version {version})" if exiftool else "not found",
        )
    )
    checks.append((f"Python {sys.version.split()[0]}", True, sys.executable))
    checks.append((f"SQLite {sqlite3.sqlite_version}", True, "stdlib sqlite3"))
    db_path = Path(args.db).expanduser().resolve()
    parent = db_path.parent
    probe = parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    checks.append(
        (
            "Database directory",
            probe.exists() and os.access(probe, os.W_OK),
            str(parent),
        )
    )

    table = Table(title="metascrub doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for name, ok, detail in checks:
        table.add_row(name, "[green]OK[/green]" if ok else "[red]FAIL[/red]", detail)
    console.print(table)
    if exiftool is None:
        console.print(
            "Install ExifTool: [bold]sudo apt-get install libimage-exiftool-perl[/bold]"
        )
    return 0 if all(ok for _, ok, _ in checks) else 2


def cmd_scan(args: argparse.Namespace) -> int:
    with Database(args.db) as db:
        outcomes, skipped = scan_paths(
            args.paths, db, recursive=args.recursive, exclude_roots=[Path(args.db)]
        )

    if args.json:
        print(
            json.dumps(
                {
                    "scanned": [_scan_to_dict(outcome) for outcome in outcomes],
                    "skipped": skipped,
                },
                indent=2,
            )
        )
        return 0

    table = Table(title=f"Scanned {len(outcomes)} file(s)")
    table.add_column("Path", overflow="fold")
    table.add_column("Type")
    table.add_column("Size")
    table.add_column("PII", justify="right")
    table.add_column("Categories")
    table.add_column("Status")
    for outcome in outcomes:
        scan = outcome.scan
        status = "[red]error[/red]" if scan.error else "[green]ok[/green]"
        table.add_row(
            str(scan.path),
            scan.detected.file_type,
            f"{scan.size_bytes:,}",
            str(len(scan.pii_fields)),
            ", ".join(scan.pii_categories) or "-",
            status,
        )
    console.print(table)
    if skipped:
        console.print(f"[yellow]Skipped {len(skipped)} unrecognised file(s).[/yellow]")
    return 0


def cmd_scrub(args: argparse.Namespace) -> int:
    if not args.out.strip():
        console.print("[red]--out must not be empty.[/red]")
        return 2
    options = ScrubOptions(
        output_root=Path(args.out),
        overwrite=args.overwrite,
        dry_run=args.dry_run,
        allow_raw_scrub=args.allow_raw_scrub,
        scrub_sidecars=args.scrub_sidecars,
        neutralize_times=args.neutralize_times,
    )
    with Database(args.db) as db:
        results, skipped = scrub_paths(args.paths, db, options, recursive=args.recursive)

    if args.json:
        print(
            json.dumps(
                {
                    "results": [_scrub_to_dict(result) for result in results],
                    "skipped": skipped,
                },
                indent=2,
            )
        )
    else:
        table = Table(title=f"Scrub results ({len(results)} file(s))")
        table.add_column("Status")
        table.add_column("Source", overflow="fold")
        table.add_column("Output", overflow="fold")
        table.add_column("Removed", justify="right")
        table.add_column("Verified")
        for result in results:
            verified = (
                "[green]yes[/green]"
                if result.verified_clean
                else ("[red]no[/red]" if result.verified_clean is False else "-")
            )
            table.add_row(
                result.status,
                str(result.source),
                str(result.output) if result.output else "-",
                str(result.fields_removed),
                verified,
            )
        console.print(table)
        for result in results:
            if result.error:
                console.print(f"[red]{result.source}: {result.error}[/red]")
            for note in result.notes:
                console.print(f"[yellow]{result.source}: {note}[/yellow]")
        if skipped:
            console.print(f"[yellow]Skipped {len(skipped)} unrecognised file(s).[/yellow]")

    failures = [r for r in results if r.status not in ("success", "dry_run")]
    return 0 if not failures else 1


def cmd_report(args: argparse.Namespace) -> int:
    with Database(args.db) as db:
        stats = db.stats()
        files = db.list_files(limit=10000)
        if args.pii_only:
            files = [f for f in files if f["pii_count"] > 0]

    if args.format == "json":
        print(json.dumps({"stats": stats, "files": files}, indent=2))
        return 0

    if args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(
            [
                "id",
                "path",
                "type",
                "mime_type",
                "size_bytes",
                "width",
                "height",
                "captured_at",
                "pii_count",
                "pii_categories",
                "scanned_at",
            ]
        )
        for file in files:
            writer.writerow(
                [
                    file["id"],
                    file["path"],
                    file["detected_type"],
                    file["mime_type"] or "",
                    file["size_bytes"],
                    file["width"] or "",
                    file["height"] or "",
                    file["captured_at"] or "",
                    file["pii_count"],
                    ",".join(file["pii_categories"]),
                    file["scanned_at"],
                ]
            )
        return 0

    summary = Table(title="Database summary")
    summary.add_column("Metric")
    summary.add_column("Value", justify="right")
    summary.add_row("Files", f"{stats['total_files']:,}")
    summary.add_row("Metadata fields", f"{stats['total_fields']:,}")
    summary.add_row("PII fields", f"{stats['pii_fields']:,}")
    summary.add_row("Files with PII", f"{stats['files_with_pii']:,}")
    summary.add_row("Scrub jobs", f"{stats['scrub_jobs']:,}")
    summary.add_row("Verified clean", f"{stats['scrub_verified']:,}")
    summary.add_row("Failed jobs", f"{stats['scrub_failed']:,}")
    console.print(summary)

    if stats["by_type"]:
        types = Table(title="Files by type")
        types.add_column("Type")
        types.add_column("Count", justify="right")
        for row in stats["by_type"]:
            types.add_row(row["detected_type"], f"{row['count']:,}")
        console.print(types)

    if stats["by_category"]:
        categories = Table(title="PII by category")
        categories.add_column("Category")
        categories.add_column("Severity")
        categories.add_column("Fields", justify="right")
        for row in stats["by_category"]:
            categories.add_row(
                row["category"], row["severity"] or "-", f"{row['count']:,}"
            )
        console.print(categories)

    files_table = Table(title=f"Files ({len(files)})")
    files_table.add_column("ID", justify="right")
    files_table.add_column("Path", overflow="fold")
    files_table.add_column("Type")
    files_table.add_column("PII", justify="right")
    files_table.add_column("Categories")
    for file in files:
        files_table.add_row(
            str(file["id"]),
            file["path"],
            file["detected_type"],
            str(file["pii_count"]),
            ", ".join(file["pii_categories"]) or "-",
        )
    console.print(files_table)
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    import uvicorn

    from .web.app import create_app

    app = create_app(args.db, args.upload_dir)
    console.print(f"metascrub GUI on [bold]http://{args.host}:{args.port}[/bold]")
    console.print(f"Uploads: [bold]{app.state.upload_dir}[/bold]")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "doctor": cmd_doctor,
        "scan": cmd_scan,
        "scrub": cmd_scrub,
        "report": cmd_report,
        "gui": cmd_gui,
    }
    try:
        return handlers[args.command](args)
    except (ExifToolNotFound, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/yellow]")
        return 130
