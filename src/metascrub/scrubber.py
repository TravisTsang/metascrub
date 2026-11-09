from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from .detector import is_raw
from .extractor import exiftool_env, extract_one, find_exiftool
from .models import ScanResult, ScrubOptions, ScrubResult
from .pii import classify_fields, is_embedded
from .verifier import verify_file

EDITOR_NAMESPACES = (
    "{http://www.inkscape.org/namespaces/inkscape}",
    "{http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd}",
)
NEUTRAL_EPOCH = 946684800  # 2000-01-01T00:00:00Z


class ScrubError(RuntimeError):
    pass


def strip_metadata(
    path: str | Path, keep_orientation: bool = True, keep_color: bool = True
) -> tuple[bool, list[str]]:
    exiftool = find_exiftool()
    if exiftool is None:
        raise ScrubError("ExifTool not found")

    cmd = [str(exiftool), "-all=", "-tagsfromfile", "@"]
    if keep_color:
        cmd.append("-ColorSpaceTags")
    if keep_orientation:
        cmd.append("-Orientation")
    cmd.extend(
        [
            "-overwrite_original",
            "-charset",
            "filename=UTF8",
            str(Path(path).resolve()),
        ]
    )
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env=exiftool_env(exiftool),
    )
    messages: list[str] = []
    if proc.stderr.strip():
        messages.append(proc.stderr.strip())
    return proc.returncode < 2, messages


def purge_residual_pii(
    path: str | Path, max_passes: int = 2
) -> tuple[bool, list[str]]:
    exiftool = find_exiftool()
    if exiftool is None:
        return False, ["ExifTool not found"]

    messages: list[str] = []
    target = str(Path(path).resolve())

    for _ in range(max_passes):
        dump = extract_one(target)
        classify_fields(dump.fields)
        residual = [
            field
            for field in dump.fields
            if field.is_pii
            and is_embedded(field)
            and (field.group or "").strip().lower() != "composite"
        ]
        if not residual:
            return True, messages

        delete_args: list[str] = []
        seen: set[str] = set()
        for field in residual:
            group = (field.group or "").strip()
            if group.lower() in ("system", "exiftool", "composite"):
                continue
            if group.lower() == "file":
                argument = f"-{field.tag}="
            else:
                argument = f"-{group}:{field.tag}="
            if argument not in seen:
                seen.add(argument)
                delete_args.append(argument)

        if not delete_args:
            return False, messages + [
                "Residual PII has no writable tags: "
                + ", ".join(field.key for field in residual)
            ]

        proc = subprocess.run(
            [
                str(exiftool),
                *delete_args,
                "-overwrite_original",
                "-charset",
                "filename=UTF8",
                target,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
            env=exiftool_env(exiftool),
        )
        if proc.stderr.strip():
            messages.append(proc.stderr.strip())
        if proc.returncode >= 2:
            return False, messages

    dump = extract_one(target)
    classify_fields(dump.fields)
    residual = [
        field
        for field in dump.fields
        if field.is_pii
        and is_embedded(field)
        and (field.group or "").strip().lower() != "composite"
    ]
    if residual:
        return False, messages + [
            "Residual PII after purge: " + ", ".join(field.key for field in residual)
        ]
    return True, messages


def sanitize_svg(path: str | Path) -> None:
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    p = Path(path)
    tree = ET.parse(p)
    root = tree.getroot()

    def walk(element: ET.Element) -> None:
        for child in list(element):
            if child.tag is ET.Comment or child.tag is ET.ProcessingInstruction:
                element.remove(child)
                continue
            if isinstance(child.tag, str) and child.tag.split("}")[-1].lower() in (
                "metadata",
                "title",
                "desc",
            ):
                element.remove(child)
                continue
            walk(child)
        for attr in list(element.attrib):
            if attr.startswith(EDITOR_NAMESPACES):
                del element.attrib[attr]

    walk(root)
    tree.write(p, encoding="utf-8", xml_declaration=True)


def _sidecar_for(path: Path) -> Path | None:
    for suffix in (".xmp", ".XMP"):
        candidate = path.with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


def _neutralize_times(path: Path) -> None:
    try:
        os.utime(path, (NEUTRAL_EPOCH, NEUTRAL_EPOCH))
    except OSError:
        pass


def scrub_file(
    scan: ScanResult,
    options: ScrubOptions,
    relative_to: Path | None = None,
) -> ScrubResult:
    source = scan.path
    embedded_pii = [field for field in scan.pii_fields if is_embedded(field)]
    if relative_to is not None:
        try:
            relative = source.relative_to(relative_to)
        except ValueError:
            relative = Path(source.name)
    else:
        relative = Path(source.name)

    output = options.output_root / relative
    notes: list[str] = []

    if is_raw(scan.detected.file_type) and not options.allow_raw_scrub:
        return ScrubResult(
            source=source,
            output=None,
            status="skipped_raw",
            error=(
                f"{scan.detected.file_type} is a RAW format; metadata is often required "
                "for rendering. Re-run with --allow-raw-scrub to override."
            ),
            notes=notes,
        )

    if output.resolve() == source.resolve():
        return ScrubResult(
            source=source,
            output=output,
            status="error",
            error="Refusing to write over the original file; choose a different output directory.",
            notes=notes,
        )

    if options.dry_run:
        return ScrubResult(
            source=source,
            output=output,
            status="dry_run",
            fields_removed=len(embedded_pii),
            notes=notes,
        )

    if output.exists() and not options.overwrite:
        return ScrubResult(
            source=source,
            output=output,
            status="skipped_exists",
            error="Output already exists; use --overwrite to replace it.",
            notes=notes,
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output)

    is_svg = (
        scan.detected.file_type.upper() == "SVG" or output.suffix.lower() == ".svg"
    )

    if is_svg:
        try:
            sanitize_svg(output)
        except (ET.ParseError, OSError) as exc:
            return ScrubResult(
                source=source,
                output=output,
                status="failed",
                fields_removed=len(embedded_pii),
                error=f"SVG sanitisation failed: {exc}",
                notes=notes,
            )
    else:
        ok, messages = strip_metadata(
            output,
            keep_orientation=options.keep_orientation,
            keep_color=options.keep_color,
        )
        if not ok:
            return ScrubResult(
                source=source,
                output=output,
                status="failed",
                fields_removed=len(embedded_pii),
                error="; ".join(messages) or "ExifTool failed to strip metadata",
                notes=notes,
            )

        purged, purge_messages = purge_residual_pii(output)
        if not purged:
            return ScrubResult(
                source=source,
                output=output,
                status="failed",
                fields_removed=len(embedded_pii),
                error="; ".join(purge_messages) or "Could not purge residual PII",
                notes=notes,
            )

    sidecar = _sidecar_for(source)
    if sidecar is not None:
        if options.scrub_sidecars:
            sidecar_out = output.with_suffix(sidecar.suffix)
            shutil.copy2(sidecar, sidecar_out)
            sidecar_ok, sidecar_messages = strip_metadata(
                sidecar_out, keep_orientation=False, keep_color=False
            )
            if sidecar_ok:
                notes.append(f"sidecar scrubbed: {sidecar.name}")
            else:
                notes.append(
                    f"sidecar strip failed: {sidecar.name}: "
                    + "; ".join(sidecar_messages)
                )
            if options.neutralize_times:
                _neutralize_times(sidecar_out)
        else:
            notes.append(f"sidecar omitted: {sidecar.name}")

    if options.neutralize_times:
        _neutralize_times(output)

    try:
        verification = verify_file(scan, output)
    except (OSError, RuntimeError, ValueError) as exc:  # pragma: no cover - defensive
        return ScrubResult(
            source=source,
            output=output,
            status="verification_error",
            fields_removed=len(embedded_pii),
            error=str(exc),
            notes=notes,
        )

    residual = [field.key for field in verification.residual_fields]
    if verification.image_hash_match is False:
        notes.append("image data hash changed after scrub")
    if not verification.validate_ok:
        notes.extend(verification.validate_messages)

    return ScrubResult(
        source=source,
        output=output,
        status="success" if verification.clean else "verification_failed",
        fields_removed=len(embedded_pii),
        verified_clean=verification.clean,
        image_hash_before=verification.image_hash_before,
        image_hash_after=verification.image_hash_after,
        error=None
        if verification.clean
        else "Residual PII or validation errors after scrub",
        residual_fields=residual,
        notes=notes,
    )
