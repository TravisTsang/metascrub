from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detector import detect_file, refine_with_exiftool
from .models import DetectedType, MetaField, ScanResult
from .pii import classify_fields

BINARY_TAGS = {
    "thumbnailimage",
    "previewimage",
    "jpgfromraw",
    "otherimage",
    "mpimage",
    "previewpng",
    "previewtiff",
    "thumbnailtiff",
    "previewjxl",
    "xmpthumbnail",
    "imagedata",
    "icc_profile",
    "image",
    "data",
}

MAX_TEXT_VALUE = 8192

_BINARY_PLACEHOLDER_RE = re.compile(
    r"^\(Binary data (\d+) bytes?, use -b option to extract\)$"
)


class ExifToolNotFound(RuntimeError):
    pass


@dataclass
class ExifDump:
    path: Path
    tags: dict[str, Any] = field(default_factory=dict)
    fields: list[MetaField] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    image_hash: str | None = None

    def first(self, *names: str) -> Any:
        for name in names:
            if name in self.tags:
                return self.tags[name]
        return None

    def value(self, *names: str) -> str | None:
        for name in names:
            value = self.tags.get(name)
            if value is None or value == "":
                continue
            return str(value)
        return None


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_exiftool() -> Path | None:
    override = os.environ.get("METASCRUB_EXIFTOOL")
    if override:
        candidate = Path(override).expanduser()
        if candidate.exists():
            return candidate
    on_path = shutil.which("exiftool")
    if on_path:
        return Path(on_path)
    root = project_root()
    for candidate in (
        root / ".tools" / "exiftool" / "usr" / "bin" / "exiftool",
        root / ".tools" / "exiftool" / "exiftool",
    ):
        if candidate.exists():
            return candidate
    return None


def exiftool_env(exiftool: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    exiftool = exiftool or find_exiftool()
    if exiftool:
        resolved = exiftool.resolve()
        if resolved.parent.name == "bin" and resolved.parent.parent.name == "usr":
            perl_lib = resolved.parent.parent / "share" / "perl5"
            if perl_lib.is_dir():
                existing = env.get("PERL5LIB")
                env["PERL5LIB"] = (
                    f"{perl_lib}{os.pathsep}{existing}" if existing else str(perl_lib)
                )
    return env


def require_exiftool() -> Path:
    exiftool = find_exiftool()
    if exiftool is None:
        raise ExifToolNotFound(
            "ExifTool was not found. Install it with "
            "`sudo apt-get install libimage-exiftool-perl` or set METASCRUB_EXIFTOOL."
        )
    return exiftool


def exiftool_version() -> str | None:
    exiftool = find_exiftool()
    if exiftool is None:
        return None
    try:
        proc = subprocess.run(
            [str(exiftool), "-ver"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=exiftool_env(exiftool),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def compute_sha256(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stringify(value: Any) -> tuple[str, str]:
    if isinstance(value, bool):
        return ("true" if value else "false", "boolean")
    if isinstance(value, (int, float)):
        return str(value), "number"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True), "struct"
    if value is None:
        return "", "null"
    return str(value), "string"


def _normalise_tag(key: str) -> tuple[str, str]:
    if ":" in key:
        group, tag = key.split(":", 1)
        return group, tag
    return "System", key


def parse_exiftool_object(obj: dict[str, Any]) -> tuple[dict[str, Any], list[MetaField], list[str], str | None, str | None]:
    tags: dict[str, Any] = {}
    fields: list[MetaField] = []
    warnings: list[str] = []
    error: str | None = None
    image_hash: str | None = None

    for key, raw_value in obj.items():
        if key == "SourceFile":
            tags["System:SourceFile"] = raw_value
            fields.append(MetaField(group="System", tag="SourceFile", value=str(raw_value)))
            continue

        group, tag = _normalise_tag(key)
        tag_l = tag.lower()
        value, value_type = _stringify(raw_value)

        if tag_l in ("warning", "error") and value:
            if tag_l == "error":
                error = value
            else:
                warnings.append(value)
            tags[f"{group}:{tag}"] = value
            continue

        placeholder = (
            _BINARY_PLACEHOLDER_RE.match(raw_value)
            if isinstance(raw_value, str)
            else None
        )
        if (
            tag_l in BINARY_TAGS
            or placeholder
            or (isinstance(raw_value, str) and len(raw_value) > MAX_TEXT_VALUE)
        ):
            if placeholder:
                value = f"[binary data: {placeholder.group(1)} bytes]"
            else:
                original_len = (
                    len(raw_value) if isinstance(raw_value, str) else len(str(raw_value))
                )
                value = f"[binary data: {original_len} chars]"
            value_type = "binary"

        if tag_l == "imagedatahash" and value:
            image_hash = value

        base_key = f"{group}:{tag}"
        dedup_key = base_key
        index = 2
        while dedup_key in tags:
            dedup_key = f"{base_key}#{index}"
            index += 1
        tags[dedup_key] = value

        fields.append(
            MetaField(group=group, tag=tag, value=value, value_type=value_type)
        )

    return tags, fields, warnings, error, image_hash


def _run_extraction_batch(paths: list[Path], timeout: int) -> list[dict[str, Any]]:
    exiftool = require_exiftool()
    cmd = [
        str(exiftool),
        "-j",
        "-G1",
        "-a",
        "-n",
        "-struct",
        "-charset",
        "filename=UTF8",
        "-all",
        "-ImageDataHash",
    ]

    argfile = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".args", delete=False
        ) as fh:
            argfile = Path(fh.name)
            for path in paths:
                fh.write(str(path.resolve()) + "\n")
        cmd.extend(["-@", str(argfile)])
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=exiftool_env(exiftool),
        )
    finally:
        if argfile is not None:
            argfile.unlink(missing_ok=True)

    if not proc.stdout.strip():
        message = proc.stderr.strip() or f"ExifTool failed with exit code {proc.returncode}"
        return [{"SourceFile": str(path), "Error": message} for path in paths]

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        message = proc.stderr.strip() or "ExifTool returned invalid JSON"
        return [{"SourceFile": str(path), "Error": message} for path in paths]

    if isinstance(payload, dict):
        payload = [payload]
    return payload


def extract_many(
    paths: Iterable[str | Path], batch_size: int = 100, timeout: int = 300
) -> dict[Path, ExifDump]:
    requested = [Path(p).resolve() for p in paths]
    if not requested:
        return {}

    dumps: dict[Path, ExifDump] = {}
    for start in range(0, len(requested), batch_size):
        chunk = requested[start : start + batch_size]
        objects = _run_extraction_batch(chunk, timeout)

        for index, obj in enumerate(objects):
            source = obj.get("SourceFile")
            path = Path(source).resolve() if source else chunk[min(index, len(chunk) - 1)]
            tags, fields, warnings, error, image_hash = parse_exiftool_object(obj)
            dumps[path] = ExifDump(
                path=path,
                tags=tags,
                fields=fields,
                warnings=warnings,
                error=error,
                image_hash=image_hash,
            )

        for path in chunk:
            dumps.setdefault(
                path,
                ExifDump(
                    path=path,
                    error="ExifTool did not return data for this file",
                ),
            )

    return dumps


def extract_one(path: str | Path) -> ExifDump:
    return extract_many([path])[Path(path).resolve()]


def build_scan_result(
    path: str | Path,
    dump: ExifDump,
    detected: DetectedType | None = None,
) -> ScanResult:
    p = Path(path).resolve()
    detected = detected or detect_file(p)
    exif_file_type = dump.value("File:FileType", "File:FileTypeExtension")
    if exif_file_type:
        detected = refine_with_exiftool(detected, exif_file_type)

    classify_fields(dump.fields)

    width = _as_int(
        dump.value(
            "File:ImageWidth",
            "ExifIFD:ExifImageWidth",
            "IFD0:ImageWidth",
        )
    )
    height = _as_int(
        dump.value(
            "File:ImageHeight",
            "ExifIFD:ExifImageHeight",
            "IFD0:ImageHeight",
        )
    )
    if width is None or height is None:
        size = dump.value("Composite:ImageSize")
        if size and " " in size:
            parts = size.split()
            if len(parts) == 2:
                width = width if width is not None else _as_int(parts[0])
                height = height if height is not None else _as_int(parts[1])

    captured_at = dump.value(
        "ExifIFD:DateTimeOriginal",
        "IFD0:DateTimeOriginal",
        "XMP-exif:DateTimeOriginal",
        "QuickTime:MediaCreateDate",
        "ExifIFD:CreateDate",
        "IFD0:CreateDate",
        "System:FileModifyDate",
    )

    try:
        size_bytes = p.stat().st_size
    except OSError:
        size_bytes = 0

    return ScanResult(
        path=p,
        sha256=compute_sha256(p) if p.exists() else "",
        size_bytes=size_bytes,
        detected=detected,
        fields=dump.fields,
        metadata_json=dump.tags,
        width=width,
        height=height,
        captured_at=captured_at,
        image_hash=dump.image_hash,
        error=dump.error,
        warnings=dump.warnings,
    )


def scan_file(path: str | Path) -> ScanResult:
    p = Path(path)
    dump = extract_one(p)
    return build_scan_result(p, dump)


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(str(value).split()[0]))
    except (ValueError, IndexError):
        return None


def image_data_hash(path: str | Path) -> str | None:
    try:
        dump = extract_one(path)
    except ExifToolNotFound:
        return None
    return dump.image_hash


def validate_file(path: str | Path) -> tuple[bool, list[str]]:
    exiftool = find_exiftool()
    if exiftool is None:
        return False, ["ExifTool not found"]

    try:
        proc = subprocess.run(
            [
                str(exiftool),
                "-j",
                "-validate",
                "-warning",
                "-error",
                "-charset",
                "filename=UTF8",
                str(Path(path).resolve()),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=exiftool_env(exiftool),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, [str(exc)]

    messages: list[str] = []
    ok = proc.returncode < 2
    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError:
        payload = []

    if isinstance(payload, dict):
        payload = [payload]
    for obj in payload:
        for key, value in obj.items():
            if key == "SourceFile":
                continue
            tag = key.split(":", 1)[-1]
            text = str(value)
            if tag.lower() in ("validate", "warning", "error"):
                messages.append(f"{tag}: {text}")
                if tag.lower() == "error" or "error" in text.lower():
                    ok = False
    if proc.stderr.strip():
        messages.append(proc.stderr.strip())

    return ok, messages
