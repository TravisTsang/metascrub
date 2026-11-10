from __future__ import annotations

import base64
import binascii
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from .detector import is_raw
from .extractor import (
    BINARY_TAGS,
    exiftool_env,
    extract_one,
    find_exiftool,
    validate_file,
)
from .models import MetadataChange, MetaField, ScanResult, WriteResult

FORBIDDEN_WRITE_GROUPS = {
    "composite",
    "exiftool",
    "file",
    "sourcefile",
    "system",
}

MAX_CHANGES = 200
MAX_VALUES = 100
MAX_VALUE_LENGTH = 8192
MAX_TOTAL_VALUE_LENGTH = 65536
MAX_BINARY_BYTES = 20 * 1024 * 1024
MAX_STRUCT_LENGTH = 65536

_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_GROUP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_LANG_SUFFIX_RE = re.compile(
    r"^(?:[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?|x-default)$",
    re.IGNORECASE,
)

_MULTI_VALUE_TAGS = {
    "contributor",
    "identifier",
    "keywords",
    "publisher",
    "relation",
    "subject",
    "supplementalcategories",
    "type",
}

_DERIVED_FIELD_SOURCES = {
    "aperture": "ExifIFD:FNumber",
    "shutterspeed": "ExifIFD:ExposureTime",
    "gpslatitude": "GPS:GPSLatitude and GPS:GPSLatitudeRef",
    "gpslongitude": "GPS:GPSLongitude and GPS:GPSLongitudeRef",
    "gpsposition": "GPS:GPSLatitude and GPS:GPSLongitude",
    "focallength35efl": "ExifIFD:FocalLength",
    "lensid": "ExifIFD:LensModel",
    "lightvalue": "ExifIFD:ExposureTime, ExifIFD:FNumber, and ExifIFD:ISO",
}


def _tag_base(tag: str) -> str:
    key = tag.casefold()
    if "-" in key:
        base, _, suffix = key.rpartition("-")
        if _LANG_SUFFIX_RE.fullmatch(suffix):
            return base
    return key


def _is_writable_tag(tag: str) -> bool:
    key = tag.casefold()
    if key in writable_tags():
        return True
    base = _tag_base(tag)
    return base != key and base in writable_tags()


def _is_multi_value(field: MetaField) -> bool:
    tag = _tag_base(field.tag)
    group = (field.group or "").casefold()
    if tag in _MULTI_VALUE_TAGS:
        return True
    return tag == "creator" and group.startswith("xmp-dc")


def _readonly_reason(group: str, tag: str) -> str:
    group_key = group.casefold()
    tag_key = tag.casefold()
    if group_key == "composite":
        source = _DERIVED_FIELD_SOURCES.get(tag_key)
        if source:
            return f"Derived field; edit {source} instead."
        if tag_key in ("imagesize", "megapixels"):
            return "Computed from image dimensions; resize the image instead."
        return "Derived metadata is read-only."
    if group_key == "file":
        if tag_key in ("imagewidth", "imageheight"):
            return "Computed from image dimensions; resize the image instead."
        if tag_key in ("imagedatahash", "currentiptcdigest"):
            return "Computed checksum; read-only."
        if tag_key == "exifbyteorder":
            return "EXIF byte order is a file-level setting; read-only in this UI."
        return "File-system and computed fields are read-only."
    return "System and ExifTool bookkeeping fields are read-only."


def _list_tokens(option: str) -> frozenset[str]:
    exiftool = find_exiftool()
    if exiftool is None:
        return frozenset()
    try:
        proc = subprocess.run(
            [str(exiftool), option],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=exiftool_env(exiftool),
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    if proc.returncode != 0:
        return frozenset()

    tokens: set[str] = set()
    for line in proc.stdout.splitlines()[1:]:
        tokens.update(token.lower() for token in line.split())
    return frozenset(tokens)


@lru_cache(maxsize=1)
def writable_tags() -> frozenset[str]:
    return _list_tokens("-listw")


@lru_cache(maxsize=1)
def writable_extensions() -> frozenset[str]:
    return frozenset(f".{token}" for token in _list_tokens("-listwf"))


def _readonly_info(reason: str) -> dict[str, Any]:
    return {
        "writable": False,
        "multi": False,
        "binary": False,
        "struct": False,
        "values": [],
        "value_json": None,
        "reason": reason,
    }


def field_write_info(field: MetaField) -> dict[str, Any]:
    group = (field.group or "").strip()
    if group.lower() in FORBIDDEN_WRITE_GROUPS:
        return _readonly_info(_readonly_reason(group, field.tag))

    if not field.tag or not _is_writable_tag(field.tag):
        return _readonly_info("ExifTool cannot write this tag directly.")

    if field.value_type == "binary":
        return {
            "writable": True,
            "multi": False,
            "binary": True,
            "struct": False,
            "values": [],
            "value_json": None,
            "reason": None,
        }

    if field.value_type == "struct":
        try:
            parsed = json.loads(field.value)
        except (json.JSONDecodeError, RecursionError):
            parsed = None
        if isinstance(parsed, list) and all(
            isinstance(item, (str, int, float, bool)) for item in parsed
        ):
            return {
                "writable": True,
                "multi": True,
                "binary": False,
                "struct": False,
                "values": [str(item) for item in parsed],
                "value_json": None,
                "reason": None,
            }
        if isinstance(parsed, (dict, list)):
            return {
                "writable": True,
                "multi": False,
                "binary": False,
                "struct": True,
                "values": [],
                "value_json": field.value,
                "reason": None,
            }
        return _readonly_info("Structured metadata could not be parsed.")

    multi = _is_multi_value(field)
    values = [field.value] if multi and field.value else []
    return {
        "writable": True,
        "multi": multi,
        "binary": False,
        "struct": False,
        "values": values,
        "value_json": None,
        "reason": None,
    }


def write_supported(path: str | Path, file_type: str | None = None) -> tuple[bool, str | None]:
    if find_exiftool() is None:
        return False, "ExifTool not found."
    suffix = Path(path).suffix.lower()
    if not suffix:
        return False, "The uploaded file has no extension, so its writable format is unknown."
    if suffix not in writable_extensions():
        label = file_type or suffix.lstrip(".").upper()
        return (
            False,
            f"ExifTool cannot write {label} files. Use the Scrub page to remove metadata instead.",
        )
    return True, None


def normalize_changes(changes: Iterable[MetadataChange]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for change in changes:
        if len(normalized) >= MAX_CHANGES:
            raise ValueError(f"Too many changes (maximum {MAX_CHANGES}).")

        group = (change.group or "").strip()
        tag = (change.tag or "").strip()
        if not tag or not _TAG_RE.fullmatch(tag):
            raise ValueError(f"Invalid metadata tag: {tag!r}")
        if group and not _GROUP_RE.fullmatch(group):
            raise ValueError(f"Invalid metadata group: {group!r}")
        if group.lower() in FORBIDDEN_WRITE_GROUPS:
            raise ValueError(f"Metadata group {group!r} is read-only.")
        label = f"{group}:{tag}" if group else tag
        if not _is_writable_tag(tag):
            raise ValueError(f"ExifTool cannot write metadata tag {label!r}.")

        action = (change.action or "set").strip().lower()
        if action not in ("set", "delete"):
            raise ValueError(f"Invalid action {action!r}; expected 'set' or 'delete'.")

        kind = "delete" if action == "delete" else "text"
        values: list[str] = []
        binary_data: bytes | None = None
        struct_value: Any = None
        value_json: str | None = None

        if action == "set":
            has_binary = change.value_base64 is not None
            has_struct = change.value_json is not None
            has_text = change.values is not None or change.value is not None
            if sum((has_binary, has_struct, has_text)) > 1:
                raise ValueError(
                    "Provide only one of value, values, value_base64, or value_json."
                )

            if has_binary:
                encoded = change.value_base64.strip()
                if not encoded:
                    raise ValueError("Binary values must not be empty.")
                if len(encoded) > MAX_BINARY_BYTES * 2:
                    raise ValueError(
                        f"Binary value is too large (maximum {MAX_BINARY_BYTES} bytes)."
                    )
                try:
                    binary_data = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise ValueError("Binary values must be valid base64.") from exc
                if not binary_data:
                    raise ValueError("Binary values must not be empty.")
                if len(binary_data) > MAX_BINARY_BYTES:
                    raise ValueError(
                        f"Binary value is too large (maximum {MAX_BINARY_BYTES} bytes)."
                    )
                kind = "binary"
            elif has_struct:
                text = change.value_json.strip()
                if not text:
                    raise ValueError("Structured values must not be empty.")
                if len(text) > MAX_STRUCT_LENGTH:
                    raise ValueError(
                        f"Structured value is too large (maximum {MAX_STRUCT_LENGTH} characters)."
                    )
                try:
                    parsed = json.loads(text)
                except (json.JSONDecodeError, RecursionError) as exc:
                    raise ValueError(f"Structured value is not valid JSON: {exc}") from exc
                if not isinstance(parsed, (dict, list)):
                    raise ValueError(
                        "Structured values must be a JSON object or array."
                    )
                struct_value = parsed
                value_json = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
                kind = "struct"
            else:
                if tag.casefold() in BINARY_TAGS:
                    raise ValueError(
                        f"{label} is a binary tag; provide value_base64."
                    )
                raw_values = (
                    change.values
                    if change.values is not None
                    else ([change.value] if change.value is not None else [])
                )
                if len(raw_values) > MAX_VALUES:
                    raise ValueError(f"Too many values (maximum {MAX_VALUES}).")
                total_length = 0
                for value in raw_values:
                    if value is None:
                        continue
                    text = str(value)
                    if not text:
                        raise ValueError(
                            "Metadata values must not be empty; use the delete action to remove a tag."
                        )
                    if "\x00" in text:
                        raise ValueError("Metadata values must not contain NUL bytes.")
                    if len(text) > MAX_VALUE_LENGTH:
                        raise ValueError(
                            f"Metadata value is too long (maximum {MAX_VALUE_LENGTH} characters)."
                        )
                    total_length += len(text)
                    if total_length > MAX_TOTAL_VALUE_LENGTH:
                        raise ValueError(
                            "Metadata values are too long in total "
                            f"(maximum {MAX_TOTAL_VALUE_LENGTH} characters)."
                        )
                    values.append(text)
                if not values:
                    raise ValueError(
                        "At least one metadata value is required for a set action."
                    )

        normalized.append(
            {
                "group": group,
                "tag": tag,
                "action": action,
                "kind": kind,
                "values": values,
                "binary_data": binary_data,
                "binary_size": len(binary_data) if binary_data is not None else None,
                "struct_value": struct_value,
                "value_json": value_json,
            }
        )

    if not normalized:
        raise ValueError("No metadata changes supplied.")
    return normalized


def build_write_args(
    changes: Iterable[dict[str, Any]], binary_dir: Path | None = None
) -> list[str]:
    args: list[str] = []
    for index, change in enumerate(changes):
        prefix = f"-{change['group']}:{change['tag']}" if change["group"] else f"-{change['tag']}"
        if change["action"] == "delete":
            args.append(prefix + "=")
        elif change.get("kind") == "struct":
            continue
        elif change.get("kind") == "binary":
            if binary_dir is None:
                raise ValueError("A temporary directory is required for binary writes.")
            binary_path = binary_dir / f"binary-{index}.bin"
            binary_path.write_bytes(change["binary_data"])
            args.append(f"{prefix}<={binary_path}")
        else:
            for value in change["values"]:
                args.append(f"{prefix}={value}")
    return args


def _needs_iptc_utf8(changes: Iterable[dict[str, Any]]) -> bool:
    for change in changes:
        if not change["group"].casefold().startswith("iptc"):
            continue
        if any(
            any(ord(character) > 127 for character in value)
            for value in change["values"]
        ):
            return True
    return False


def _field_values(field: MetaField) -> list[str]:
    if field.value_type == "struct":
        try:
            parsed = json.loads(field.value)
        except json.JSONDecodeError:
            return [field.value]
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    return [field.value]


def _values_equal(expected: str, actual: str) -> bool:
    expected_text = expected.strip()
    actual_text = actual.strip()
    if expected_text == actual_text:
        return True
    if expected_text.casefold() == actual_text.casefold():
        return True
    try:
        return float(expected_text) == float(actual_text)
    except ValueError:
        return False


def _struct_equal(expected: Any, actual: Any) -> bool:
    return json.dumps(expected, ensure_ascii=False, sort_keys=True) == json.dumps(
        actual, ensure_ascii=False, sort_keys=True
    )


def _matching_fields(
    fields: Iterable[MetaField], group: str, tag: str, fallback: bool = True
) -> list[MetaField]:
    group_key = group.casefold()
    tag_key = tag.casefold()
    if group_key:
        exact = [
            field
            for field in fields
            if (field.group or "").casefold() == group_key
            and field.tag.casefold() == tag_key
        ]
        if exact:
            return exact
        if not fallback:
            return []
    return [field for field in fields if field.tag.casefold() == tag_key]


def verify_changes(
    fields: Iterable[MetaField], changes: Iterable[dict[str, Any]]
) -> tuple[list[str], list[str]]:
    field_list = list(fields)
    verified: list[str] = []
    failed: list[str] = []

    for change in changes:
        label = f"{change['group']}:{change['tag']}" if change["group"] else change["tag"]
        if change.get("kind") == "binary" and change["action"] == "set":
            continue
        matches = _matching_fields(
            field_list,
            change["group"],
            change["tag"],
            fallback=change["action"] != "delete",
        )
        actual = [value for field in matches for value in _field_values(field)]

        if change["action"] == "delete":
            if any(value.strip() for value in actual):
                failed.append(label)
            else:
                verified.append(label)
            continue

        if change.get("kind") == "struct":
            actual_structs: list[Any] = []
            for field in matches:
                if field.value_type != "struct":
                    continue
                try:
                    actual_structs.append(json.loads(field.value))
                except (json.JSONDecodeError, RecursionError):
                    continue
            if any(
                _struct_equal(change["struct_value"], value)
                for value in actual_structs
            ):
                verified.append(label)
            else:
                failed.append(label)
            continue

        expected = change["values"]
        if len(expected) == 1:
            ok = any(_values_equal(expected[0], value) for value in actual)
        else:
            ok = len(actual) == len(expected) and all(
                any(_values_equal(item, value) for value in actual)
                for item in expected
            )
        if ok:
            verified.append(label)
        else:
            failed.append(label)

    return verified, failed


def verify_binary_changes(
    path: str | Path,
    changes: Iterable[dict[str, Any]],
    exiftool: Path,
) -> tuple[list[str], list[str]]:
    verified: list[str] = []
    failed: list[str] = []
    for change in changes:
        if change.get("kind") != "binary" or change["action"] != "set":
            continue
        label = f"{change['group']}:{change['tag']}" if change["group"] else change["tag"]
        prefix = f"-{change['group']}:{change['tag']}" if change["group"] else f"-{change['tag']}"
        try:
            proc = subprocess.run(
                [str(exiftool), "-b", prefix, str(path)],
                check=False,
                capture_output=True,
                timeout=60,
                env=exiftool_env(exiftool),
            )
        except (OSError, subprocess.SubprocessError):
            failed.append(label)
            continue
        if proc.returncode == 0 and proc.stdout == change["binary_data"]:
            verified.append(label)
        else:
            failed.append(label)
    return verified, failed


def changes_for_storage(changes: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    stored: list[dict[str, Any]] = []
    for change in changes:
        item = {
            key: value
            for key, value in change.items()
            if key not in ("binary_data", "struct_value")
        }
        if change.get("binary_data") is not None:
            item["binary_size"] = len(change["binary_data"])
        stored.append(item)
    return stored


def write_metadata(
    scan: ScanResult,
    output: str | Path,
    changes: list[dict[str, Any]],
) -> WriteResult:
    source = scan.path
    output_path = Path(output)
    if output_path.resolve() == source.resolve():
        raise ValueError("Refusing to write over the original file.")

    exiftool = find_exiftool()
    if exiftool is None:
        return WriteResult(
            source=source,
            output=None,
            status="failed",
            fields_written=len(changes),
            error="ExifTool not found.",
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(source, output_path)
    except OSError as exc:
        return WriteResult(
            source=source,
            output=output_path,
            status="failed",
            fields_written=len(changes),
            error=str(exc),
        )

    notes: list[str] = []

    def run_exiftool(command: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
                env=exiftool_env(exiftool),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            notes.append(str(exc))
            return None

    try:
        with tempfile.TemporaryDirectory(prefix="metascrub-write-") as temp_name:
            temp_dir = Path(temp_name)
            struct_changes = [
                change
                for change in changes
                if change.get("kind") == "struct" and change["action"] == "set"
            ]
            if struct_changes:
                import_path = temp_dir / "import.json"
                item: dict[str, Any] = {}
                for change in struct_changes:
                    key = (
                        f"{change['group']}:{change['tag']}"
                        if change["group"]
                        else change["tag"]
                    )
                    item[key] = change["struct_value"]
                item["SourceFile"] = str(output_path.resolve())
                import_path.write_text(
                    json.dumps([item], ensure_ascii=False), encoding="utf-8"
                )
                proc = run_exiftool(
                    [
                        str(exiftool),
                        f"-json={import_path}",
                        "-overwrite_original",
                        "-charset",
                        "filename=UTF8",
                        str(output_path.resolve()),
                    ]
                )
                if proc is None:
                    return WriteResult(
                        source=source,
                        output=output_path,
                        status="failed",
                        fields_written=len(changes),
                        error=notes[-1],
                        notes=notes,
                    )
                if proc.stderr.strip():
                    notes.append(proc.stderr.strip())
                if proc.returncode >= 2:
                    return WriteResult(
                        source=source,
                        output=output_path,
                        status="failed",
                        fields_written=len(changes),
                        error=(
                            proc.stderr.strip()
                            or proc.stdout.strip()
                            or "ExifTool failed to write structured metadata."
                        ),
                        notes=notes,
                    )
                if proc.returncode == 1 and not proc.stderr.strip():
                    notes.append(
                        "ExifTool reported a warning while writing structured metadata."
                    )

            normal_changes = [
                change for change in changes if change.get("kind") != "struct"
            ]
            if normal_changes:
                command = [str(exiftool)]
                if _needs_iptc_utf8(normal_changes):
                    command.extend(
                        ["-charset", "iptc=UTF8", "-IPTC:CodedCharacterSet=UTF8"]
                    )
                command.extend(
                    [
                        *build_write_args(normal_changes, temp_dir),
                        "-overwrite_original",
                        "-charset",
                        "filename=UTF8",
                        str(output_path.resolve()),
                    ]
                )
                proc = run_exiftool(command)
                if proc is None:
                    return WriteResult(
                        source=source,
                        output=output_path,
                        status="failed",
                        fields_written=len(changes),
                        error=notes[-1],
                        notes=notes,
                    )
                if proc.stderr.strip():
                    notes.append(proc.stderr.strip())
                if proc.returncode >= 2:
                    return WriteResult(
                        source=source,
                        output=output_path,
                        status="failed",
                        fields_written=len(changes),
                        error=(
                            proc.stderr.strip()
                            or proc.stdout.strip()
                            or "ExifTool failed to write metadata."
                        ),
                        notes=notes,
                    )
                if proc.returncode == 1 and not proc.stderr.strip():
                    notes.append("ExifTool reported a warning while writing metadata.")
    except (OSError, ValueError) as exc:
        return WriteResult(
            source=source,
            output=output_path,
            status="failed",
            fields_written=len(changes),
            error=str(exc),
            notes=notes,
        )

    try:
        dump = extract_one(output_path)
        validate_ok, validate_messages = validate_file(output_path)
    except (OSError, RuntimeError, ValueError) as exc:
        return WriteResult(
            source=source,
            output=output_path,
            status="verification_error",
            fields_written=len(changes),
            error=str(exc),
            notes=notes,
        )

    verified_fields, failed_fields = verify_changes(dump.fields, changes)
    binary_verified, binary_failed = verify_binary_changes(
        output_path, changes, exiftool
    )
    verified_fields.extend(binary_verified)
    failed_fields.extend(binary_failed)
    hash_before = scan.image_hash
    hash_after = dump.image_hash
    hash_match: bool | None = None
    if hash_before and hash_after:
        hash_match = hash_before == hash_after
    if hash_match is False:
        notes.append("Image data hash changed after writing metadata.")
    if not validate_ok:
        notes.extend(validate_messages)
    if is_raw(scan.detected.file_type):
        notes.append(
            "RAW metadata edits may affect how some tools render the image; "
            "the original file was not modified."
        )

    verified = validate_ok and hash_match is not False and not failed_fields
    if verified:
        status = "success"
        error = None
    else:
        status = "verification_failed"
        if failed_fields:
            error = "Could not verify metadata changes: " + ", ".join(failed_fields)
        else:
            error = "Validation failed after writing metadata."

    return WriteResult(
        source=source,
        output=output_path,
        status=status,
        fields_written=len(changes),
        verified=verified,
        image_hash_before=hash_before,
        image_hash_after=hash_after,
        verified_fields=verified_fields,
        failed_fields=failed_fields,
        error=error,
        notes=notes,
    )
