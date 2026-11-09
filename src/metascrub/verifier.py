from __future__ import annotations

from pathlib import Path

from .extractor import extract_one, validate_file
from .models import ScanResult, VerifyResult
from .pii import classify_fields, is_embedded


def verify_file(source_scan: ScanResult, output: str | Path) -> VerifyResult:
    output_path = Path(output)
    dump = extract_one(output_path)
    classify_fields(dump.fields)

    residual = [field for field in dump.fields if field.is_pii and is_embedded(field)]
    validate_ok, validate_messages = validate_file(output_path)

    hash_before = source_scan.image_hash
    hash_after = dump.image_hash
    hash_match: bool | None = None
    if hash_before and hash_after:
        hash_match = hash_before == hash_after

    clean = not residual and validate_ok
    return VerifyResult(
        clean=clean,
        residual_fields=residual,
        validate_ok=validate_ok,
        validate_messages=validate_messages,
        image_hash_before=hash_before,
        image_hash_after=hash_after,
        image_hash_match=hash_match,
    )
