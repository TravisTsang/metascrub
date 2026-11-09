from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DetectedType:
    file_type: str
    mime_type: str | None = None
    confidence: str = "magic"
    source: str = "signature"


@dataclass
class MetaField:
    group: str
    tag: str
    value: str
    value_type: str = "string"
    is_pii: bool = False
    pii_category: str | None = None
    severity: str | None = None

    @property
    def key(self) -> str:
        return f"{self.group}:{self.tag}" if self.group else self.tag


@dataclass
class ScanResult:
    path: Path
    sha256: str
    size_bytes: int
    detected: DetectedType
    fields: list[MetaField] = field(default_factory=list)
    metadata_json: dict[str, Any] = field(default_factory=dict)
    width: int | None = None
    height: int | None = None
    captured_at: str | None = None
    image_hash: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def pii_fields(self) -> list[MetaField]:
        return [f for f in self.fields if f.is_pii]

    @property
    def pii_categories(self) -> list[str]:
        return sorted({f.pii_category for f in self.pii_fields if f.pii_category})


@dataclass
class VerifyResult:
    clean: bool
    residual_fields: list[MetaField] = field(default_factory=list)
    validate_ok: bool = True
    validate_messages: list[str] = field(default_factory=list)
    image_hash_before: str | None = None
    image_hash_after: str | None = None
    image_hash_match: bool | None = None


@dataclass
class ScrubResult:
    source: Path
    output: Path | None
    status: str
    fields_removed: int = 0
    verified_clean: bool | None = None
    image_hash_before: str | None = None
    image_hash_after: str | None = None
    error: str | None = None
    residual_fields: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ScrubOptions:
    output_root: Path
    overwrite: bool = False
    dry_run: bool = False
    allow_raw_scrub: bool = False
    scrub_sidecars: bool = False
    neutralize_times: bool = False
    keep_orientation: bool = True
    keep_color: bool = True
