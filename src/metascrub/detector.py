from __future__ import annotations

from pathlib import Path

from .models import DetectedType

RAW_TYPES = {
    "DNG",
    "CR2",
    "CR3",
    "NEF",
    "ARW",
    "RAF",
    "ORF",
    "RW2",
    "PEF",
    "SRW",
    "3FR",
    "IIQ",
    "X3F",
}

MIME_TYPES = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "GIF": "image/gif",
    "TIFF": "image/tiff",
    "WEBP": "image/webp",
    "HEIC": "image/heic",
    "HEIF": "image/heif",
    "AVIF": "image/avif",
    "BMP": "image/bmp",
    "SVG": "image/svg+xml",
    "DNG": "image/x-adobe-dng",
    "CR2": "image/x-canon-cr2",
    "CR3": "image/x-canon-cr3",
    "NEF": "image/x-nikon-nef",
    "ARW": "image/x-sony-arw",
    "RAF": "image/x-fujifilm-raf",
    "ORF": "image/x-olympus-orf",
    "RW2": "image/x-panasonic-rw2",
    "PEF": "image/x-pentax-pef",
    "SRW": "image/x-samsung-srw",
    "3FR": "image/x-hasselblad-3fr",
    "IIQ": "image/x-phaseone-iiq",
    "X3F": "image/x-sigma-x3f",
    "UNKNOWN": None,
}

EXTENSION_MAP = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".jpe": "JPEG",
    ".png": "PNG",
    ".gif": "GIF",
    ".tif": "TIFF",
    ".tiff": "TIFF",
    ".webp": "WEBP",
    ".heic": "HEIC",
    ".heif": "HEIF",
    ".avif": "AVIF",
    ".bmp": "BMP",
    ".svg": "SVG",
    ".dng": "DNG",
    ".cr2": "CR2",
    ".cr3": "CR3",
    ".nef": "NEF",
    ".arw": "ARW",
    ".raf": "RAF",
    ".orf": "ORF",
    ".rw2": "RW2",
    ".pef": "PEF",
    ".srw": "SRW",
    ".3fr": "3FR",
    ".fff": "3FR",
    ".iiq": "IIQ",
    ".x3f": "X3F",
}

TIFF_RAW_EXTENSIONS = {
    ".dng": "DNG",
    ".cr2": "CR2",
    ".nef": "NEF",
    ".arw": "ARW",
    ".pef": "PEF",
    ".srw": "SRW",
    ".3fr": "3FR",
    ".fff": "3FR",
    ".iiq": "IIQ",
}

ISO_BMFF_BRANDS = {
    b"heic": "HEIC",
    b"heix": "HEIC",
    b"hevc": "HEIC",
    b"hevx": "HEIC",
    b"heim": "HEIC",
    b"heis": "HEIC",
    b"mif1": "HEIF",
    b"msf1": "HEIF",
    b"avif": "AVIF",
    b"avis": "AVIF",
    b"crx ": "CR3",
}


def is_raw(file_type: str) -> bool:
    return file_type.upper() in RAW_TYPES


def _result(file_type: str, confidence: str, source: str) -> DetectedType:
    return DetectedType(
        file_type=file_type,
        mime_type=MIME_TYPES.get(file_type),
        confidence=confidence,
        source=source,
    )


def _detect_iso_bmff(head: bytes) -> str | None:
    if len(head) < 12 or head[4:8] != b"ftyp":
        return None
    major = head[8:12]
    if major in ISO_BMFF_BRANDS:
        return ISO_BMFF_BRANDS[major]
    for brand, file_type in ISO_BMFF_BRANDS.items():
        if brand in head[8:64]:
            return file_type
    return "HEIF"


def _detect_svg(head: bytes) -> bool:
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if not stripped:
        return False
    if stripped.startswith((b"<?xml", b"<svg", b"<!--")):
        return b"<svg" in stripped[:4096].lower()
    return False


def detect_bytes(head: bytes, suffix: str = "") -> DetectedType:
    suffix = suffix.lower()

    iso_type = _detect_iso_bmff(head)
    if iso_type:
        return _result(iso_type, "magic", "signature")

    if head.startswith(b"\xff\xd8\xff"):
        return _result("JPEG", "magic", "signature")
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return _result("PNG", "magic", "signature")
    if head.startswith((b"GIF87a", b"GIF89a")):
        return _result("GIF", "magic", "signature")
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return _result("WEBP", "magic", "signature")
    if head.startswith(b"BM"):
        return _result("BMP", "magic", "signature")
    if head.startswith(b"FUJIFILMCCD-RAW"):
        return _result("RAF", "magic", "signature")
    if head.startswith((b"IIRO", b"MMOR", b"IIRS")):
        return _result("ORF", "magic", "signature")
    if head.startswith(b"IIU\x00"):
        return _result("RW2", "magic", "signature")
    if head.startswith(b"FOVb"):
        return _result("X3F", "magic", "signature")

    if head.startswith((b"II*\x00", b"MM\x00*")):
        if head[8:10] == b"CR" and suffix == ".cr2":
            return _result("CR2", "magic", "signature")
        raw_type = TIFF_RAW_EXTENSIONS.get(suffix)
        if raw_type:
            return _result(raw_type, "extension", "signature+extension")
        return _result("TIFF", "magic", "signature")

    if _detect_svg(head):
        return _result("SVG", "magic", "signature")

    ext_type = EXTENSION_MAP.get(suffix)
    if ext_type:
        return _result(ext_type, "extension", "extension")

    return _result("UNKNOWN", "none", "none")


def detect_file(path: str | Path) -> DetectedType:
    p = Path(path)
    try:
        with p.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return _result("UNKNOWN", "none", "unreadable")
    return detect_bytes(head, p.suffix)


def refine_with_exiftool(detected: DetectedType, exif_file_type: str | None) -> DetectedType:
    if not exif_file_type:
        return detected
    exif_type = exif_file_type.upper()
    if exif_type == detected.file_type.upper():
        return detected
    if detected.confidence == "magic" and detected.file_type == "TIFF":
        return _result(exif_type, "exiftool", "exiftool")
    if detected.file_type == "UNKNOWN":
        return _result(exif_type, "exiftool", "exiftool")
    return detected
