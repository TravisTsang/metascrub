from __future__ import annotations

import pytest

from metascrub.detector import detect_bytes, detect_file, is_raw, refine_with_exiftool
from metascrub.models import DetectedType


@pytest.mark.parametrize(
    "name,fmt,expected",
    [
        ("photo.jpg", "JPEG", "JPEG"),
        ("photo.png", "PNG", "PNG"),
        ("photo.tif", "TIFF", "TIFF"),
        ("photo.webp", "WEBP", "WEBP"),
        ("photo.gif", "GIF", "GIF"),
        ("photo.bmp", "BMP", "BMP"),
        ("photo.avif", "AVIF", "AVIF"),
        ("photo.heic", "HEIC", "HEIC"),
    ],
)
def test_detects_generated_images(image_factory, name, fmt, expected):
    path = image_factory(name=name, fmt=fmt)
    detected = detect_file(path)
    assert detected.file_type == expected
    assert detected.mime_type is not None


def test_detects_svg(tmp_path):
    path = tmp_path / "image.svg"
    path.write_text(
        '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>',
        encoding="utf-8",
    )
    assert detect_file(path).file_type == "SVG"


@pytest.mark.parametrize(
    "head,suffix,expected",
    [
        (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00", ".bin", "HEIC"),
        (b"\x00\x00\x00\x18ftypheix\x00\x00\x00\x00", ".bin", "HEIC"),
        (b"\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00", ".bin", "HEIF"),
        (b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00", ".bin", "AVIF"),
        (b"\x00\x00\x00\x18ftypcrx \x00\x00\x00\x00", ".bin", "CR3"),
        (b"FUJIFILMCCD-RAW" + b"\x00" * 16, ".raf", "RAF"),
        (b"IIRO" + b"\x00" * 16, ".orf", "ORF"),
        (b"IIU\x00" + b"\x00" * 16, ".rw2", "RW2"),
        (b"FOVb" + b"\x00" * 16, ".x3f", "X3F"),
        (b"II*\x00\x08\x00\x00\x00CR\x02\x00", ".cr2", "CR2"),
        (b"II*\x00\x08\x00\x00\x00", ".dng", "DNG"),
        (b"MM\x00*\x00\x00\x00\x08", ".nef", "NEF"),
        (b"MM\x00*\x00\x00\x00\x08", ".arw", "ARW"),
    ],
)
def test_detects_signatures(head, suffix, expected):
    assert detect_bytes(head, suffix).file_type == expected


def test_extension_fallback(tmp_path):
    path = tmp_path / "empty.jpg"
    path.write_bytes(b"")
    detected = detect_file(path)
    assert detected.file_type == "JPEG"
    assert detected.confidence == "extension"


def test_unknown_file(tmp_path):
    path = tmp_path / "notes.bin"
    path.write_bytes(b"this is not an image")
    assert detect_file(path).file_type == "UNKNOWN"


def test_refine_tiff_with_exiftool():
    detected = DetectedType(file_type="TIFF", mime_type="image/tiff", confidence="magic")
    refined = refine_with_exiftool(detected, "DNG")
    assert refined.file_type == "DNG"
    assert refined.confidence == "exiftool"


def test_raw_classification():
    assert is_raw("DNG")
    assert is_raw("CR3")
    assert not is_raw("JPEG")
