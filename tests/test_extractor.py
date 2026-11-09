from __future__ import annotations

from metascrub.extractor import (
    build_scan_result,
    exiftool_version,
    extract_one,
    parse_exiftool_object,
    scan_file,
)


def test_extracts_metadata_and_pii(image_factory, add_metadata, pii_metadata):
    path = add_metadata(image_factory(), pii_metadata)
    dump = extract_one(path)

    assert dump.error is None
    assert dump.tags["IFD0:Artist"] == "Alice Example"
    assert dump.tags["ExifIFD:SerialNumber"] == "SN-12345"
    assert float(dump.tags["GPS:GPSLatitude"]) == 51.5074
    assert dump.image_hash

    scan = build_scan_result(path, dump)
    assert scan.detected.file_type == "JPEG"
    assert scan.width == 32
    assert scan.height == 24
    assert scan.captured_at.startswith("2024:01:02")
    categories = {field.pii_category for field in scan.pii_fields}
    assert {"identity", "device", "location", "temporal"} <= categories
    assert any(field.tag == "Comment" and field.severity == "high" for field in scan.pii_fields)


def test_scan_file_hashes_and_dimensions(image_factory):
    path = image_factory(name="plain.png", fmt="PNG")
    scan = scan_file(path)
    assert scan.detected.file_type == "PNG"
    assert scan.sha256
    assert scan.size_bytes > 0
    assert scan.width == 32 and scan.height == 24


def test_parse_redacts_binary_tags():
    tags, fields, warnings, error, image_hash = parse_exiftool_object(
        {
            "SourceFile": "/tmp/example.jpg",
            "File:FileType": "JPEG",
            "File:ThumbnailImage": "A" * 20000,
            "File:ImageDataHash": "abc123",
            "ExifTool:Warning": "minor warning",
        }
    )
    assert tags["File:ThumbnailImage"].startswith("[binary data:")
    binary = next(field for field in fields if field.tag == "ThumbnailImage")
    assert binary.value_type == "binary"
    assert warnings == ["minor warning"]
    assert error is None
    assert image_hash == "abc123"


def test_parse_error_tag():
    _, _, _, error, _ = parse_exiftool_object(
        {"SourceFile": "/tmp/missing.jpg", "Error": "File not found"}
    )
    assert error == "File not found"


def test_extract_many_handles_missing_file(tmp_path, exiftool):
    missing = tmp_path / "missing.jpg"
    dump = extract_one(missing)
    assert dump.error is not None


def test_exiftool_version(exiftool):
    version = exiftool_version()
    assert version
    assert version[0].isdigit()
