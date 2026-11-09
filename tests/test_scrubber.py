from __future__ import annotations

import os
import subprocess
from pathlib import Path

from metascrub.extractor import compute_sha256, exiftool_env, extract_one, scan_file
from metascrub.models import ScrubOptions
from metascrub.pii import classify_fields, is_embedded
from metascrub.scrubber import NEUTRAL_EPOCH, sanitize_svg, scrub_file


def embedded_pii(path: Path):
    dump = extract_one(path)
    classify_fields(dump.fields)
    return [field for field in dump.fields if field.is_pii and is_embedded(field)]


def test_scrub_jpeg_removes_pii_and_preserves_pixels(
    tmp_path, image_factory, add_metadata, pii_metadata
):
    source = add_metadata(image_factory(), pii_metadata, **{"Orientation#": "6"})
    source_hash = compute_sha256(source)
    scan = scan_file(source)
    assert scan.pii_fields

    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))

    assert result.status == "success"
    assert result.verified_clean is True
    assert result.image_hash_before == result.image_hash_after
    assert result.fields_removed > 0
    assert source.exists()
    assert compute_sha256(source) == source_hash
    assert embedded_pii(result.output) == []

    output_dump = extract_one(result.output)
    assert output_dump.value("IFD0:Orientation") == "6"


def test_scrub_preserves_icc_profile(tmp_path, image_factory, add_metadata):
    source = add_metadata(
        image_factory(name="icc.jpg", icc=True),
        {"Artist": "Alice"},
    )
    scan = scan_file(source)
    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.status == "success"
    dump = extract_one(result.output)
    icc_fields = [
        field for field in dump.fields if field.group.lower().startswith("icc")
    ]
    assert icc_fields, "expected ICC profile tags to survive scrubbing"
    assert embedded_pii(result.output) == []


def test_scrub_heic(tmp_path, image_factory, add_metadata):
    source = add_metadata(
        image_factory(name="photo.heic", fmt="HEIC"),
        {
            "Artist": "Alice",
            "SerialNumber": "SN-1",
            "GPSLatitude": "51.5074",
            "GPSLongitude": "0.1278",
            "DateTimeOriginal": "2024:01:02 03:04:05",
        },
    )
    scan = scan_file(source)
    assert scan.detected.file_type == "HEIC"
    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.status == "success", result.error
    assert embedded_pii(result.output) == []


def test_scrub_webp_exif_and_xmp_pii(tmp_path, image_factory, add_metadata):
    source = add_metadata(
        image_factory(name="photo.webp", fmt="WEBP"),
        {
            "Artist": "Alice Artist",
            "OwnerName": "Alice Owner",
            "GPSLatitude": "51.5074",
            "GPSLongitude": "-0.1278",
            "GPSAltitude": "35",
            "DateTimeOriginal": "2024:01:02 03:04:05",
            "SerialNumber": "SN-123",
            "LensSerialNumber": "LENS-9",
            "Make": "Canon",
            "Model": "EOS R5",
            "Software": "Editor 1.0",
            "UserComment": "contact alice@example.com",
            "ImageDescription": "Alice at home",
            "XMP-dc:Creator": "Alice XMP",
            "XMP-dc:Description": "Alice XMP description",
            "XMP-dc:Rights": "Alice rights",
        },
    )
    scan = scan_file(source)
    categories = {
        field.pii_category
        for field in scan.pii_fields
        if is_embedded(field) and field.pii_category
    }
    assert {"location", "identity", "device", "temporal", "free_text"} <= categories

    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.output is not None
    assert result.status == "success", result.error
    assert result.verified_clean is True
    assert embedded_pii(result.output) == []

    output = extract_one(result.output)
    for tag in (
        "IFD0:Artist",
        "IFD0:Make",
        "IFD0:Model",
        "IFD0:Software",
        "IFD0:ImageDescription",
        "ExifIFD:DateTimeOriginal",
        "ExifIFD:SerialNumber",
        "ExifIFD:LensSerialNumber",
        "ExifIFD:UserComment",
        "GPS:GPSLatitude",
        "GPS:GPSLongitude",
        "GPS:GPSAltitude",
        "XMP-dc:Creator",
        "XMP-dc:Description",
        "XMP-dc:Rights",
    ):
        assert tag not in output.tags, tag

    payload = result.output.read_bytes().lower()
    for needle in (b"alice", b"canon", b"eos r5", b"gps", b"2024:01:02", b"lens-9"):
        assert needle not in payload, needle


def test_scrub_webp_removes_ifd1_thumbnail(
    tmp_path, image_factory, add_metadata, exiftool
):
    source = add_metadata(
        image_factory(name="photo.webp", fmt="WEBP"), {"Artist": "Alice"}
    )
    thumb = image_factory(name="thumb.jpg", fmt="JPEG", size=(8, 8))
    proc = subprocess.run(
        [
            str(exiftool),
            "-overwrite_original",
            f"-ThumbnailImage<={thumb}",
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=exiftool_env(exiftool),
    )
    assert proc.returncode < 2, proc.stderr

    scan = scan_file(source)
    assert any(
        field.group == "IFD1" and field.tag == "ThumbnailImage"
        for field in scan.fields
    )

    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.output is not None
    assert result.status == "success", result.error
    assert embedded_pii(result.output) == []

    output = extract_one(result.output)
    assert not [tag for tag in output.tags if tag.startswith("IFD1:")]


def test_scrub_tiff_removes_ifd0_pii(tmp_path, image_factory, add_metadata):
    source = add_metadata(
        image_factory(name="photo.tif", fmt="TIFF"),
        {
            "Artist": "Alice",
            "ImageDescription": "contact alice@example.com",
            "Software": "MyApp",
            "Make": "Canon",
            "Model": "EOS",
            "Copyright": "Alice 2024",
        },
    )
    scan = scan_file(source)
    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.status == "success", result.error
    assert embedded_pii(result.output) == []


def test_scrub_svg_removes_metadata_title_desc(tmp_path, exiftool):
    source = tmp_path / "portrait.svg"
    source.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:dc="http://purl.org/dc/elements/1.1/"
     xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
     width="20" height="20">
  <metadata><dc:creator>Alice Example</dc:creator></metadata>
  <title>Alice photo</title>
  <desc>Portrait of Alice</desc>
  <rect width="20" height="20" fill="red" inkscape:version="1.0"/>
</svg>
""",
        encoding="utf-8",
    )
    scan = scan_file(source)
    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.status == "success", result.error
    text = result.output.read_text(encoding="utf-8")
    assert "Alice" not in text
    assert "<metadata" not in text
    assert "<title" not in text
    assert "<desc" not in text
    assert "inkscape" not in text


def test_sanitize_svg_keeps_graphics(tmp_path):
    path = tmp_path / "image.svg"
    path.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><rect width="5" height="5"/></svg>',
        encoding="utf-8",
    )
    sanitize_svg(path)
    text = path.read_text(encoding="utf-8")
    assert "<rect" in text
    assert "<svg" in text


def test_raw_is_skipped_by_default(tmp_path, image_factory):
    source = image_factory(name="raw.dng", fmt="TIFF")
    scan = scan_file(source)
    assert scan.detected.file_type == "DNG"
    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.status == "skipped_raw"
    assert result.output is None


def test_dry_run_writes_nothing(tmp_path, image_factory, add_metadata):
    source = add_metadata(image_factory(), {"Artist": "Alice"})
    scan = scan_file(source)
    result = scrub_file(
        scan, ScrubOptions(output_root=tmp_path / "out", dry_run=True)
    )
    assert result.status == "dry_run"
    assert not result.output.exists()


def test_existing_output_requires_overwrite(tmp_path, image_factory, add_metadata):
    source = add_metadata(image_factory(), {"Artist": "Alice"})
    scan = scan_file(source)
    output_root = tmp_path / "out"
    output_root.mkdir()
    (output_root / source.name).write_bytes(b"existing")

    result = scrub_file(scan, ScrubOptions(output_root=output_root))
    assert result.status == "skipped_exists"

    result = scrub_file(
        scan, ScrubOptions(output_root=output_root, overwrite=True)
    )
    assert result.status == "success"


def test_refuses_to_overwrite_original(tmp_path, image_factory, add_metadata):
    source = add_metadata(image_factory(), {"Artist": "Alice"})
    scan = scan_file(source)
    result = scrub_file(scan, ScrubOptions(output_root=source.parent))
    assert result.status == "error"


def test_sidecar_is_omitted(tmp_path, image_factory, add_metadata):
    source = add_metadata(image_factory(), {"Artist": "Alice"})
    sidecar = source.with_suffix(".xmp")
    sidecar.write_text("<x:xmpmeta/>", encoding="utf-8")
    scan = scan_file(source)
    result = scrub_file(scan, ScrubOptions(output_root=tmp_path / "out"))
    assert result.status == "success"
    assert not (tmp_path / "out" / sidecar.name).exists()
    assert any("sidecar omitted" in note for note in result.notes)


def test_neutralize_times(tmp_path, image_factory, add_metadata):
    source = add_metadata(image_factory(), {"Artist": "Alice"})
    scan = scan_file(source)
    result = scrub_file(
        scan,
        ScrubOptions(output_root=tmp_path / "out", neutralize_times=True),
    )
    assert result.status == "success"
    assert int(os.stat(result.output).st_mtime) == NEUTRAL_EPOCH
