from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from metascrub.extractor import compute_sha256, extract_one
from metascrub.pii import classify_fields, is_embedded


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "metascrub", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )


def embedded_pii(path: Path):
    dump = extract_one(path)
    classify_fields(dump.fields)
    return [field for field in dump.fields if field.is_pii and is_embedded(field)]


def test_end_to_end_scan_scrub_rescan(tmp_path, image_factory, add_metadata, pii_metadata):
    db = tmp_path / "e2e.db"
    out = tmp_path / "scrubbed"

    formats = [
        ("photo.jpg", "JPEG"),
        ("photo.png", "PNG"),
        ("photo.tif", "TIFF"),
        ("photo.webp", "WEBP"),
        ("photo.gif", "GIF"),
        ("photo.bmp", "BMP"),
        ("photo.avif", "AVIF"),
        ("photo.heic", "HEIC"),
    ]
    sources = []
    for name, fmt in formats:
        path = image_factory(name=name, fmt=fmt)
        if fmt != "BMP":
            add_metadata(path, pii_metadata)
        sources.append(path)

    svg = tmp_path / "portrait.svg"
    svg.write_text(
        """<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <metadata>Alice Example alice@example.com</metadata>
  <title>Alice photo</title>
  <rect width="10" height="10" fill="blue"/>
</svg>
""",
        encoding="utf-8",
    )
    sources.append(svg)

    raw = image_factory(name="raw.dng", fmt="TIFF")
    add_metadata(raw, pii_metadata)
    sources.append(raw)

    sidecar = (tmp_path / "photo.xmp")
    sidecar.write_text(
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta>',
        encoding="utf-8",
    )

    jpeg = tmp_path / "photo.jpg"
    jpeg_hash = compute_sha256(jpeg)

    scan = run_cli("scan", str(tmp_path), "--db", str(db), "--json")
    assert scan.returncode == 0, scan.stderr
    scan_payload = json.loads(scan.stdout)
    assert len(scan_payload["scanned"]) == len(sources)
    assert scan_payload["skipped"] == []

    scrub = run_cli(
        "scrub", str(tmp_path), "--out", str(out), "--db", str(db), "--json"
    )
    assert scrub.returncode == 1, scrub.stderr
    scrub_payload = json.loads(scrub.stdout)
    statuses = {Path(result["source"]).name: result["status"] for result in scrub_payload["results"]}
    assert statuses["raw.dng"] == "skipped_raw"
    for name in (
        "photo.jpg",
        "photo.png",
        "photo.tif",
        "photo.webp",
        "photo.gif",
        "photo.bmp",
        "photo.avif",
        "photo.heic",
        "portrait.svg",
    ):
        assert statuses[name] == "success", (name, statuses[name])

    assert compute_sha256(jpeg) == jpeg_hash
    assert embedded_pii(jpeg)

    for result in scrub_payload["results"]:
        if result["status"] != "success":
            continue
        output = Path(result["output"])
        assert output.exists()
        assert embedded_pii(output) == []
        payload = output.read_bytes().lower()
        for needle in (
            b"alice",
            b"alice@example.com",
            b"canon",
            b"eos r5",
            b"gpslatitude",
            b"2024:01:02",
        ):
            assert needle not in payload, (output.name, needle)
        if result["image_hash_before"] and result["image_hash_after"]:
            assert result["image_hash_before"] == result["image_hash_after"]

    assert not (out / "raw.dng").exists()
    assert not (out / "photo.xmp").exists()
    assert "Alice" not in (out / "portrait.svg").read_text(encoding="utf-8")

    report = run_cli("report", "--db", str(db), "--format", "json")
    assert report.returncode == 0, report.stderr
    report_payload = json.loads(report.stdout)
    stats = report_payload["stats"]
    assert stats["scrub_jobs"] == len(sources)
    assert stats["scrub_verified"] == len(sources) - 1
    assert stats["scrub_failed"] == 1

    rescan_db = tmp_path / "rescan.db"
    rescan = run_cli("scan", str(out), "--db", str(rescan_db), "--json")
    assert rescan.returncode == 0, rescan.stderr
    rescan_payload = json.loads(rescan.stdout)
    assert len(rescan_payload["scanned"]) == len(sources) - 1
    for file in rescan_payload["scanned"]:
        non_filesystem = [
            field
            for field in file["pii_fields"]
            if field["category"] != "filesystem"
        ]
        assert non_filesystem == [], (file["path"], non_filesystem)
