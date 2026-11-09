from __future__ import annotations

import os
import stat

from metascrub.db import Database
from metascrub.models import DetectedType, MetaField, ScanResult, ScrubResult
from metascrub.pii import classify_fields


def make_scan(path, fields, file_type="JPEG"):
    classify_fields(fields)
    return ScanResult(
        path=path,
        sha256="deadbeef",
        size_bytes=1234,
        detected=DetectedType(file_type=file_type, mime_type="image/jpeg"),
        fields=fields,
        metadata_json={"File:FileType": file_type},
        width=32,
        height=24,
        captured_at="2024:01:02 03:04:05",
    )


def test_upsert_and_replace_fields(tmp_path):
    db = Database(tmp_path / "test.db")
    path = tmp_path / "photo.jpg"
    path.write_bytes(b"x")

    scan = make_scan(
        path,
        [
            MetaField(group="IFD0", tag="Artist", value="Alice"),
            MetaField(group="GPS", tag="GPSLatitude", value="51.5"),
        ],
    )
    file_id = db.upsert_file(scan)
    record = db.get_file(file_id)
    assert record is not None
    assert record["detected_type"] == "JPEG"
    assert record["pii_summary"]
    assert len(record["fields"]) == 2

    scan.fields = [MetaField(group="IFD0", tag="Orientation", value="6")]
    classify_fields(scan.fields)
    same_id = db.upsert_file(scan)
    assert same_id == file_id
    record = db.get_file(file_id)
    assert len(record["fields"]) == 1
    assert record["fields"][0]["tag"] == "Orientation"
    assert db.stats()["total_files"] == 1
    db.close()


def test_list_filters_and_stats(tmp_path):
    db = Database(tmp_path / "test.db")
    first = tmp_path / "a.jpg"
    second = tmp_path / "b.png"
    first.write_bytes(b"a")
    second.write_bytes(b"b")

    db.upsert_file(
        make_scan(first, [MetaField(group="GPS", tag="GPSLatitude", value="1.5")])
    )
    db.upsert_file(
        make_scan(
            second,
            [MetaField(group="IFD0", tag="Artist", value="Bob")],
            file_type="PNG",
        )
    )

    assert len(db.list_files()) == 2
    assert len(db.list_files(file_type="PNG")) == 1
    assert len(db.list_files(pii_category="location")) == 1
    assert len(db.list_files(severity="high")) == 2
    assert len(db.list_files(search="a.jpg")) == 1

    stats = db.stats()
    assert stats["total_files"] == 2
    assert stats["files_with_pii"] == 2
    assert stats["pii_fields"] == 2
    assert {row["detected_type"] for row in stats["by_type"]} == {"JPEG", "PNG"}
    db.close()


def test_scrub_jobs_and_delete(tmp_path):
    db = Database(tmp_path / "test.db")
    path = tmp_path / "photo.jpg"
    path.write_bytes(b"x")
    file_id = db.upsert_file(make_scan(path, []))

    result = ScrubResult(
        source=path,
        output=tmp_path / "out" / "photo.jpg",
        status="success",
        fields_removed=3,
        verified_clean=True,
        image_hash_before="abc",
        image_hash_after="abc",
    )
    job_id = db.record_scrub(file_id, result, tmp_path / "out")
    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "success"
    assert job["verified_clean"] == 1
    assert job["source_path"] == str(path)

    assert db.delete_file(file_id) is True
    assert db.get_file(file_id) is None
    job = db.get_job(job_id)
    assert job is not None
    assert job["file_id"] is None
    db.close()


def test_database_permissions(tmp_path):
    db_path = tmp_path / "secure.db"
    db = Database(db_path)
    db.close()
    if os.name != "nt":
        mode = stat.S_IMODE(db_path.stat().st_mode)
        assert mode == 0o600
