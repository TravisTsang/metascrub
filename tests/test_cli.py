from __future__ import annotations

import json

from metascrub.cli import main


def test_doctor_returns_ok(exiftool, tmp_path, capsys):
    code = main(["doctor", "--db", str(tmp_path / "db.sqlite")])
    assert code == 0
    assert "ExifTool" in capsys.readouterr().out


def test_scan_scrub_report_json(tmp_path, image_factory, add_metadata, pii_metadata, capsys):
    source = add_metadata(image_factory(), pii_metadata)
    db = tmp_path / "meta.db"
    out = tmp_path / "out"

    assert main(["scan", str(source), "--db", str(db), "--json"]) == 0
    scanned = json.loads(capsys.readouterr().out)
    assert scanned["scanned"][0]["type"] == "JPEG"
    assert scanned["scanned"][0]["pii_count"] > 0

    assert main(
        ["scrub", str(source), "--out", str(out), "--db", str(db), "--json"]
    ) == 0
    scrubbed = json.loads(capsys.readouterr().out)
    assert scrubbed["results"][0]["status"] == "success"
    assert scrubbed["results"][0]["verified_clean"] is True

    assert main(["report", "--db", str(db), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["stats"]["scrub_jobs"] == 1
    assert report["stats"]["scrub_verified"] == 1
    assert len(report["files"]) == 1


def test_report_csv_and_table(tmp_path, image_factory, add_metadata, capsys):
    source = add_metadata(image_factory(), {"Artist": "Alice"})
    db = tmp_path / "meta.db"
    assert main(["scan", str(source), "--db", str(db)]) == 0
    capsys.readouterr()

    assert main(["report", "--db", str(db), "--format", "csv"]) == 0
    csv_output = capsys.readouterr().out
    assert "id,path,type" in csv_output
    assert "Alice" not in csv_output

    assert main(["report", "--db", str(db), "--format", "table"]) == 0
    table_output = capsys.readouterr().out
    assert "Database summary" in table_output
    assert "PII by category" in table_output


def test_scan_skips_unknown_files(tmp_path, capsys):
    unknown = tmp_path / "notes.bin"
    unknown.write_bytes(b"not an image")
    db = tmp_path / "meta.db"
    assert main(["scan", str(tmp_path), "--db", str(db), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scanned"] == []
    assert payload["skipped"] == [str(unknown.resolve())]
