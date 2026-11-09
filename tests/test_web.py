from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from metascrub.models import ScrubResult
from metascrub.web.app import create_app


@pytest.fixture
def client(tmp_path, image_factory, add_metadata, pii_metadata):
    source = add_metadata(image_factory(), pii_metadata)
    app = create_app(tmp_path / "web.db")
    with TestClient(app) as test_client:
        yield test_client, source, tmp_path


def _scan(client: TestClient, source):
    response = client.post(
        "/api/scan", json={"path": str(source), "recursive": False}
    )
    assert response.status_code == 200
    return response.json()


def test_health_endpoint(client):
    test_client, _, _ = client
    response = test_client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["exiftool_version"]


def test_index_page_shows_dropzone(client):
    test_client, _, _ = client
    response = test_client.get("/")
    assert response.status_code == 200
    assert 'id="dropzone"' in response.text
    assert "/api/scrub-upload" in response.text
    assert "Download scrubbed image" in response.text
    assert 'badge("scrubbed"' not in response.text
    assert 'badge("verified clean"' not in response.text
    assert "Typical metadata for" in response.text
    assert "Removed" in response.text
    assert "Remains" in response.text
    assert 'href="/extract"' in response.text


def test_extract_page_shows_dropzone(client):
    test_client, _, _ = client
    response = test_client.get("/extract")
    assert response.status_code == 200
    assert 'id="extract-dropzone"' in response.text
    assert "/api/extract-upload" in response.text
    assert "Download JSON" in response.text
    assert 'href="/extract"' in response.text
    assert 'aria-current="page"' in response.text


def test_extract_upload_returns_metadata(client):
    test_client, source, _ = client
    response = test_client.post(
        "/api/extract-upload",
        files=[("files", ("photo.jpg", source.read_bytes(), "image/jpeg"))],
    )
    assert response.status_code == 200
    entry = response.json()["results"][0]
    assert entry["status"] == "success"
    assert entry["name"] == "photo.jpg"
    assert entry["type"] == "JPEG"
    assert entry["pii_count"] > 0
    assert entry["width"] == 32
    assert entry["height"] == 24
    assert entry["captured_at"].startswith("2024:01:02")
    assert entry["preview_url"]

    fields = entry["fields"]
    artist = next(field for field in fields if field["tag"] == "Artist")
    assert artist["value"] == "Alice Example"
    assert artist["is_pii"] is True
    assert artist["category"] == "identity"
    assert artist["category_label"] == "Owner/identity"
    assert artist["severity"] in {"high", "medium", "low"}

    gps = next(field for field in fields if field["tag"] == "GPSLatitude")
    assert gps["category"] == "location"
    assert gps["category_label"] == "Location"
    assert any(field["group"] == "File" for field in fields)
    assert not any(field["group"] == "System" for field in fields)

    labels = {item["label"] for item in entry["pii_categories"]}
    assert {"Location", "Owner/identity", "Device", "Date/time", "Free text"} <= labels

    preview = test_client.get(entry["preview_url"])
    assert preview.status_code == 200
    assert preview.headers["content-type"].startswith("image/")


def test_extract_upload_reports_unknown_files(client):
    test_client, _, _ = client
    response = test_client.post(
        "/api/extract-upload",
        files=[("files", ("notes.txt", b"not an image", "text/plain"))],
    )
    assert response.status_code == 200
    entry = response.json()["results"][0]
    assert entry["status"] == "unsupported"
    assert entry["fields"] == []
    assert entry["preview_url"] is None


def test_extract_upload_sanitizes_filename(client):
    test_client, source, _ = client
    response = test_client.post(
        "/api/extract-upload",
        files=[("files", ("../../evil.jpg", source.read_bytes(), "image/jpeg"))],
    )
    assert response.status_code == 200
    entry = response.json()["results"][0]
    assert entry["name"] == "evil.jpg"
    uploaded = Path(test_client.app.state.db.get_file(entry["file_id"])["path"])
    assert uploaded.parent == test_client.app.state.upload_dir


def test_scrub_upload_returns_preview_and_download(client):
    test_client, source, _ = client
    response = test_client.post(
        "/api/scrub-upload",
        files=[("files", ("photo.jpg", source.read_bytes(), "image/jpeg"))],
    )
    assert response.status_code == 200
    entry = response.json()["results"][0]
    assert entry["status"] == "success"
    assert entry["verified_clean"] is True
    assert entry["download_url"]
    assert entry["preview_url"]

    labels = {item["label"] for item in entry["removed_categories"]}
    assert {"Location", "Owner/identity", "Device", "Date/time", "Free text"} <= labels
    assert entry["remaining_metadata"]
    remaining_tags = {field["tag"].lower() for field in entry["remaining_metadata"]}
    assert "artist" not in remaining_tags
    assert "gpslatitude" not in remaining_tags
    assert entry["typical_metadata"]
    assert any("GPS" in item for item in entry["typical_metadata"])

    preview = test_client.get(entry["preview_url"])
    assert preview.status_code == 200
    assert preview.headers["content-type"].startswith("image/")

    download = test_client.get(entry["download_url"])
    assert download.status_code == 200
    assert len(download.content) > 0

    uploaded = Path(test_client.app.state.db.get_file(entry["file_id"])["path"])
    assert uploaded.parent == test_client.app.state.upload_dir


def test_scrub_upload_reports_unknown_files(client):
    test_client, _, _ = client
    response = test_client.post(
        "/api/scrub-upload",
        files=[("files", ("notes.txt", b"not an image", "text/plain"))],
    )
    assert response.status_code == 200
    entry = response.json()["results"][0]
    assert entry["status"] == "unsupported"
    assert entry["download_url"] is None


def test_scrub_upload_sanitizes_filename(client):
    test_client, source, _ = client
    response = test_client.post(
        "/api/scrub-upload",
        files=[("files", ("../../evil.jpg", source.read_bytes(), "image/jpeg"))],
    )
    assert response.status_code == 200
    entry = response.json()["results"][0]
    assert entry["name"] == "evil.jpg"
    uploaded = Path(test_client.app.state.db.get_file(entry["file_id"])["path"])
    assert uploaded.parent == test_client.app.state.upload_dir


def test_scan_and_files_endpoints(client):
    test_client, source, _ = client
    payload = _scan(test_client, source)
    assert len(payload["scanned"]) == 1
    assert payload["scanned"][0]["pii_count"] > 0

    response = test_client.get("/api/files")
    assert response.status_code == 200
    files = response.json()
    assert len(files) == 1
    assert files[0]["path"] == str(source.resolve())

    filtered = test_client.get("/api/files", params={"type": "JPEG"}).json()
    assert len(filtered) == 1
    filtered = test_client.get("/api/files", params={"category": "location"}).json()
    assert len(filtered) == 1
    filtered = test_client.get("/api/files", params={"severity": "high"}).json()
    assert len(filtered) == 1


def test_file_detail_and_delete_endpoints(client):
    test_client, source, _ = client
    _scan(test_client, source)
    file_id = test_client.get("/api/files").json()[0]["id"]

    detail = test_client.get(f"/api/files/{file_id}")
    assert detail.status_code == 200
    assert detail.json()["fields"]
    assert detail.json()["pii_summary"]

    assert test_client.delete(f"/api/files/{file_id}").status_code == 200
    assert test_client.get(f"/api/files/{file_id}").status_code == 404
    assert test_client.delete(f"/api/files/{file_id}").status_code == 404


def test_scrub_jobs_and_download_endpoints(client):
    test_client, source, tmp_path = client
    _scan(test_client, source)
    file_id = test_client.get("/api/files").json()[0]["id"]
    output_dir = tmp_path / "out"

    response = test_client.post(
        "/api/scrub",
        json={"file_ids": [file_id], "output_dir": str(output_dir)},
    )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["status"] == "success"
    assert result["verified_clean"] is True

    jobs = test_client.get("/api/jobs").json()
    assert len(jobs) == 1
    job_id = jobs[0]["id"]

    job = test_client.get(f"/api/jobs/{job_id}")
    assert job.status_code == 200
    assert job.json()["verified_clean"] == 1

    download = test_client.get(f"/api/jobs/{job_id}/download")
    assert download.status_code == 200
    assert len(download.content) == (output_dir / source.name).stat().st_size


def test_report_endpoint(client):
    test_client, source, _ = client
    _scan(test_client, source)
    report = test_client.get("/api/report")
    assert report.status_code == 200
    assert report.json()["stats"]["total_files"] == 1


def test_error_responses(client):
    test_client, _, tmp_path = client

    assert (
        test_client.post("/api/scan", json={"path": str(tmp_path / "nope")}).status_code
        == 400
    )
    assert test_client.get("/api/files/99999").status_code == 404
    assert test_client.get("/api/jobs/99999").status_code == 404
    assert test_client.get("/api/jobs/99999/download").status_code == 404
    assert (
        test_client.post(
            "/api/scrub", json={"file_ids": [], "output_dir": str(tmp_path / "out")}
        ).status_code
        == 400
    )
    assert (
        test_client.post(
            "/api/scrub",
            json={"file_ids": [99999], "output_dir": str(tmp_path / "out")},
        ).status_code
        == 404
    )


def test_download_rejects_path_outside_output_root(client):
    test_client, source, tmp_path = client
    _scan(test_client, source)
    file_id = test_client.get("/api/files").json()[0]["id"]

    outside = tmp_path / "outside.jpg"
    outside.write_bytes(b"outside")
    result = ScrubResult(
        source=source,
        output=outside,
        status="success",
        fields_removed=1,
        verified_clean=True,
    )
    job_id = test_client.app.state.db.record_scrub(
        file_id, result, tmp_path / "allowed-out"
    )
    response = test_client.get(f"/api/jobs/{job_id}/download")
    assert response.status_code == 403
