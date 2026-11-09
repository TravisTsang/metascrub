from __future__ import annotations

import shutil
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..db import Database
from ..detector import detect_file
from ..extractor import build_scan_result, exiftool_version, extract_many, find_exiftool
from ..models import ScrubOptions
from ..pii import is_embedded
from ..pipeline import scan_paths, scrub_paths
from ..scrubber import scrub_file

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_CATEGORY_LABELS = {
    "location": "Location",
    "identity": "Owner/identity",
    "device": "Device",
    "temporal": "Date/time",
    "free_text": "Free text",
    "embedded_media": "Embedded media",
    "filesystem": "Filesystem",
    "structural": "Structural",
}

_RAW_TYPES = {
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

_RAW_TYPICAL = [
    "EXIF: GPS location and altitude",
    "EXIF: capture/edit timestamps",
    "EXIF: Artist, copyright, owner, UserComment, ImageDescription",
    "EXIF: Make/Model, body and lens serial numbers, Software",
    "Maker notes (camera/lens serials and settings)",
    "Embedded preview image",
    "XMP/IPTC: creator, description, rights, keywords",
    "ICC color profile",
]

_TYPICAL_METADATA: dict[str, list[str]] = {
    "JPEG": [
        "EXIF: GPS location and altitude",
        "EXIF: DateTimeOriginal and other capture/edit dates",
        "EXIF: Artist, Copyright, OwnerName, UserComment, ImageDescription",
        "EXIF: Make/Model, body and lens serial numbers, Software",
        "EXIF: embedded thumbnail (IFD1)",
        "XMP/IPTC: dc:creator, dc:description, dc:rights, keywords",
        "ICC color profile",
    ],
    "PNG": [
        "PNG text chunks: Author, Comment, Copyright, Software, Creation Time",
        "EXIF: GPS, dates, Artist, Make/Model, serial numbers",
        "XMP: dc:creator, dc:description, dc:rights",
        "Resolution and gamma values",
        "ICC color profile",
    ],
    "TIFF": [
        "EXIF: GPS location and altitude",
        "EXIF: capture/edit timestamps",
        "EXIF: Artist, Copyright, OwnerName, UserComment, ImageDescription",
        "EXIF: Make/Model, body and lens serial numbers, Software",
        "IFD1 embedded thumbnail",
        "IPTC/XMP: creator, description, rights, keywords",
        "ICC color profile",
    ],
    "HEIC": [
        "EXIF: GPS, dates, Artist, Make/Model, serial numbers, Software",
        "XMP: dc:creator, dc:description, dc:rights",
        "Camera maker notes",
        "Item and item-property metadata",
        "ICC color profile",
    ],
    "HEIF": [
        "EXIF: GPS, dates, Artist, Make/Model, serial numbers, Software",
        "XMP: dc:creator, dc:description, dc:rights",
        "Camera maker notes",
        "Item and item-property metadata",
        "ICC color profile",
    ],
    "WEBP": [
        "EXIF: GPS location and altitude",
        "EXIF: DateTimeOriginal and other capture/edit dates",
        "EXIF: Artist, Copyright, OwnerName, UserComment, ImageDescription",
        "EXIF: Make/Model, body and lens serial numbers, Software",
        "EXIF: embedded thumbnail (IFD1)",
        "XMP: dc:creator, dc:description, dc:rights",
        "Animation metadata",
        "ICC color profile",
    ],
    "AVIF": [
        "EXIF: GPS, dates, Artist, Make/Model, serial numbers, Software",
        "XMP: dc:creator, dc:description, dc:rights",
        "HDR metadata",
        "Camera maker notes",
        "ICC color profile",
    ],
    "GIF": [
        "Comment blocks (can contain names/contact details)",
        "XMP: creator, description, rights, GPS, dates, serial numbers",
        "Application extensions",
        "Frame timing",
        "ICC color profile",
    ],
    "BMP": [
        "File header and resolution fields",
        "ICC color profile (can include copyright/creator)",
        "Palette information",
    ],
    "SVG": [
        "<metadata> blocks (RDF/XML)",
        "<title> and <desc> text",
        "Editor attributes (Inkscape/Sodipodi)",
        "Comments and processing instructions",
        "XML namespace declarations",
    ],
    "UNKNOWN": ["Unknown format"],
}
for _raw_type in _RAW_TYPES:
    _TYPICAL_METADATA[_raw_type] = _RAW_TYPICAL


class ScanRequest(BaseModel):
    path: str
    recursive: bool = True


class ScrubRequest(BaseModel):
    file_ids: list[int]
    output_dir: str
    overwrite: bool = False
    dry_run: bool = False
    allow_raw_scrub: bool = False
    scrub_sidecars: bool = False
    neutralize_times: bool = False


def _safe_upload_name(filename: str) -> str:
    name = (filename or "upload").replace("\\", "/").replace("\x00", "")
    name = Path(name).name.strip()
    return name or "upload"


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem = candidate.stem or "upload"
    suffix = candidate.suffix
    counter = 1
    while True:
        candidate = directory / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _save_upload(upload: UploadFile, directory: Path) -> Path:
    name = _safe_upload_name(upload.filename or "upload")
    destination = _unique_path(directory, name)
    with destination.open("wb") as handle:
        shutil.copyfileobj(upload.file, handle)
    return destination


def _scan_payload(outcome) -> dict[str, Any]:
    scan = outcome.scan
    return {
        "file_id": outcome.file_id,
        "path": str(scan.path),
        "type": scan.detected.file_type,
        "mime_type": scan.detected.mime_type,
        "size_bytes": scan.size_bytes,
        "width": scan.width,
        "height": scan.height,
        "captured_at": scan.captured_at,
        "pii_count": len(scan.pii_fields),
        "pii_categories": scan.pii_categories,
        "pii_fields": [
            {
                "group": field.group,
                "tag": field.tag,
                "category": field.pii_category,
                "severity": field.severity,
            }
            for field in scan.pii_fields
        ],
        "warnings": scan.warnings,
        "error": scan.error,
    }


def _extract_payload(outcome) -> dict[str, Any]:
    scan = outcome.scan
    fields = [
        {
            "group": field.group,
            "tag": field.tag,
            "value": field.value,
            "value_type": field.value_type,
            "is_pii": field.is_pii,
            "category": field.pii_category,
            "category_label": (
                _CATEGORY_LABELS.get(field.pii_category, field.pii_category.title())
                if field.pii_category
                else None
            ),
            "severity": field.severity,
        }
        for field in scan.fields
        if (field.group or "").strip().lower() not in ("system", "exiftool")
    ]
    pii_fields = [field for field in fields if field["is_pii"]]
    categories = sorted(
        {field["category"] for field in pii_fields if field["category"]}
    )
    return {
        "file_id": outcome.file_id,
        "name": scan.path.name,
        "type": scan.detected.file_type,
        "mime_type": scan.detected.mime_type,
        "size_bytes": scan.size_bytes,
        "width": scan.width,
        "height": scan.height,
        "captured_at": scan.captured_at,
        "sha256": scan.sha256,
        "pii_count": len(pii_fields),
        "pii_categories": [
            {
                "category": category,
                "label": _CATEGORY_LABELS.get(category, category.title()),
            }
            for category in categories
        ],
        "fields": fields,
        "warnings": scan.warnings,
        "error": scan.error,
        "preview_url": f"/api/files/{outcome.file_id}/preview",
    }


def _removed_categories(scan) -> list[dict[str, Any]]:
    counts = Counter(
        field.pii_category
        for field in scan.pii_fields
        if is_embedded(field) and field.pii_category
    )
    return [
        {
            "category": category,
            "label": _CATEGORY_LABELS.get(category, category.title()),
            "count": count,
        }
        for category, count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]


def _remaining_metadata(path: Path) -> list[dict[str, str]]:
    detected = detect_file(path)
    dumps = extract_many([path])
    dump = dumps.get(path.resolve())
    if dump is None:
        return []
    scan = build_scan_result(path, dump, detected)
    seen: set[tuple[str, str]] = set()
    remaining: list[dict[str, str]] = []
    for field in scan.fields:
        group = (field.group or "").strip()
        if group.lower() in ("system", "file", "exiftool", "composite"):
            continue
        if not is_embedded(field):
            continue
        key = (group, field.tag)
        if key in seen:
            continue
        seen.add(key)
        remaining.append({"group": group, "tag": field.tag})
    return remaining


def _scrub_payload(result) -> dict[str, Any]:
    return {
        "source": str(result.source),
        "output": str(result.output) if result.output else None,
        "status": result.status,
        "fields_removed": result.fields_removed,
        "verified_clean": result.verified_clean,
        "image_hash_before": result.image_hash_before,
        "image_hash_after": result.image_hash_after,
        "residual_fields": result.residual_fields,
        "notes": result.notes,
        "error": result.error,
    }


def create_app(
    db_path: str | Path = "metascrub.db",
    upload_dir: str | Path | None = None,
) -> FastAPI:
    database = Database(db_path)
    if upload_dir is None:
        upload_root = Path(db_path).expanduser().resolve().parent / "uploads"
    else:
        upload_root = Path(upload_dir).expanduser().resolve()
    scrub_root = upload_root / "scrubbed"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.db.close()

    app = FastAPI(title="metascrub", version="0.1.0", lifespan=lifespan)
    app.state.db = database
    app.state.db_path = str(db_path)
    app.state.upload_dir = upload_root
    app.state.scrub_dir = scrub_root
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

    @app.get("/")
    def index(request: Request):
        return templates.TemplateResponse(request=request, name="index.html", context={})

    @app.get("/extract")
    def extract(request: Request):
        return templates.TemplateResponse(
            request=request, name="extract.html", context={}
        )

    @app.post("/api/extract-upload")
    def api_extract_upload(files: Annotated[list[UploadFile], File(...)]):
        db: Database = app.state.db
        upload_root.mkdir(parents=True, exist_ok=True)
        entries: list[dict[str, Any]] = []

        for upload in files:
            destination = _save_upload(upload, upload_root)
            outcomes, _ = scan_paths([destination], db, recursive=False)
            if not outcomes:
                entries.append(
                    {
                        "name": destination.name,
                        "type": "UNKNOWN",
                        "status": "unsupported",
                        "preview_url": None,
                        "fields": [],
                        "pii_count": 0,
                        "pii_categories": [],
                        "warnings": [],
                        "error": "Unsupported or unrecognized image type.",
                    }
                )
                continue

            payload = _extract_payload(outcomes[0])
            payload["status"] = "error" if payload["error"] else "success"
            entries.append(payload)

        return {"results": entries}

    @app.post("/api/scrub-upload")
    def api_scrub_upload(files: Annotated[list[UploadFile], File(...)]):
        db: Database = app.state.db
        upload_root.mkdir(parents=True, exist_ok=True)
        options = ScrubOptions(output_root=scrub_root, overwrite=True)
        entries: list[dict[str, Any]] = []

        for upload in files:
            destination = _save_upload(upload, upload_root)
            outcomes, _ = scan_paths([destination], db, recursive=False)
            if not outcomes:
                entries.append(
                    {
                        "name": destination.name,
                        "type": "UNKNOWN",
                        "status": "unsupported",
                        "preview_url": None,
                        "download_url": None,
                        "removed_categories": [],
                        "remaining_metadata": [],
                        "typical_metadata": _TYPICAL_METADATA["UNKNOWN"],
                        "error": "Unsupported or unrecognized image type.",
                    }
                )
                continue

            outcome = outcomes[0]
            scan = outcome.scan
            result = scrub_file(scan, options, relative_to=destination.parent)
            job_id = db.record_scrub(outcome.file_id, result, options.output_root)
            entries.append(
                {
                    "name": destination.name,
                    "file_id": outcome.file_id,
                    "job_id": job_id,
                    "type": scan.detected.file_type,
                    "status": result.status,
                    "verified_clean": result.verified_clean,
                    "fields_removed": result.fields_removed,
                    "pii_count": len(scan.pii_fields),
                    "removed_categories": (
                        _removed_categories(scan) if result.status == "success" else []
                    ),
                    "remaining_metadata": (
                        _remaining_metadata(result.output) if result.output else []
                    ),
                    "typical_metadata": _TYPICAL_METADATA.get(
                        scan.detected.file_type, _TYPICAL_METADATA["UNKNOWN"]
                    ),
                    "preview_url": f"/api/files/{outcome.file_id}/preview",
                    "download_url": (
                        f"/api/jobs/{job_id}/download" if result.output else None
                    ),
                    "notes": result.notes,
                    "error": result.error,
                }
            )

        return {"results": entries}

    @app.get("/api/files/{file_id}/preview")
    def api_preview(file_id: int):
        file = app.state.db.get_file(file_id)
        if file is None:
            raise HTTPException(status_code=404, detail="File not found")
        path = Path(file["path"])
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Preview not found")
        return FileResponse(path)

    @app.post("/api/scan")
    def api_scan(payload: ScanRequest):
        db: Database = app.state.db
        path = Path(payload.path).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail=f"Path does not exist: {path}")
        outcomes, skipped = scan_paths(
            [path], db, recursive=payload.recursive, exclude_roots=[app.state.db_path]
        )
        return {"scanned": [_scan_payload(outcome) for outcome in outcomes], "skipped": skipped}

    @app.get("/api/files")
    def api_files(
        search: str | None = None,
        type: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        limit: int = 500,
    ):
        return app.state.db.list_files(
            search=search,
            file_type=type,
            pii_category=category,
            severity=severity,
            limit=limit,
        )

    @app.get("/api/files/{file_id}")
    def api_file(file_id: int):
        file = app.state.db.get_file(file_id)
        if file is None:
            raise HTTPException(status_code=404, detail="File not found")
        return file

    @app.delete("/api/files/{file_id}")
    def api_delete_file(file_id: int):
        deleted = app.state.db.delete_file(file_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="File not found")
        return {"deleted": file_id}

    @app.post("/api/scrub")
    def api_scrub(payload: ScrubRequest):
        db: Database = app.state.db
        if not payload.file_ids:
            raise HTTPException(status_code=400, detail="No file ids supplied")
        if not payload.output_dir.strip():
            raise HTTPException(status_code=400, detail="output_dir must not be empty")
        sources: list[Path] = []
        missing: list[int] = []
        for file_id in payload.file_ids:
            file = db.get_file(file_id)
            if file is None:
                missing.append(file_id)
                continue
            sources.append(Path(file["path"]))
        if missing:
            raise HTTPException(status_code=404, detail=f"Unknown file ids: {missing}")

        options = ScrubOptions(
            output_root=Path(payload.output_dir),
            overwrite=payload.overwrite,
            dry_run=payload.dry_run,
            allow_raw_scrub=payload.allow_raw_scrub,
            scrub_sidecars=payload.scrub_sidecars,
            neutralize_times=payload.neutralize_times,
        )
        results, skipped = scrub_paths(sources, db, options, recursive=False)
        return {
            "results": [_scrub_payload(result) for result in results],
            "skipped": skipped,
        }

    @app.get("/api/jobs")
    def api_jobs(limit: int = 200):
        return app.state.db.list_jobs(limit)

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: int):
        job = app.state.db.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return job

    @app.get("/api/jobs/{job_id}/download")
    def api_download(job_id: int):
        job = app.state.db.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        output = Path(job["output_path"]).resolve()
        root = Path(job["output_root"]).resolve()
        if not output.exists() or not output.is_file():
            raise HTTPException(status_code=404, detail="Scrubbed file not found")
        try:
            if not output.is_relative_to(root):
                raise HTTPException(status_code=403, detail="Path outside output root")
        except ValueError:
            raise HTTPException(status_code=403, detail="Path outside output root")
        return FileResponse(output, filename=output.name)

    @app.get("/api/report")
    def api_report():
        db: Database = app.state.db
        return {"stats": db.stats(), "files": db.list_files(limit=10000)}

    @app.get("/api/health")
    def api_health():
        exiftool = find_exiftool()
        return {
            "status": "ok" if exiftool else "degraded",
            "exiftool": str(exiftool) if exiftool else None,
            "exiftool_version": exiftool_version(),
            "db_path": app.state.db_path,
        }

    @app.exception_handler(ValueError)
    def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app
