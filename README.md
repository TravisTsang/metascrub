---
title: metascrub
sdk: docker
app_port: 7860
---

# metascrub

Extract image metadata, classify personally identifiable information (PII), store
everything in SQLite, and write metadata-free copies of images.

Extraction and stripping are performed by [ExifTool](https://exiftool.org/), so
operations are lossless: image pixels are never re-encoded. Originals are never
modified.

## Supported formats

JPEG, PNG, TIFF, HEIC/HEIF, WebP, AVIF, GIF, BMP, SVG, and TIFF-based RAW formats
(DNG, CR2, CR3, NEF, ARW, RAF, ORF, RW2, PEF, SRW, 3FR, IIQ, X3F).

RAW files are extracted but skipped during scrubbing by default because their
metadata is often required for rendering. Use `--allow-raw-scrub` to override.

## Install

System dependency:

```bash
sudo apt-get update
sudo apt-get install -y libimage-exiftool-perl
```

Python environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Verify the setup:

```bash
.venv/bin/metascrub doctor
```

If sudo is unavailable, the same apt package can be fetched and unpacked locally;
`metascrub` automatically finds `.tools/exiftool/usr/bin/exiftool` and sets
`PERL5LIB` for it:

```bash
mkdir -p .tools/exiftool
cd .tools/exiftool
apt-get download libimage-exiftool-perl
dpkg-deb -x libimage-exiftool-perl_*_all.deb .
cd ../..
```

You can also point at any ExifTool binary with `METASCRUB_EXIFTOOL=/path/to/exiftool`.

## CLI

```bash
# Index metadata and PII findings
metascrub scan ~/Pictures --db metascrub.db

# Write scrubbed copies (originals untouched)
metascrub scrub ~/Pictures --out ~/Pictures-scrubbed --db metascrub.db

# Inspect results
metascrub report --db metascrub.db
metascrub report --db metascrub.db --format json
metascrub report --db metascrub.db --format csv --pii-only
```

Useful scrub options:

| Option | Meaning |
| --- | --- |
| `--dry-run` | Show what would happen without writing files |
| `--overwrite` | Replace existing output files |
| `--allow-raw-scrub` | Attempt RAW stripping (may break rendering) |
| `--scrub-sidecars` | Copy and strip `.xmp` sidecars instead of omitting them |
| `--neutralize-times` | Set output timestamps to a fixed neutral time |
| `--no-recursive` | Do not descend into directories |

## Web GUI

```bash
metascrub gui --db metascrub.db
```

Open <http://127.0.0.1:8765>. The app has two pages:

**Scrub** (`/`)

1. Drop or choose an image.
2. The uploaded image is displayed immediately as a preview.
3. It is scrubbed automatically and a **Download scrubbed image** button appears.
   The original file is never modified.
4. A side panel lists the categories of PII that were removed (location,
   owner/identity, date/time, device, free text, embedded media), the metadata
   that remains in the scrubbed copy, and what that file type typically contains.

**Extract** (`/extract`)

1. Drop or choose one or more images.
2. Every embedded metadata field is shown with its group, tag, value, PII
   category, and severity; PII rows are highlighted.
3. The page reports dimensions, size, capture time, PII totals/categories, and
   any ExifTool warnings. The extracted data can be downloaded as JSON.

Uploads are saved to `uploads/` next to the database and scrubbed copies to
`uploads/scrubbed/`. Use `--upload-dir` to change the location:

```bash
metascrub gui --db metascrub.db --upload-dir ~/metascrub-uploads
```

The GUI is backed by the same JSON API (useful for scripts):

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | ExifTool/database status |
| POST | `/api/extract-upload` | Upload images and return all extracted metadata fields |
| POST | `/api/scrub-upload` | Upload and scrub images; returns preview/download URLs |
| GET | `/api/files/{id}/preview` | Inline preview of an uploaded image |
| POST | `/api/scan` | Scan a file or directory |
| GET | `/api/files` | List indexed files (filters: search, type, category, severity) |
| GET | `/api/files/{id}` | File details, metadata fields, PII summary |
| DELETE | `/api/files/{id}` | Remove a file from the index |
| POST | `/api/scrub` | Scrub selected file IDs |
| GET | `/api/jobs` | Scrub-job history |
| GET | `/api/jobs/{id}` | Scrub-job detail |
| GET | `/api/jobs/{id}/download` | Download a scrubbed output |
| GET | `/api/report` | Stats plus all indexed files (JSON) |


## What gets removed

- GPS coordinates and location tags
- Artist, creator, owner, copyright, contact details
- Camera/lens serial numbers (including body serial numbers), make/model, software
- Capture and modification timestamps
- Comments, descriptions, keywords, titles (including `UserComment` and `dc:description`)
- Embedded thumbnails and previews (including `IFD1` thumbnails)
- XMP metadata (`dc:creator`, `dc:description`, `dc:rights`, `CreatorTool`)
- XMP sidecars (omitted from output by default)
- SVG `<metadata>`, `<title>`, `<desc>`, comments, and editor-specific attributes

This applies across JPEG, PNG, TIFF, WebP, HEIC/HEIF, AVIF, GIF, BMP, SVG, and
RAW files (RAW scrubbing remains opt-in). WebP files are handled like JPEG/TIFF:
EXIF and XMP chunks are stripped, including GPS, timestamps, creator/owner,
serial numbers, make/model, software, comments, descriptions, and `IFD1`
thumbnails.

By default `Orientation` and ICC/color-space tags are preserved so images do not
rotate or shift color. Absolute stripping is possible through the library options
(`keep_orientation=False`, `keep_color=False`).

Every scrubbed copy is verified automatically: it is re-scanned for embedded PII,
validated with `exiftool -validate`, and its image-data hash is compared with the
source when the format supports it. Verification results are stored in the
`scrub_jobs` table.

## Database

SQLite is created with mode `0600` because it contains extracted PII. Tables:

- `files` — path, SHA-256, type, dimensions, capture date, raw metadata JSON
- `metadata_fields` — normalized `group`, `tag`, `value`, PII category and severity
- `scrub_jobs` — output path, status, removed-field count, hashes, verification

Useful views: `file_pii_summary`, `file_pii_totals`.

## Other notes

- Originals are never modified; output goes to the directory passed with `--out`.
- The tool removes embedded metadata only. It does not detect faces, text rendered
  into pixels, or PII in filenames/directory names.
- Protect `metascrub.db`: it is a PII inventory by design.
- RAW scrubbing is opt-in and may make files unreadable by some software.
