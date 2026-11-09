from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .models import MetaField, ScanResult, ScrubResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    detected_type TEXT NOT NULL,
    mime_type TEXT,
    width INTEGER,
    height INTEGER,
    captured_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    scan_error TEXT,
    scanned_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_type ON files(detected_type);

CREATE TABLE IF NOT EXISTS metadata_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    group_name TEXT NOT NULL DEFAULT '',
    tag TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    value_type TEXT NOT NULL DEFAULT 'string',
    is_pii INTEGER NOT NULL DEFAULT 0,
    pii_category TEXT,
    severity TEXT,
    UNIQUE(file_id, group_name, tag, value)
);
CREATE INDEX IF NOT EXISTS idx_fields_file ON metadata_fields(file_id);
CREATE INDEX IF NOT EXISTS idx_fields_pii ON metadata_fields(is_pii, pii_category);

CREATE TABLE IF NOT EXISTS scrub_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
    output_path TEXT NOT NULL,
    output_root TEXT NOT NULL,
    status TEXT NOT NULL,
    fields_removed INTEGER NOT NULL DEFAULT 0,
    image_hash_before TEXT,
    image_hash_after TEXT,
    verified_clean INTEGER,
    verify_error TEXT,
    error TEXT,
    scrubbed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_file ON scrub_jobs(file_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON scrub_jobs(status);

CREATE VIEW IF NOT EXISTS file_pii_summary AS
SELECT
    mf.file_id AS file_id,
    mf.pii_category AS category,
    mf.severity AS severity,
    COUNT(*) AS field_count
FROM metadata_fields mf
WHERE mf.is_pii = 1
GROUP BY mf.file_id, mf.pii_category, mf.severity;

CREATE VIEW IF NOT EXISTS file_pii_totals AS
SELECT
    file_id,
    COUNT(*) AS pii_count,
    MAX(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AS severity_rank
FROM metadata_fields
WHERE is_pii = 1
GROUP BY file_id;
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            try:
                self.conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.executescript(SCHEMA)
            self.conn.execute("PRAGMA user_version=1")
            self.conn.commit()
        self._secure_permissions()

    def _secure_permissions(self) -> None:
        if str(self.path) == ":memory:" or os.name == "nt":
            return
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            try:
                if candidate.exists():
                    os.chmod(candidate, 0o600)
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def upsert_file(self, scan: ScanResult) -> int:
        payload = json.dumps(scan.metadata_json, ensure_ascii=False, sort_keys=True)
        with self._lock, self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO files (
                    path, sha256, size_bytes, detected_type, mime_type,
                    width, height, captured_at, metadata_json, scan_error, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    sha256=excluded.sha256,
                    size_bytes=excluded.size_bytes,
                    detected_type=excluded.detected_type,
                    mime_type=excluded.mime_type,
                    width=excluded.width,
                    height=excluded.height,
                    captured_at=excluded.captured_at,
                    metadata_json=excluded.metadata_json,
                    scan_error=excluded.scan_error,
                    scanned_at=excluded.scanned_at
                RETURNING id
                """,
                (
                    str(scan.path),
                    scan.sha256,
                    scan.size_bytes,
                    scan.detected.file_type,
                    scan.detected.mime_type,
                    scan.width,
                    scan.height,
                    scan.captured_at,
                    payload,
                    scan.error,
                    utc_now(),
                ),
            )
            row = cursor.fetchone()
            file_id = int(row[0])
            self.conn.execute(
                "DELETE FROM metadata_fields WHERE file_id = ?", (file_id,)
            )
            self._insert_fields(file_id, scan.fields)
        self._secure_permissions()
        return file_id

    def _insert_fields(self, file_id: int, fields: Iterable[MetaField]) -> None:
        rows = [
            (
                file_id,
                field.group,
                field.tag,
                field.value,
                field.value_type,
                1 if field.is_pii else 0,
                field.pii_category,
                field.severity,
            )
            for field in fields
        ]
        if rows:
            self.conn.executemany(
                """
                INSERT OR IGNORE INTO metadata_fields (
                    file_id, group_name, tag, value, value_type,
                    is_pii, pii_category, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def record_scrub(self, file_id: int, result: ScrubResult, output_root: Path) -> int:
        with self._lock, self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO scrub_jobs (
                    file_id, output_path, output_root, status, fields_removed,
                    image_hash_before, image_hash_after, verified_clean,
                    verify_error, error, scrubbed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    str(result.output) if result.output else "",
                    str(output_root),
                    result.status,
                    result.fields_removed,
                    result.image_hash_before,
                    result.image_hash_after,
                    1 if result.verified_clean else (0 if result.verified_clean is False else None),
                    ", ".join(result.residual_fields) if result.residual_fields else None,
                    result.error,
                    utc_now(),
                ),
            )
            job_id = int(cursor.lastrowid)
        self._secure_permissions()
        return job_id

    def get_file(self, file_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM files WHERE id = ?", (file_id,)
            ).fetchone()
            if row is None:
                return None
            data = dict(row)
            data["metadata_json"] = json.loads(data["metadata_json"] or "{}")
            data["fields"] = self.get_fields(file_id)
            data["pii_summary"] = self.pii_summary(file_id)
        return data

    def get_file_by_path(self, path: str | Path) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM files WHERE path = ?", (str(Path(path).resolve()),)
            ).fetchone()
        if row is None:
            return None
        return self.get_file(int(row[0]))

    def get_fields(self, file_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT group_name, tag, value, value_type,
                       is_pii, pii_category, severity
                FROM metadata_fields
                WHERE file_id = ?
                ORDER BY is_pii DESC, pii_category, group_name, tag
                """,
                (file_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def pii_summary(self, file_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT category, severity, field_count
                FROM file_pii_summary
                WHERE file_id = ?
                ORDER BY severity, category
                """,
                (file_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_files(
        self,
        search: str | None = None,
        file_type: str | None = None,
        pii_category: str | None = None,
        severity: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if search:
            clauses.append("f.path LIKE ?")
            params.append(f"%{search}%")
        if file_type:
            clauses.append("f.detected_type = ?")
            params.append(file_type.upper())
        if pii_category:
            clauses.append(
                "EXISTS (SELECT 1 FROM metadata_fields m WHERE m.file_id = f.id "
                "AND m.is_pii = 1 AND m.pii_category = ?)"
            )
            params.append(pii_category)
        if severity:
            clauses.append(
                "EXISTS (SELECT 1 FROM metadata_fields m WHERE m.file_id = f.id "
                "AND m.is_pii = 1 AND m.severity = ?)"
            )
            params.append(severity)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
            SELECT f.id, f.path, f.detected_type, f.mime_type, f.size_bytes,
                   f.width, f.height, f.captured_at, f.scanned_at, f.scan_error,
                   COALESCE(SUM(CASE WHEN mf.is_pii = 1 THEN 1 ELSE 0 END), 0) AS pii_count,
                   GROUP_CONCAT(DISTINCT CASE WHEN mf.is_pii = 1 THEN mf.pii_category END)
                       AS pii_categories
            FROM files f
            LEFT JOIN metadata_fields mf ON mf.file_id = f.id
            {where}
            GROUP BY f.id
            ORDER BY pii_count DESC, f.path
            LIMIT ?
        """
        params.append(limit)
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            data = dict(row)
            categories = data.get("pii_categories")
            data["pii_categories"] = categories.split(",") if categories else []
            results.append(data)
        return results

    def list_jobs(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT j.*, f.path AS source_path, f.detected_type
                FROM scrub_jobs j
                LEFT JOIN files f ON f.id = j.file_id
                ORDER BY j.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_job(self, job_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT j.*, f.path AS source_path, f.detected_type
                FROM scrub_jobs j
                LEFT JOIN files f ON f.id = j.file_id
                WHERE j.id = ?
                """,
                (job_id,),
            ).fetchone()
        return dict(row) if row else None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total_files = self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            total_fields = self.conn.execute(
                "SELECT COUNT(*) FROM metadata_fields"
            ).fetchone()[0]
            pii_fields = self.conn.execute(
                "SELECT COUNT(*) FROM metadata_fields WHERE is_pii = 1"
            ).fetchone()[0]
            files_with_pii = self.conn.execute(
                "SELECT COUNT(DISTINCT file_id) FROM metadata_fields WHERE is_pii = 1"
            ).fetchone()[0]
            jobs = self.conn.execute("SELECT COUNT(*) FROM scrub_jobs").fetchone()[0]
            verified = self.conn.execute(
                "SELECT COUNT(*) FROM scrub_jobs WHERE verified_clean = 1"
            ).fetchone()[0]
            failed = self.conn.execute(
                "SELECT COUNT(*) FROM scrub_jobs WHERE status != 'success'"
            ).fetchone()[0]
            by_type = self.conn.execute(
                "SELECT detected_type, COUNT(*) AS count FROM files "
                "GROUP BY detected_type ORDER BY count DESC"
            ).fetchall()
            by_category = self.conn.execute(
                "SELECT pii_category AS category, severity, COUNT(*) AS count "
                "FROM metadata_fields WHERE is_pii = 1 "
                "GROUP BY pii_category, severity ORDER BY count DESC"
            ).fetchall()
        return {
            "total_files": total_files,
            "total_fields": total_fields,
            "pii_fields": pii_fields,
            "files_with_pii": files_with_pii,
            "scrub_jobs": jobs,
            "scrub_verified": verified,
            "scrub_failed": failed,
            "by_type": [dict(row) for row in by_type],
            "by_category": [dict(row) for row in by_category],
        }

    def recent_files(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.list_files(limit=limit)

    def delete_file(self, file_id: int) -> bool:
        with self._lock, self.conn:
            cursor = self.conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            deleted = cursor.rowcount > 0
        self._secure_permissions()
        return deleted
