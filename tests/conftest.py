from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from PIL import Image

from metascrub.extractor import exiftool_env, exiftool_version, find_exiftool

PII_METADATA = {
    "Artist": "Alice Example",
    "OwnerName": "Alice",
    "SerialNumber": "SN-12345",
    "GPSLatitude": "51.5074",
    "GPSLongitude": "0.1278",
    "DateTimeOriginal": "2024:01:02 03:04:05",
    "Comment": "contact alice@example.com",
    "UserComment": "contact alice@example.com",
    "ImageDescription": "Alice at home",
    "Make": "Canon",
    "Model": "EOS R5",
    "Software": "Editor 1.0",
    "XMP-dc:Creator": "Alice XMP",
    "XMP-dc:Description": "Alice XMP description",
    "XMP-dc:Rights": "Alice rights",
    "XMP-xmp:CreatorTool": "XMP Editor 2.0",
}


@pytest.fixture(scope="session")
def exiftool() -> Path:
    path = find_exiftool()
    if path is None:
        pytest.skip("ExifTool is not installed")
    if exiftool_version() is None:
        pytest.skip("ExifTool is not runnable")
    return path


@pytest.fixture
def image_factory(tmp_path: Path):
    def make(
        name: str = "photo.jpg",
        fmt: str = "JPEG",
        size: tuple[int, int] = (32, 24),
        color: tuple[int, int, int] = (40, 120, 200),
        icc: bool = False,
    ) -> Path:
        path = tmp_path / name
        image = Image.new("RGB", size, color)
        kwargs = {}
        if icc:
            from PIL import ImageCms

            profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB"))
            kwargs["icc_profile"] = profile.tobytes()
        if fmt.upper() in ("HEIC", "HEIF"):
            try:
                import pillow_heif
            except ImportError:
                pytest.skip("pillow-heif is required for HEIC fixtures")
            pillow_heif.register_heif_opener()
            image.save(path, format="HEIF", **kwargs)
        else:
            image.save(path, format=fmt, **kwargs)
        return path

    return make


@pytest.fixture
def add_metadata(exiftool: Path):
    def apply(path: Path, tags: dict[str, str] | None = None, **extra: str) -> Path:
        values = dict(tags or {})
        values.update(extra)
        if not values:
            return path
        cmd = [str(exiftool), "-overwrite_original", "-charset", "filename=UTF8"]
        for key, value in values.items():
            cmd.append(f"-{key}={value}")
        cmd.append(str(path))
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=exiftool_env(exiftool),
        )
        assert proc.returncode < 2, proc.stderr
        return path

    return apply


@pytest.fixture
def pii_metadata() -> dict[str, str]:
    return dict(PII_METADATA)
