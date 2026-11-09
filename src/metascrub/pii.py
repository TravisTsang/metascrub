from __future__ import annotations

import re
from collections.abc import Iterable

from .models import MetaField

LOCATION = "location"
IDENTITY = "identity"
DEVICE = "device"
TEMPORAL = "temporal"
FREE_TEXT = "free_text"
EMBEDDED_MEDIA = "embedded_media"
FILESYSTEM = "filesystem"
STRUCTURAL = "structural"

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_STRUCTURAL_TAGS = {
    "orientation",
    "icc_profile",
    "colorspace",
    "colorspacedata",
    "profilecmtype",
    "profileversion",
    "profileclass",
    "profileconnectionspace",
    "profiledatetime",
    "profilefilesignature",
    "primaryplatform",
    "cmmflags",
    "devicemanufacturer",
    "devicemodel",
    "deviceattributes",
    "renderingintent",
    "connectionspaceilluminant",
    "profilecreator",
    "profileid",
    "imagewidth",
    "imageheight",
    "imagewidth_units",
    "imageheight_units",
    "bitspersample",
    "compression",
    "photometricinterpretation",
    "samplesperpixel",
    "planarconfiguration",
    "ycbcrsubsampling",
    "ycbcrpositioning",
    "tilewidth",
    "tilelength",
    "rowsperstrip",
    "stripoffsets",
    "stripbytecounts",
    "xresolution",
    "yresolution",
    "resolutionunit",
    "jfifversion",
    "exifbyteorder",
    "encodingprocess",
    "numberofcomponents",
    "megapixels",
    "image size",
    "filetype",
    "mimetype",
    "filesize",
    "filetypeextension",
    "exiftoolversion",
    "exiftoolversionnumber",
    "warning",
    "error",
    "validate",
    "duration",
    "avgbitrate",
    "imagesize",
    "colorspacetags",
    "xmlns",
}

_STRUCTURAL_GROUPS = {
    "icc_profile",
    "icc-header",
    "icc-viewingconditions",
    "icc-measurement",
    "icc-copyright",
}

_PII_TAGS: dict[str, tuple[str, str]] = {
    # Location
    "gpslatitude": (LOCATION, HIGH),
    "gpslongitude": (LOCATION, HIGH),
    "gpsaltitude": (LOCATION, HIGH),
    "gpsposition": (LOCATION, HIGH),
    "gpsdestlatitude": (LOCATION, HIGH),
    "gpsdestlongitude": (LOCATION, HIGH),
    "gpsimgdirection": (LOCATION, MEDIUM),
    "gpstrack": (LOCATION, MEDIUM),
    "gpsspeed": (LOCATION, MEDIUM),
    "gpslatituderef": (LOCATION, MEDIUM),
    "gpslongituderef": (LOCATION, MEDIUM),
    "city": (LOCATION, HIGH),
    "country": (LOCATION, HIGH),
    "country-primarylocationname": (LOCATION, HIGH),
    "country-primarylocationcode": (LOCATION, MEDIUM),
    "province-state": (LOCATION, HIGH),
    "state": (LOCATION, HIGH),
    "sublocation": (LOCATION, HIGH),
    "location": (LOCATION, HIGH),
    "locationcreated": (LOCATION, HIGH),
    "locationshown": (LOCATION, HIGH),
    "worldregion": (LOCATION, MEDIUM),
    "countrycode": (LOCATION, MEDIUM),
    # Identity / contact
    "artist": (IDENTITY, HIGH),
    "creator": (IDENTITY, HIGH),
    "author": (IDENTITY, HIGH),
    "owner": (IDENTITY, HIGH),
    "ownername": (IDENTITY, HIGH),
    "cameraownername": (IDENTITY, HIGH),
    "copyright": (IDENTITY, HIGH),
    "copyrightnotice": (IDENTITY, HIGH),
    "rights": (IDENTITY, MEDIUM),
    "by-line": (IDENTITY, HIGH),
    "byline": (IDENTITY, HIGH),
    "credit": (IDENTITY, MEDIUM),
    "contactinfo": (IDENTITY, HIGH),
    "creatorcontactinfo": (IDENTITY, HIGH),
    "email": (IDENTITY, HIGH),
    "phone": (IDENTITY, HIGH),
    "phonenumber": (IDENTITY, HIGH),
    "xpauthor": (IDENTITY, HIGH),
    "xptitle": (FREE_TEXT, MEDIUM),
    "xpcomment": (FREE_TEXT, MEDIUM),
    "xpsubject": (FREE_TEXT, MEDIUM),
    "xpkeywords": (FREE_TEXT, MEDIUM),
    "persondisplayname": (IDENTITY, HIGH),
    "facename": (IDENTITY, HIGH),
    "regioninfo": (IDENTITY, HIGH),
    "source": (IDENTITY, MEDIUM),
    # Device / software fingerprints
    "make": (DEVICE, MEDIUM),
    "model": (DEVICE, MEDIUM),
    "serialnumber": (DEVICE, HIGH),
    "internalserialnumber": (DEVICE, HIGH),
    "cameraserialnumber": (DEVICE, HIGH),
    "cameramodelname": (DEVICE, MEDIUM),
    "uniquecameramodel": (DEVICE, HIGH),
    "lensserialnumber": (DEVICE, HIGH),
    "bodyserialnumber": (DEVICE, HIGH),
    "lensid": (DEVICE, LOW),
    "lensmodel": (DEVICE, LOW),
    "lensmake": (DEVICE, LOW),
    "software": (DEVICE, MEDIUM),
    "creatortool": (DEVICE, MEDIUM),
    "firmwareversion": (DEVICE, MEDIUM),
    "hostcomputer": (DEVICE, HIGH),
    "documentid": (DEVICE, MEDIUM),
    "instanceid": (DEVICE, MEDIUM),
    "originaldocumentid": (DEVICE, MEDIUM),
    # Temporal
    "datetimeoriginal": (TEMPORAL, MEDIUM),
    "createdate": (TEMPORAL, MEDIUM),
    "modifydate": (TEMPORAL, MEDIUM),
    "metadatadate": (TEMPORAL, MEDIUM),
    "datemodified": (TEMPORAL, MEDIUM),
    "datecreated": (TEMPORAL, MEDIUM),
    "datetimedigitized": (TEMPORAL, MEDIUM),
    "gpsdatestamp": (TEMPORAL, MEDIUM),
    "gpstimestamp": (TEMPORAL, MEDIUM),
    "offsettime": (TEMPORAL, MEDIUM),
    "offsettimeoriginal": (TEMPORAL, MEDIUM),
    "offsettimedigitized": (TEMPORAL, MEDIUM),
    "mediacreatedate": (TEMPORAL, MEDIUM),
    "mediamodifydate": (TEMPORAL, MEDIUM),
    "trackcreatedate": (TEMPORAL, MEDIUM),
    "trackmodifydate": (TEMPORAL, MEDIUM),
    # Free text (may contain names, emails, addresses)
    "comment": (FREE_TEXT, MEDIUM),
    "usercomment": (FREE_TEXT, MEDIUM),
    "imagedescription": (FREE_TEXT, MEDIUM),
    "caption-abstract": (FREE_TEXT, MEDIUM),
    "caption": (FREE_TEXT, MEDIUM),
    "description": (FREE_TEXT, MEDIUM),
    "keywords": (FREE_TEXT, MEDIUM),
    "subject": (FREE_TEXT, MEDIUM),
    "title": (FREE_TEXT, MEDIUM),
    "headline": (FREE_TEXT, MEDIUM),
    "instructions": (FREE_TEXT, MEDIUM),
    "category": (FREE_TEXT, LOW),
    "supplementalcategories": (FREE_TEXT, LOW),
    "transmissionreference": (FREE_TEXT, LOW),
    "notes": (FREE_TEXT, MEDIUM),
    "specialinstructions": (FREE_TEXT, MEDIUM),
    # Embedded media
    "thumbnailimage": (EMBEDDED_MEDIA, MEDIUM),
    "previewimage": (EMBEDDED_MEDIA, MEDIUM),
    "jpgfromraw": (EMBEDDED_MEDIA, MEDIUM),
    "otherimage": (EMBEDDED_MEDIA, MEDIUM),
    "mpimage": (EMBEDDED_MEDIA, MEDIUM),
    "previewpng": (EMBEDDED_MEDIA, MEDIUM),
    "previewtiff": (EMBEDDED_MEDIA, MEDIUM),
    "thumbnailtiff": (EMBEDDED_MEDIA, MEDIUM),
    "thumbnailoffset": (EMBEDDED_MEDIA, MEDIUM),
    "previewjxl": (EMBEDDED_MEDIA, MEDIUM),
    # Filesystem
    "filename": (FILESYSTEM, MEDIUM),
    "directory": (FILESYSTEM, MEDIUM),
    "sourcefile": (FILESYSTEM, MEDIUM),
    "filemodifydate": (FILESYSTEM, MEDIUM),
    "fileaccessdate": (FILESYSTEM, MEDIUM),
    "fileinodechangedate": (FILESYSTEM, MEDIUM),
    "filecreatedate": (FILESYSTEM, MEDIUM),
    "filepermissions": (FILESYSTEM, LOW),
    "fileowner": (FILESYSTEM, MEDIUM),
    "fileuserid": (FILESYSTEM, LOW),
    "filegroupid": (FILESYSTEM, LOW),
}

_FILESYSTEM_TAGS = {
    "sourcefile",
    "filename",
    "directory",
    "filemodifydate",
    "fileaccessdate",
    "fileinodechangedate",
    "filecreatedate",
    "filepermissions",
    "fileowner",
    "fileuserid",
    "filegroupid",
}

_FREE_TEXT_TAGS = {
    tag
    for tag, (category, _severity) in _PII_TAGS.items()
    if category == FREE_TEXT
} | {"desc"}

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PHONE_RE = re.compile(r"(?<!\d)\+?\d[\d\s().-]{7,}\d(?!\d)")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_COORD_RE = re.compile(r"-?\d{1,3}\.\d{4,}\s*[,;]\s*-?\d{1,3}\.\d{4,}")


def _normalise(tag: str) -> str:
    return tag.strip().lower()


def _scan_text(value: str) -> str | None:
    if _EMAIL_RE.search(value) or _PHONE_RE.search(value):
        return IDENTITY
    if _COORD_RE.search(value) or _IPV4_RE.search(value) or _URL_RE.search(value):
        return FREE_TEXT
    return None


def classify_field(group: str, tag: str, value: str) -> tuple[bool, str | None, str | None]:
    group_l = (group or "").strip().lower()
    tag_l = _normalise(tag)

    if group_l.startswith("icc") or group_l in _STRUCTURAL_GROUPS or tag_l in _STRUCTURAL_TAGS:
        return False, None, None

    if tag_l in _PII_TAGS:
        category, severity = _PII_TAGS[tag_l]
        if category == FREE_TEXT and isinstance(value, str):
            hit = _scan_text(value)
            if hit == IDENTITY:
                return True, IDENTITY, HIGH
        return True, category, severity

    if group_l == "composite" and ("gps" in tag_l or "location" in tag_l):
        return True, LOCATION, HIGH

    if tag_l in _FREE_TEXT_TAGS and isinstance(value, str) and len(value) >= 4:
        hit = _scan_text(value)
        if hit:
            return True, hit, HIGH if hit == IDENTITY else MEDIUM

    return False, None, None


def classify_fields(fields: Iterable[MetaField]) -> None:
    for field in fields:
        is_pii, category, severity = classify_field(field.group, field.tag, field.value)
        field.is_pii = is_pii
        field.pii_category = category
        field.severity = severity


def is_embedded(field: MetaField) -> bool:
    group = (field.group or "").strip().lower()
    if group in ("system", "exiftool"):
        return False
    return not (group == "file" and field.tag.lower() in _FILESYSTEM_TAGS)


def summarize(fields: Iterable[MetaField]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for field in fields:
        if field.is_pii and field.pii_category:
            summary[field.pii_category] = summary.get(field.pii_category, 0) + 1
    return dict(sorted(summary.items()))
