from __future__ import annotations

from metascrub.models import MetaField
from metascrub.pii import classify_field, classify_fields, is_embedded, summarize


def test_classifies_location():
    is_pii, category, severity = classify_field("GPS", "GPSLatitude", "51.5")
    assert is_pii is True
    assert category == "location"
    assert severity == "high"


def test_classifies_identity_and_device():
    assert classify_field("IFD0", "Artist", "Alice")[:2] == (True, "identity")
    assert classify_field("ExifIFD", "SerialNumber", "SN1")[:2] == (True, "device")


def test_structural_tags_are_not_pii():
    assert classify_field("IFD0", "Orientation", "6") == (False, None, None)
    assert classify_field("ExifIFD", "ColorSpace", "1") == (False, None, None)
    assert classify_field("File", "MIMEType", "image/jpeg") == (False, None, None)


def test_email_in_free_text_becomes_high_identity():
    is_pii, category, severity = classify_field(
        "File", "Comment", "reach me at alice@example.com"
    )
    assert (is_pii, category, severity) == (True, "identity", "high")


def test_phone_in_free_text_becomes_high_identity():
    is_pii, category, severity = classify_field(
        "XMP-dc", "Description", "call +1 555 123 4567"
    )
    assert (is_pii, category, severity) == (True, "identity", "high")


def test_filesystem_fields_are_not_embedded():
    system_field = MetaField(group="System", tag="FileName", value="alice.jpg")
    assert is_embedded(system_field) is False
    artist_field = MetaField(group="IFD0", tag="Artist", value="Alice")
    assert is_embedded(artist_field) is True


def test_classify_fields_and_summary():
    fields = [
        MetaField(group="IFD0", tag="Artist", value="Alice"),
        MetaField(group="GPS", tag="GPSLatitude", value="51.5"),
        MetaField(group="IFD0", tag="Orientation", value="6"),
    ]
    classify_fields(fields)
    assert [field.is_pii for field in fields] == [True, True, False]
    assert summarize(fields) == {"identity": 1, "location": 1}
