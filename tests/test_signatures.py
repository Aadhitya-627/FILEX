import json

import pytest

from core.signature_engine import (
    SignatureDatabaseError,
    SignatureEngine,
    load_signature_database,
)


def write_database(path, signatures=None):
    data = {
        "database_version": "test-1",
        "description": "test signatures",
        "signatures": signatures if signatures is not None else [{
            "id": "TEST", "name": "Test format", "category": "test",
            "mime_type": "application/octet-stream", "extensions": [".tst"],
            "magic_hex": "41424344", "offsets": [0],
            "scan_embedded": True, "description": "Test header",
        }],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_default_signature_database_loads():
    engine = SignatureEngine()
    assert {item.id for item in engine.signatures} == {"PNG", "PDF", "ZIP"}
    assert engine.get_signature("PNG").magic_bytes == bytes.fromhex("89504E470D0A1A0A")


def test_custom_database_loads(tmp_path):
    path = tmp_path / "signatures.json"
    write_database(path)
    database = load_signature_database(path)
    assert database.database_version == "test-1"
    assert database.max_signature_length == 4


@pytest.mark.parametrize("magic", ["XYZ", "", "123"])
def test_invalid_hex_signature_is_rejected(tmp_path, magic):
    path = tmp_path / "bad.json"
    entries = [{
        "id": "BAD", "name": "Bad", "category": "test",
        "mime_type": "application/octet-stream", "extensions": [".bad"],
        "magic_hex": magic, "offsets": [0], "scan_embedded": True,
        "description": "bad signature",
    }]
    write_database(path, entries)
    with pytest.raises(SignatureDatabaseError):
        load_signature_database(path)


def test_duplicate_signature_ids_are_rejected_case_insensitively(tmp_path):
    path = tmp_path / "duplicate.json"
    write_database(path, [
        {"id": "DUP", "name": "One", "category": "test", "mime_type": "application/x-test", "extensions": [".one"], "magic_hex": "41", "offsets": [0], "scan_embedded": True, "description": "one"},
        {"id": "dup", "name": "Two", "category": "test", "mime_type": "application/x-test", "extensions": [".two"], "magic_hex": "42", "offsets": [0], "scan_embedded": True, "description": "two"},
    ])
    with pytest.raises(SignatureDatabaseError, match="Duplicate"):
        load_signature_database(path)


def test_invalid_extension_and_offset_are_rejected(tmp_path):
    path = tmp_path / "invalid.json"
    entry = {"id": "BAD", "name": "Bad", "category": "test", "mime_type": "application/x-test", "extensions": ["../bad"], "magic_hex": "41", "offsets": [-1], "scan_embedded": True, "description": "bad"}
    write_database(path, [entry])
    with pytest.raises(SignatureDatabaseError):
        load_signature_database(path)


def test_database_size_limit_is_enforced(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(SignatureDatabaseError, match="size limit"):
        load_signature_database(path)
