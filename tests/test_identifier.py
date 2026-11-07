import pytest

from core.file_identifier import FileIdentifier, FileIdentificationError

PNG = bytes.fromhex("89504E470D0A1A0A")
PDF = bytes.fromhex("25504446")


def test_identifies_png_by_header(tmp_path):
    path = tmp_path / "photo.png"
    path.write_bytes(PNG + b"payload")
    result = FileIdentifier().identify(path)
    assert result.detected
    assert result.primary_match.signature_id == "PNG"
    assert result.extension_status == "match"


def test_detects_extension_mismatch(tmp_path):
    path = tmp_path / "misnamed.txt"
    path.write_bytes(PDF + b"-1.7")
    result = FileIdentifier().identify(path)
    assert result.detected
    assert result.extension_status == "mismatch"
    assert result.extension_mismatch is True


def test_unknown_format_returns_unknown_status(tmp_path):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"not a registered header")
    result = FileIdentifier().identify(path)
    assert result.detected is False
    assert result.extension_status == "unknown"
    assert result.extension_mismatch is None


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(FileIdentificationError):
        FileIdentifier().identify(tmp_path / "missing.bin")
