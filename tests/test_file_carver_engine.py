import pytest

from core.file_carver import (
    FileCarver,
    FileCarvingError,
)

PNG_SIGNATURE = bytes.fromhex("89504E470D0A1A0A")
PDF_SIGNATURE = bytes.fromhex("25504446")
ZIP_SIGNATURE = bytes.fromhex("504B0304")


def create_sample_file(path):
    content = (
        b"HEAD"
        + PNG_SIGNATURE
        + b"A" * 10
        + PDF_SIGNATURE
        + b"B" * 5
        + ZIP_SIGNATURE
        + b"TAIL"
    )
    path.write_bytes(content)
    return content


def test_multiple_candidate_detection(tmp_path):
    file_path = tmp_path / "multiple.bin"
    content = create_sample_file(file_path)

    candidates = FileCarver().carve(file_path)

    assert len(candidates) == 3
    assert [c.signature_id for c in candidates] == [
        "PNG", "PDF", "ZIP"
    ]
    assert [c.start_offset for c in candidates] == [
        4, 22, 31
    ]
    assert candidates[0].end_offset == 22
    assert candidates[1].end_offset == 31
    assert candidates[2].end_offset == len(content)


def test_absolute_offsets(tmp_path):
    file_path = tmp_path / "offsets.bin"
    file_path.write_bytes(b"X" * 100 + PNG_SIGNATURE + b"Y" * 20)

    candidates = FileCarver().carve(file_path)

    assert len(candidates) == 1
    assert candidates[0].start_offset == 100


def test_next_signature_boundary(tmp_path):
    file_path = tmp_path / "boundary.bin"
    file_path.write_bytes(
        PNG_SIGNATURE + b"A" * 20 + PDF_SIGNATURE + b"B" * 10
    )

    candidates = FileCarver().carve(file_path)

    png = next(c for c in candidates if c.signature_id == "PNG")

    assert png.end_offset == 28
    assert png.boundary_reason == "next_detected_signature"


def test_maximum_candidate_size(tmp_path):
    file_path = tmp_path / "limited.bin"
    file_path.write_bytes(PNG_SIGNATURE + b"A" * 100)

    candidates = FileCarver(max_candidate_size=12).carve(file_path)

    assert len(candidates) == 1
    assert candidates[0].size == 12
    assert candidates[0].boundary_reason == "max_size_limit"


def test_unknown_file(tmp_path):
    file_path = tmp_path / "unknown.bin"
    file_path.write_bytes(b"Ordinary FILEX test content")

    assert FileCarver().carve(file_path) == ()


def test_empty_file(tmp_path):
    file_path = tmp_path / "empty.bin"
    file_path.write_bytes(b"")

    assert FileCarver().carve(file_path) == ()


def test_candidate_json_serialization(tmp_path):
    file_path = tmp_path / "serialize.bin"
    file_path.write_bytes(PNG_SIGNATURE + b"TEST")

    candidates = FileCarver().carve(file_path)

    assert len(candidates) == 1

    report = candidates[0].to_dict()

    assert report["signature_id"] == "PNG"
    assert report["start_offset"] == 0
    assert report["end_offset_exclusive"] == 12
    assert report["size"] == 12
    assert report["boundary_reason"] == "end_of_file"


def test_invalid_maximum_candidate_size():
    with pytest.raises(FileCarvingError):
        FileCarver(max_candidate_size=0)


def test_missing_source_file(tmp_path):
    missing_file = tmp_path / "missing.bin"

    with pytest.raises(FileCarvingError):
        FileCarver().carve(missing_file)


def test_candidate_size_consistency(tmp_path):
    file_path = tmp_path / "size.bin"
    file_path.write_bytes(b"START" + PNG_SIGNATURE + b"END")

    candidate = FileCarver().carve(file_path)[0]

    assert candidate.size == (
        candidate.end_offset - candidate.start_offset
    )
