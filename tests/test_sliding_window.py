import pytest

from core.sliding_window import (
    SlidingWindowError,
    SlidingWindowScanner,
    iter_file_chunks,
)


PNG_SIGNATURE = bytes.fromhex("89504E470D0A1A0A")


def test_signature_crosses_chunk_boundary(tmp_path):
    """Detect a signature split across two chunks."""

    file_path = tmp_path / "boundary.bin"

    content = (
        b"A" * 6
        + PNG_SIGNATURE
        + b"B" * 4
        + PNG_SIGNATURE
        + b"C" * 5
    )

    file_path.write_bytes(content)

    scanner = SlidingWindowScanner(chunk_size=8)

    matches = scanner.scan_file(file_path)

    png_offsets = [
        match.offset
        for match in matches
        if match.signature_id == "PNG"
    ]

    assert png_offsets == [6, 18]


def test_signature_spans_multiple_small_chunks(tmp_path):
    """Detect a signature when chunk size is smaller than the signature."""

    file_path = tmp_path / "small_chunks.bin"

    file_path.write_bytes(
        b"PREFIX" + PNG_SIGNATURE + b"SUFFIX"
    )

    scanner = SlidingWindowScanner(chunk_size=3)

    matches = scanner.scan_file(file_path)

    png_offsets = [
        match.offset
        for match in matches
        if match.signature_id == "PNG"
    ]

    assert png_offsets == [6]


def test_no_duplicate_matches(tmp_path):
    """Verify that overlapping windows do not duplicate matches."""

    file_path = tmp_path / "duplicates.bin"

    file_path.write_bytes(
        b"A" * 6 + PNG_SIGNATURE + b"B" * 4 + PNG_SIGNATURE
    )

    scanner = SlidingWindowScanner(chunk_size=8)

    matches = scanner.scan_file(file_path)

    png_offsets = [
        match.offset
        for match in matches
        if match.signature_id == "PNG"
    ]

    assert len(png_offsets) == len(set(png_offsets))
    assert len(png_offsets) == 2


def test_unknown_file(tmp_path):
    """An unknown file should return no signature matches."""

    file_path = tmp_path / "unknown.bin"

    file_path.write_bytes(b"Ordinary FILEX test data")

    scanner = SlidingWindowScanner(chunk_size=8)

    matches = scanner.scan_file(file_path)

    assert matches == ()


def test_empty_file(tmp_path):
    """An empty file should return no matches."""

    file_path = tmp_path / "empty.bin"

    file_path.write_bytes(b"")

    scanner = SlidingWindowScanner()

    matches = scanner.scan_file(file_path)

    assert matches == ()


def test_chunk_absolute_offsets(tmp_path):
    """Verify the start offsets of overlapping windows."""

    file_path = tmp_path / "offsets.bin"

    file_path.write_bytes(b"abcdefghij")

    windows = list(
        iter_file_chunks(
            file_path,
            chunk_size=4,
            overlap=2,
        )
    )

    assert windows[0] == (0, 0, b"abcd")
    assert windows[1] == (2, 4, b"cdefgh")
    assert windows[2] == (6, 8, b"ghij")


def test_invalid_chunk_size(tmp_path):

    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"test")

    with pytest.raises(SlidingWindowError):
        SlidingWindowScanner(chunk_size=0)