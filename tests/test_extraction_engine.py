import hashlib

import pytest

from core.extraction import ExtractionError, SafeExtractor
from core.models import CarvedFileCandidate

PNG = bytes.fromhex("89504E470D0A1A0A")


def candidate_for(path, start=0, end=None, signature_id="PNG", extensions=(".png",)):
    if end is None:
        end = path.stat().st_size
    return CarvedFileCandidate(
        source_path=path,
        signature_id=signature_id,
        name="PNG image",
        category="image",
        mime_type="image/png",
        extensions=extensions,
        start_offset=start,
        end_offset=end,
        boundary_reason="test",
    )


def test_extracts_exact_candidate_and_verifies_sha256(tmp_path):
    source = tmp_path / "source.bin"
    payload = b"PREFIX" + PNG + b"PAYLOAD" + b"TRAILER"
    source.write_bytes(payload)
    output = tmp_path / "out"
    result = SafeExtractor(output, chunk_size=3).extract(
        candidate_for(source, 6, len(payload) - 7)
    )
    expected = payload[6:-7]
    assert result.output_path.read_bytes() == expected
    assert result.bytes_written == len(expected)
    assert result.sha256 == hashlib.sha256(expected).hexdigest()
    assert result.integrity_verified is True
    assert result.output_path.parent == output.resolve()
    assert result.output_path.stat().st_mode & 0o777 == 0o600


def test_generated_filename_is_safe_for_untrusted_signature_id(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(PNG + b"DATA")
    result = SafeExtractor(tmp_path / "out").extract(
        candidate_for(source, signature_id="../../outside/evil")
    )
    assert result.output_path.parent == (tmp_path / "out").resolve()
    assert ".." not in result.output_path.name
    assert "/" not in result.output_path.name
    assert result.output_path.suffix == ".png"
    assert not (tmp_path / "outside").exists()


def test_unsafe_extension_falls_back_to_bin(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"DATA")
    result = SafeExtractor(tmp_path / "out").extract(
        candidate_for(source, signature_id="CUSTOM", extensions=("../../bad",))
    )
    assert result.output_path.suffix == ".bin"


def test_existing_output_is_never_overwritten(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(PNG + b"DATA")
    out = tmp_path / "out"
    out.mkdir()
    first = SafeExtractor(out).extract(candidate_for(source))
    first_contents = first.output_path.read_bytes()
    second = SafeExtractor(out).extract(candidate_for(source))
    assert second.output_path != first.output_path
    assert first.output_path.read_bytes() == first_contents
    assert second.output_path.exists()


def test_per_file_size_limit(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789")
    with pytest.raises(ExtractionError, match="per-file output limit"):
        SafeExtractor(tmp_path / "out", max_output_size=5).extract(
            candidate_for(source, 0, 6)
        )


def test_total_size_limit(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"123456")
    extractor = SafeExtractor(
        tmp_path / "out", max_output_size=4, max_total_output_size=5
    )
    extractor.extract(candidate_for(source, 0, 3, "A", (".bin",)))
    with pytest.raises(ExtractionError, match="total output-size limit"):
        extractor.extract(candidate_for(source, 3, 6, "B", (".bin",)))


def test_rejects_negative_and_reversed_ranges(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"123456")
    extractor = SafeExtractor(tmp_path / "out")
    with pytest.raises(ExtractionError, match="start_offset"):
        extractor.extract(candidate_for(source, -1, 3))
    with pytest.raises(ExtractionError, match="greater than"):
        extractor.extract(candidate_for(source, 4, 3))


def test_rejects_range_beyond_eof(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"123456")
    with pytest.raises(ExtractionError, match="beyond"):
        SafeExtractor(tmp_path / "out").extract(candidate_for(source, 0, 7))


def test_rejects_symlink_source(tmp_path):
    source = tmp_path / "real.bin"
    source.write_bytes(b"1234")
    link = tmp_path / "link.bin"
    link.symlink_to(source)
    with pytest.raises(ExtractionError, match="Symbolic-link"):
        SafeExtractor(tmp_path / "out").extract(candidate_for(link))


def test_invalid_limits_are_rejected(tmp_path):
    with pytest.raises(ExtractionError):
        SafeExtractor(tmp_path / "out", max_output_size=0)
    with pytest.raises(ExtractionError):
        SafeExtractor(tmp_path / "out", max_output_size=10, max_total_output_size=5)


def test_failed_extraction_removes_partial_output(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"123456")
    extractor = SafeExtractor(tmp_path / "out", chunk_size=2)
    original = extractor._reserve_destination

    def reserve_then_corrupt(signature_id, offset, extension):
        path, stream = original(signature_id, offset, extension)
        stream.close()
        return path, path.open("wb")

    # Cause a write failure without retaining a partial result.
    class BrokenWriter:
        def __init__(self, wrapped):
            self.wrapped = wrapped
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.wrapped.close()
        def write(self, data):
            raise OSError("simulated write failure")
        def flush(self):
            return self.wrapped.flush()
        def fileno(self):
            return self.wrapped.fileno()

    def broken_reserve(signature_id, offset, extension):
        path, stream = original(signature_id, offset, extension)
        return path, BrokenWriter(stream)

    monkeypatch.setattr(extractor, "_reserve_destination", broken_reserve)
    with pytest.raises(ExtractionError):
        extractor.extract(candidate_for(source))
    assert list((tmp_path / "out").iterdir()) == []


def test_extract_many_rolls_back_when_total_budget_is_exceeded(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abcdef")
    extractor = SafeExtractor(
        tmp_path / "out", max_output_size=4, max_total_output_size=5
    )
    first = candidate_for(source, 0, 3, "FIRST", (".bin",))
    second = candidate_for(source, 3, 6, "SECOND", (".bin",))
    with pytest.raises(ExtractionError, match="total output-size limit"):
        extractor.extract_many((first, second))
    assert list((tmp_path / "out").iterdir()) == []
    assert extractor._total_bytes_written == 0


def test_existing_symlink_destination_is_not_followed_or_overwritten(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(PNG + b"DATA")
    out = tmp_path / "out"
    out.mkdir()
    protected = tmp_path / "protected.txt"
    protected.write_text("keep this file", encoding="utf-8")
    collision = out / "filex_png_0000000000000000.png"
    collision.symlink_to(protected)

    result = SafeExtractor(out).extract(candidate_for(source))
    assert result.output_path != collision
    assert collision.is_symlink()
    assert protected.read_text(encoding="utf-8") == "keep this file"


def test_extraction_rejects_candidate_source_that_is_a_directory(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    fake = CarvedFileCandidate(
        source_path=directory,
        signature_id="PNG",
        name="PNG image",
        category="image",
        mime_type="image/png",
        extensions=(".png",),
        start_offset=0,
        end_offset=8,
        boundary_reason="test",
    )
    with pytest.raises(ExtractionError, match="regular file"):
        SafeExtractor(tmp_path / "out").extract(fake)
