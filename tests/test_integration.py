"""End-to-end tests spanning detection, carving and safe extraction."""

from core.extraction import SafeExtractor
from core.file_carver import FileCarver
from core.scanner import FileXScanner

PNG = bytes.fromhex("89504E470D0A1A0A")
PDF = bytes.fromhex("25504446")


def test_detect_carve_and_extract_pipeline(tmp_path):
    source = tmp_path / "mixed.bin"
    content = b"PREFIX" + PNG + b"image-like-data" + PDF + b"document-like-data"
    source.write_bytes(content)
    analysis = FileXScanner(chunk_size=7, entropy_window_size=8).analyze_file(source)
    assert [match.signature_id for match in analysis.embedded_matches] == ["PNG", "PDF"]
    candidates = FileCarver(chunk_size=7).carve(source)
    assert len(candidates) == 2
    results = SafeExtractor(tmp_path / "extracted", chunk_size=5).extract_many(candidates)
    assert len(results) == 2
    assert all(result.integrity_verified for result in results)
    pdf_offset = content.index(PDF)
    assert results[0].output_path.read_bytes() == content[6:pdf_offset]
    assert results[1].output_path.read_bytes() == content[pdf_offset:]
