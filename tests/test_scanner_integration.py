from core.scanner import FileXScanner, ScanError

PNG = bytes.fromhex("89504E470D0A1A0A")


def test_complete_analysis_pipeline(tmp_path):
    source = tmp_path / "sample.png"
    source.write_bytes(PNG + b"A" * 200)
    report = FileXScanner(
        chunk_size=16,
        entropy_window_size=32,
        entropy_threshold=7.2,
    ).analyze_file(source)
    data = report.to_dict()
    assert data["application"] == "FILEX"
    assert data["identification"]["detected"] is True
    assert data["embedded_matches"][0]["offset"] == 0
    assert data["entropy"]["window_count"] > 0
    assert len(data["carving_candidates"]) == 1
    assert data["yara"] is None
    assert len(data["interpretation_notes"]) == 3


def test_unknown_file_analysis(tmp_path):
    source = tmp_path / "unknown.bin"
    source.write_bytes(b"ordinary data" * 30)
    report = FileXScanner(entropy_window_size=32).analyze_file(source)
    assert report.identification.detected is False
    assert report.embedded_matches == ()
    assert report.candidates == ()


def test_scanner_rejects_symlink(tmp_path):
    source = tmp_path / "real.bin"
    source.write_bytes(b"data")
    link = tmp_path / "link.bin"
    link.symlink_to(source)
    try:
        FileXScanner().analyze_file(link)
    except ScanError as error:
        assert "non-symlink" in str(error)
    else:
        raise AssertionError("Expected ScanError")
