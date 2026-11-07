from core.file_carver import FileCarver
from core.sliding_window import SlidingWindowScanner

PNG = bytes.fromhex("89504E470D0A1A0A")


def test_signature_at_last_valid_start_offset(tmp_path):
    path = tmp_path / "last.bin"
    path.write_bytes(b"X" * 5 + PNG)
    matches = SlidingWindowScanner(chunk_size=4).scan_file(path)
    assert [(m.signature_id, m.offset) for m in matches] == [("PNG", 5)]


def test_truncated_signature_at_eof_is_not_detected(tmp_path):
    path = tmp_path / "truncated.bin"
    path.write_bytes(PNG[:-1])
    assert SlidingWindowScanner().scan_file(path) == ()


def test_carver_candidate_ends_at_eof(tmp_path):
    path = tmp_path / "eof.bin"
    content = PNG + b"END"
    path.write_bytes(content)
    candidates = FileCarver().carve(path)
    assert len(candidates) == 1
    assert candidates[0].end_offset == len(content)
    assert candidates[0].boundary_reason == "end_of_file"
