import pytest

from core.entropy import EntropyAnalyzer, EntropyAnalysisError, iter_entropy_windows


def test_entropy_windows_cover_file_without_gaps(tmp_path):
    path = tmp_path / "bytes.bin"
    path.write_bytes(bytes(range(100)))
    windows = list(iter_entropy_windows(path, window_size=16))
    assert windows[0].offset == 0
    assert windows[-1].offset + windows[-1].size == 100
    assert sum(window.size for window in windows) == 100
    assert all(a.offset + a.size == b.offset for a, b in zip(windows, windows[1:]))


def test_entropy_threshold_is_configurable(tmp_path):
    path = tmp_path / "varied.bin"
    path.write_bytes(bytes(range(256)))
    lower = EntropyAnalyzer(window_size=256, threshold=7.0).analyze_file(path)
    higher = EntropyAnalyzer(window_size=256, threshold=8.0).analyze_file(path)
    assert lower.high_entropy_count == 1
    assert higher.high_entropy_count == 1


def test_missing_entropy_target_is_rejected(tmp_path):
    with pytest.raises(EntropyAnalysisError):
        EntropyAnalyzer().analyze_file(tmp_path / "missing")
