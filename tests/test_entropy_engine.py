import pytest

from core.entropy import (
    EntropyAnalyzer,
    EntropyAnalysisError,
    calculate_shannon_entropy,
)


def test_empty_data_entropy():
    assert calculate_shannon_entropy(b"") == 0.0


def test_constant_data_entropy():
    assert calculate_shannon_entropy(b"A" * 100) == 0.0


def test_two_byte_values_entropy():
    data = b"A" * 50 + b"B" * 50
    assert calculate_shannon_entropy(data) == pytest.approx(1.0)


def test_maximum_entropy():
    data = bytes(range(256))
    assert calculate_shannon_entropy(data) == pytest.approx(8.0)


def test_invalid_entropy_input():
    with pytest.raises(TypeError):
        calculate_shannon_entropy("not binary data")


def test_configurable_windows(tmp_path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"ABCDEFGHIJ")

    analyzer = EntropyAnalyzer(window_size=4, threshold=7.2)
    result = analyzer.analyze_file(file_path)

    assert result.file_size == 10
    assert result.window_count == 3

    assert [
        (window.offset, window.size)
        for window in result.windows
    ] == [(0, 4), (4, 4), (8, 2)]


def test_high_entropy_detection(tmp_path):
    file_path = tmp_path / "high_entropy.bin"
    file_path.write_bytes(bytes(range(256)))

    analyzer = EntropyAnalyzer(window_size=256, threshold=7.2)
    result = analyzer.analyze_file(file_path)

    assert result.window_count == 1
    assert result.high_entropy_count == 1
    assert result.windows[0].entropy == pytest.approx(8.0)
    assert result.windows[0].high_entropy is True


def test_low_entropy_detection(tmp_path):
    file_path = tmp_path / "low_entropy.bin"
    file_path.write_bytes(b"A" * 256)

    analyzer = EntropyAnalyzer(window_size=256, threshold=7.2)
    result = analyzer.analyze_file(file_path)

    assert result.high_entropy_count == 0
    assert result.windows[0].entropy == 0.0
    assert result.windows[0].high_entropy is False


def test_empty_file(tmp_path):
    file_path = tmp_path / "empty.bin"
    file_path.write_bytes(b"")

    result = EntropyAnalyzer().analyze_file(file_path)

    assert result.file_size == 0
    assert result.window_count == 0
    assert result.high_entropy_count == 0
    assert result.average_window_entropy == 0.0


def test_invalid_window_size():
    with pytest.raises(EntropyAnalysisError):
        EntropyAnalyzer(window_size=0)


def test_invalid_threshold():
    with pytest.raises(EntropyAnalysisError):
        EntropyAnalyzer(threshold=9.0)


def test_json_friendly_report(tmp_path):
    file_path = tmp_path / "report.bin"
    file_path.write_bytes(bytes(range(256)))

    result = EntropyAnalyzer(
        window_size=256,
        threshold=7.2,
    ).analyze_file(file_path)

    report = result.to_dict()

    assert report["file_size"] == 256
    assert report["window_count"] == 1
    assert report["high_entropy_count"] == 1
    assert len(report["high_entropy_windows"]) == 1
