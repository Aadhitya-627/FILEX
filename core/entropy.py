"""
FILEX - Entropy Analysis Engine

Provides Shannon entropy calculation and incremental
window-based file analysis.

Entropy is a statistical indicator, not a malware verdict.
"""

import math

from collections import Counter
from pathlib import Path
from typing import Iterator, Union

from config.settings import (
    ENTROPY_THRESHOLD,
    ENTROPY_WINDOW_SIZE,
)

from core.models import (
    EntropyAnalysisResult,
    EntropyWindowResult,
)


# =====================================================
# CUSTOM EXCEPTION
# =====================================================

class EntropyAnalysisError(Exception):
    """Raised when entropy analysis cannot be completed."""


# =====================================================
# CONFIGURATION VALIDATION
# =====================================================

def _validate_window_size(window_size: int) -> None:
    """Validate the configured analysis window size."""

    if (
        isinstance(window_size, bool)
        or not isinstance(window_size, int)
        or window_size <= 0
    ):
        raise EntropyAnalysisError(
            "Window size must be a positive integer."
        )


def _validate_threshold(threshold: float) -> None:
    """Validate a Shannon entropy threshold."""

    if isinstance(threshold, bool) or not isinstance(
        threshold, (int, float)
    ):
        raise EntropyAnalysisError(
            "Entropy threshold must be a number."
        )

    if not math.isfinite(threshold) or not 0 <= threshold <= 8:
        raise EntropyAnalysisError(
            "Entropy threshold must be between 0 and 8."
        )


# =====================================================
# SHANNON ENTROPY CALCULATION
# =====================================================

def calculate_shannon_entropy(
    data: Union[bytes, bytearray, memoryview],
) -> float:
    """
    Calculate Shannon entropy for binary data.

    Returns:
        Entropy in bits per byte, from 0.0 to 8.0.

    Empty input returns 0.0.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            "Entropy input must be bytes-like data."
        )

    if len(data) == 0:
        return 0.0

    total_bytes = len(data)

    # Count occurrences of each byte value.
    frequencies = Counter(data)

    entropy = 0.0

    for count in frequencies.values():

        probability = count / total_bytes

        entropy -= probability * math.log2(probability)

    # Protect against negligible floating-point deviations.
    return max(0.0, min(8.0, entropy))


# Backward-compatible short function name.
def calculate_entropy(data) -> float:
    """Alias for calculate_shannon_entropy()."""

    return calculate_shannon_entropy(data)


# =====================================================
# ENTROPY WINDOW ITERATOR
# =====================================================

def iter_entropy_windows(
    file_path: Union[str, Path],
    window_size: int = ENTROPY_WINDOW_SIZE,
    threshold: float = ENTROPY_THRESHOLD,
) -> Iterator[EntropyWindowResult]:
    """
    Read a file incrementally and calculate entropy per window.

    Each window is non-overlapping.

    The final window may be smaller than window_size.

    Yields:
        EntropyWindowResult objects with absolute offsets.
    """

    _validate_window_size(window_size)
    _validate_threshold(threshold)

    try:
        path = Path(file_path)

    except (TypeError, ValueError) as error:
        raise EntropyAnalysisError(
            "Invalid file path."
        ) from error

    if not path.exists():
        raise EntropyAnalysisError(
            f"File does not exist: {path}"
        )

    if not path.is_file():
        raise EntropyAnalysisError(
            f"Path is not a regular file: {path}"
        )

    absolute_offset = 0

    try:
        with path.open("rb") as target:

            while True:

                # Read one window, not the entire target file.
                data = target.read(window_size)

                if not data:
                    break

                entropy = calculate_shannon_entropy(data)

                result = EntropyWindowResult(
                    offset=absolute_offset,
                    size=len(data),
                    entropy=entropy,
                    high_entropy=entropy >= threshold,
                )

                yield result

                absolute_offset += len(data)

    except OSError as error:
        raise EntropyAnalysisError(
            f"Unable to read file for entropy analysis: {error}"
        ) from error


# =====================================================
# ENTROPY ANALYZER
# =====================================================

class EntropyAnalyzer:
    """Performs configurable window-based entropy analysis."""

    def __init__(
        self,
        window_size: int = ENTROPY_WINDOW_SIZE,
        threshold: float = ENTROPY_THRESHOLD,
    ):

        _validate_window_size(window_size)
        _validate_threshold(threshold)

        self.window_size = window_size
        self.threshold = float(threshold)

    def iter_windows(
        self,
        file_path: Union[str, Path],
    ) -> Iterator[EntropyWindowResult]:
        """Stream entropy results one window at a time."""

        return iter_entropy_windows(
            file_path=file_path,
            window_size=self.window_size,
            threshold=self.threshold,
        )

    def analyze_file(
        self,
        file_path: Union[str, Path],
    ) -> EntropyAnalysisResult:
        """
        Analyze a complete file and return its structured result.

        Window contents are discarded after each calculation.
        Only the window metadata and entropy results are retained.
        """

        try:
            path = Path(file_path)

        except (TypeError, ValueError) as error:
            raise EntropyAnalysisError(
                "Invalid file path."
            ) from error

        windows = tuple(self.iter_windows(path))

        # Calculate the amount of data actually analyzed.
        file_size = sum(window.size for window in windows)

        return EntropyAnalysisResult(
            file_path=path,
            file_size=file_size,
            window_size=self.window_size,
            threshold=self.threshold,
            windows=windows,
        )

    def analyze(
        self,
        file_path: Union[str, Path],
    ) -> EntropyAnalysisResult:
        """Alias for analyze_file()."""

        return self.analyze_file(file_path)


# =====================================================
# CONVENIENCE FUNCTION
# =====================================================

def analyze_file(
    file_path: Union[str, Path],
    window_size: int = ENTROPY_WINDOW_SIZE,
    threshold: float = ENTROPY_THRESHOLD,
) -> EntropyAnalysisResult:
    """Analyze a file without manually creating an analyzer."""

    analyzer = EntropyAnalyzer(
        window_size=window_size,
        threshold=threshold,
    )

    return analyzer.analyze_file(file_path)