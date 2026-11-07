"""
FILEX - Sliding Window Binary Scanner

Scans files in chunks and detects embedded binary signatures.

Features:
- Bounded chunk-based file reading
- Automatic overlap calculation
- Absolute byte offset tracking
- Detection across chunk boundaries
- Duplicate-match prevention
- Read-only target file access
"""

from pathlib import Path
from typing import Iterator, Optional, Tuple, Union

from config.settings import CHUNK_SIZE

from core.models import SignatureMatch
from core.signature_engine import SignatureEngine


# =====================================================
# CUSTOM EXCEPTION
# =====================================================

class SlidingWindowError(Exception):
    """Raised when sliding-window scanning fails."""


# =====================================================
# CHUNK READER
# =====================================================

def iter_file_chunks(
    file_path: Union[str, Path],
    chunk_size: int = CHUNK_SIZE,
    overlap: int = 0,
) -> Iterator[Tuple[int, int, bytes]]:
    """
    Yield overlapping file windows without reading the entire file.

    Each yielded item contains:

        window_offset:
            Absolute offset where the combined window begins.

        new_data_offset:
            Absolute offset where newly read data begins.

        window_data:
            Previous overlap bytes followed by the new chunk.

    Args:
        file_path: Target file path.
        chunk_size: Number of new bytes read per iteration.
        overlap: Number of bytes retained from the previous window.

    Yields:
        (window_offset, new_data_offset, window_data)

    Memory:
        Each yielded window contains at most chunk_size + overlap bytes.
    """

    if (
        isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or chunk_size <= 0
    ):
        raise SlidingWindowError(
            "chunk_size must be a positive integer."
        )

    if (
        isinstance(overlap, bool)
        or not isinstance(overlap, int)
        or overlap < 0
    ):
        raise SlidingWindowError(
            "overlap must be a non-negative integer."
        )

    try:
        path = Path(file_path)

    except (TypeError, ValueError) as error:
        raise SlidingWindowError(
            "Invalid file path."
        ) from error

    if not path.exists():
        raise SlidingWindowError(
            f"File does not exist: {path}"
        )

    if not path.is_file():
        raise SlidingWindowError(
            f"Path is not a regular file: {path}"
        )

    previous_tail = b""
    total_bytes_read = 0

    try:
        with path.open("rb") as file:

            while True:

                # Read only the next chunk.
                new_chunk = file.read(chunk_size)

                if not new_chunk:
                    break

                # Record the absolute start of new data.
                new_data_offset = total_bytes_read

                # Combine previous overlap with new data.
                window_data = previous_tail + new_chunk

                window_offset = (
                    total_bytes_read - len(previous_tail)
                )

                yield (
                    window_offset,
                    new_data_offset,
                    window_data,
                )

                # Update the absolute file position.
                total_bytes_read += len(new_chunk)

                # Retain the last N bytes for the next window.
                if overlap:
                    previous_tail = window_data[-overlap:]
                else:
                    previous_tail = b""

    except OSError as error:
        raise SlidingWindowError(
            f"Unable to read file: {error}"
        ) from error


# =====================================================
# SLIDING WINDOW SCANNER
# =====================================================

class SlidingWindowScanner:
    """Scans files for embedded binary signatures."""

    def __init__(
        self,
        engine: Optional[SignatureEngine] = None,
        chunk_size: int = CHUNK_SIZE,
    ):
        """
        Initialize the scanner.

        Args:
            engine: Existing validated SignatureEngine.
            chunk_size: Number of new bytes per chunk.
        """

        if (
            isinstance(chunk_size, bool)
            or not isinstance(chunk_size, int)
            or chunk_size <= 0
        ):
            raise SlidingWindowError(
                "chunk_size must be a positive integer."
            )

        self.engine = (
            engine if engine is not None
            else SignatureEngine()
        )

        self.chunk_size = chunk_size

        # Only signatures configured for embedded scanning
        # are considered by this scanner.
        self.signatures = tuple(
            signature
            for signature in self.engine.signatures
            if signature.scan_embedded
        )

        # Find the longest signature eligible for scanning.
        self.max_signature_length = max(
            (
                signature.length
                for signature in self.signatures
            ),
            default=0,
        )

        # Preserve enough bytes to detect signatures that
        # cross a chunk boundary.
        self.overlap = max(
            0,
            self.max_signature_length - 1,
        )

    # =================================================
    # SIGNATURE SEARCH
    # =================================================

    def iter_matches(
        self,
        file_path: Union[str, Path],
    ) -> Iterator[SignatureMatch]:
        """
        Yield detected embedded signature matches.

        A match is reported only when its final byte belongs
        to the newly read portion of the current window.

        This ownership rule prevents duplicate reporting
        across overlapping windows.
        """

        for (
            window_offset,
            new_data_offset,
            window_data,
        ) in iter_file_chunks(
            file_path=file_path,
            chunk_size=self.chunk_size,
            overlap=self.overlap,
        ):

            window_matches = []

            for signature in self.signatures:

                pattern = signature.magic_bytes
                pattern_length = len(pattern)

                search_position = 0

                # Find every occurrence, including overlapping
                # occurrences of the same byte pattern.
                while True:

                    match_position = window_data.find(
                        pattern,
                        search_position,
                    )

                    if match_position == -1:
                        break

                    absolute_offset = (
                        window_offset + match_position
                    )

                    absolute_end = (
                        absolute_offset + pattern_length
                    )

                    # Ownership rule:
                    # Report only if the match reaches into
                    # newly read data.
                    if absolute_end > new_data_offset:

                        match = SignatureMatch.from_signature(
                            signature,
                            absolute_offset,
                        )

                        window_matches.append(match)

                    # Advance by one to allow overlapping matches.
                    search_position = match_position + 1

            # Maintain deterministic ordering within each window.
            window_matches.sort(
                key=lambda item: (
                    item.offset,
                    item.signature_id,
                )
            )

            yield from window_matches

    # =================================================
    # COMPLETE SCAN
    # =================================================

    def scan_file(
        self,
        file_path: Union[str, Path],
    ) -> tuple:
        """
        Scan a complete file and return sorted matches.

        The result collection grows with the number of matches;
        file contents themselves are processed incrementally.
        """

        matches = list(self.iter_matches(file_path))

        matches.sort(
            key=lambda item: (
                item.offset,
                item.signature_id,
            )
        )

        return tuple(matches)

    def scan(
        self,
        file_path: Union[str, Path],
    ) -> tuple:
        """Alias for scan_file()."""

        return self.scan_file(file_path)


# =====================================================
# CONVENIENCE FUNCTION
# =====================================================

def scan_embedded_signatures(
    file_path: Union[str, Path],
    engine: Optional[SignatureEngine] = None,
    chunk_size: int = CHUNK_SIZE,
) -> tuple:
    """Scan a file without manually creating a scanner."""

    scanner = SlidingWindowScanner(
        engine=engine,
        chunk_size=chunk_size,
    )

    return scanner.scan_file(file_path)