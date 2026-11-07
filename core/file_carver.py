
"""
FILEX - File Carving Engine

Identifies possible embedded file regions using registered
binary signatures and calculates candidate byte boundaries.

This module does not extract, execute or modify file contents.
Candidate boundaries are heuristic unless format-specific
validation is added.
"""

from bisect import bisect_right
from pathlib import Path
from typing import Optional, Union

from config.settings import (
    MAX_EXTRACTION_SIZE,
    CHUNK_SIZE,
)

from core.models import CarvedFileCandidate

from core.signature_engine import (
    SignatureEngine,
)

from core.sliding_window import (
    SlidingWindowScanner,
    SlidingWindowError,
)


# =====================================================
# CUSTOM EXCEPTION
# =====================================================

class FileCarvingError(Exception):
    """Raised when file carving cannot be completed."""


# =====================================================
# FILE CARVER
# =====================================================

class FileCarver:
    """Detects candidate embedded file regions."""

    def __init__(
        self,
        engine: Optional[SignatureEngine] = None,
        chunk_size: int = CHUNK_SIZE,
        max_candidate_size: int = MAX_EXTRACTION_SIZE,
    ):
        """
        Initialize the file carver.

        Args:
            engine:
                Existing validated signature engine.

            chunk_size:
                Number of new bytes read per scanner chunk.

            max_candidate_size:
                Maximum size of a single candidate region.
        """

        if (
            isinstance(max_candidate_size, bool)
            or not isinstance(max_candidate_size, int)
            or max_candidate_size <= 0
        ):
            raise FileCarvingError(
                "Maximum candidate size must be a positive integer."
            )

        self.engine = (
            engine if engine is not None
            else SignatureEngine()
        )

        self.scanner = SlidingWindowScanner(
            engine=self.engine,
            chunk_size=chunk_size,
        )

        if max_candidate_size < self.scanner.max_signature_length:
            raise FileCarvingError(
                "Maximum candidate size must be at least "
                "the longest embedded signature length."
            )

        self.max_candidate_size = max_candidate_size

    # =================================================
    # FILE VALIDATION
    # =================================================

    @staticmethod
    def _validate_file(file_path: Union[str, Path]) -> Path:
        """Validate the source file path."""

        try:
            path = Path(file_path)

        except (TypeError, ValueError) as error:
            raise FileCarvingError(
                "Invalid source file path."
            ) from error

        if not path.exists():
            raise FileCarvingError(
                f"Source file does not exist: {path}"
            )

        if not path.is_file():
            raise FileCarvingError(
                f"Source path is not a regular file: {path}"
            )

        return path

    # =================================================
    # CANDIDATE CREATION
    # =================================================

    def carve(
        self,
        file_path: Union[str, Path],
    ) -> tuple:
        """
        Find candidate embedded file regions.

        Candidate starts come from detected signature offsets.

        Candidate ends are determined using:
        1. The next distinct signature offset.
        2. The maximum candidate size.
        3. The source file boundary.

        Returns:
            A tuple of CarvedFileCandidate objects.
        """

        path = self._validate_file(file_path)

        try:
            initial_stat = path.stat()

            # Reuse the Phase 3.5 sliding-window scanner.
            matches = self.scanner.scan_file(path)

            final_stat = path.stat()

        except SlidingWindowError as error:
            raise FileCarvingError(
                f"Signature scanning failed: {error}"
            ) from error

        except OSError as error:
            raise FileCarvingError(
                f"Unable to inspect source file: {error}"
            ) from error

        # Avoid using offsets if the file changed during scanning.
        if (
            initial_stat.st_size != final_stat.st_size
            or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
            or initial_stat.st_ino != final_stat.st_ino
        ):
            raise FileCarvingError(
                "Source file changed during scanning. "
                "Please retry with a stable file."
            )

        file_size = final_stat.st_size

        if not matches:
            return ()

        # Collect distinct start offsets.
        # Multiple signatures can theoretically occur at the same offset.
        unique_offsets = sorted({
            match.offset
            for match in matches
        })

        candidates = []

        for match in matches:

            start_offset = match.offset

            # Locate the next distinct signature position.
            next_index = bisect_right(
                unique_offsets,
                start_offset,
            )

            next_offset = (
                unique_offsets[next_index]
                if next_index < len(unique_offsets)
                else None
            )

            # Natural boundary based on the next signature or EOF.
            natural_end = (
                next_offset
                if next_offset is not None
                else file_size
            )

            # Apply the configured size limit.
            maximum_end = min(
                start_offset + self.max_candidate_size,
                file_size,
            )

            end_offset = min(
                natural_end,
                maximum_end,
            )

            # Determine why the candidate ended.
            if (
                start_offset + self.max_candidate_size
                < natural_end
            ):
                boundary_reason = "max_size_limit"

            elif next_offset is not None:
                boundary_reason = "next_detected_signature"

            else:
                boundary_reason = "end_of_file"

            # A valid detected signature should always occupy
            # bytes inside the candidate range.
            if end_offset <= start_offset:
                continue

            candidate = CarvedFileCandidate(
                source_path=path,
                signature_id=match.signature_id,
                name=match.name,
                category=match.category,
                mime_type=match.mime_type,
                extensions=match.extensions,
                start_offset=start_offset,
                end_offset=end_offset,
                boundary_reason=boundary_reason,
            )

            candidates.append(candidate)

        # Deterministic result ordering.
        candidates.sort(
            key=lambda item: (
                item.start_offset,
                item.signature_id,
            )
        )

        return tuple(candidates)

    # =================================================
    # ALTERNATIVE METHOD NAMES
    # =================================================

    def find_candidates(
        self,
        file_path: Union[str, Path],
    ) -> tuple:
        """Alias for carve()."""

        return self.carve(file_path)

    def carve_file(
        self,
        file_path: Union[str, Path],
    ) -> tuple:
        """Alias for carve()."""

        return self.carve(file_path)


# =====================================================
# CONVENIENCE FUNCTION
# =====================================================

def carve_file(
    file_path: Union[str, Path],
    engine: Optional[SignatureEngine] = None,
    chunk_size: int = CHUNK_SIZE,
    max_candidate_size: int = MAX_EXTRACTION_SIZE,
) -> tuple:
    """Find carving candidates without manual initialization."""

    carver = FileCarver(
        engine=engine,
        chunk_size=chunk_size,
        max_candidate_size=max_candidate_size,
    )

    return carver.carve(file_path)
