"""Bounded, defensive extraction of FILEX carving candidates.

Extracted data is always treated as untrusted data. FILEX never executes it.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Union

from config.settings import (
    CHUNK_SIZE,
    EXTRACTED_DIR,
    MAX_EXTRACTION_SIZE,
    MAX_TOTAL_EXTRACTION_SIZE,
)
from core.models import CarvedFileCandidate


class ExtractionError(Exception):
    """Raised when a candidate cannot be extracted safely."""


@dataclass(frozen=True)
class ExtractionResult:
    """Metadata for one successfully extracted candidate."""

    source_path: Path
    output_path: Path
    signature_id: str
    start_offset: int
    end_offset: int
    bytes_written: int
    sha256: str
    integrity_verified: bool

    def to_dict(self) -> dict:
        return {
            "source_path": str(self.source_path),
            "output_path": str(self.output_path),
            "signature_id": self.signature_id,
            "start_offset": self.start_offset,
            "end_offset_exclusive": self.end_offset,
            "bytes_written": self.bytes_written,
            "sha256": self.sha256,
            "integrity_verified": self.integrity_verified,
            "status": "success" if self.integrity_verified else "failed",
        }


class SafeExtractor:
    """Extract candidate byte ranges with strict filesystem safeguards."""

    def __init__(
        self,
        output_dir: Union[str, Path] = EXTRACTED_DIR,
        max_output_size: int = MAX_EXTRACTION_SIZE,
        max_total_output_size: int = MAX_TOTAL_EXTRACTION_SIZE,
        chunk_size: int = CHUNK_SIZE,
    ) -> None:
        self.max_output_size = self._positive_int(max_output_size, "max_output_size")
        self.max_total_output_size = self._positive_int(
            max_total_output_size, "max_total_output_size"
        )
        self.chunk_size = self._positive_int(chunk_size, "chunk_size")
        if self.max_output_size > self.max_total_output_size:
            raise ExtractionError(
                "max_output_size cannot exceed max_total_output_size."
            )
        try:
            requested_dir = Path(output_dir).expanduser()
            requested_dir.mkdir(parents=True, exist_ok=True)
            self.output_dir = requested_dir.resolve(strict=True)
        except (OSError, TypeError, ValueError) as error:
            raise ExtractionError(f"Invalid extraction directory: {error}") from error
        if not self.output_dir.is_dir():
            raise ExtractionError("Extraction destination is not a directory.")
        self._total_bytes_written = 0

    @staticmethod
    def _positive_int(value: int, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ExtractionError(f"{field} must be a positive integer.")
        return value

    @staticmethod
    def _safe_stem(signature_id: str) -> str:
        stem = re.sub(r"[^A-Za-z0-9_-]+", "_", str(signature_id)).strip("._-")
        return (stem[:48] or "unknown").lower()

    @staticmethod
    def _safe_extension(extensions: Iterable[str]) -> str:
        for extension in extensions or ():
            if isinstance(extension, str) and re.fullmatch(r"\.[A-Za-z0-9]{1,10}", extension):
                return extension.lower()
        return ".bin"

    def _validate_candidate(self, candidate: CarvedFileCandidate) -> tuple[Path, int, int, int]:
        required = ("source_path", "signature_id", "start_offset", "end_offset", "extensions")
        if any(not hasattr(candidate, field) for field in required):
            raise ExtractionError("Candidate is missing required metadata.")
        try:
            source_path = Path(candidate.source_path).expanduser()
        except (TypeError, ValueError) as error:
            raise ExtractionError("Candidate source path is invalid.") from error
        if source_path.is_symlink():
            raise ExtractionError("Symbolic-link source files are not accepted.")
        if not source_path.is_file():
            raise ExtractionError("Candidate source must be an existing regular file.")
        start = candidate.start_offset
        end = candidate.end_offset
        for value, label in ((start, "start_offset"), (end, "end_offset")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ExtractionError(f"{label} must be a non-negative integer.")
        if end <= start:
            raise ExtractionError("Candidate end_offset must be greater than start_offset.")
        size = end - start
        if size > self.max_output_size:
            raise ExtractionError(
                f"Candidate size ({size} bytes) exceeds the per-file output limit "
                f"({self.max_output_size} bytes)."
            )
        if self._total_bytes_written + size > self.max_total_output_size:
            raise ExtractionError("Extraction would exceed the total output-size limit.")
        return source_path, start, end, size

    def _reserve_destination(self, signature_id: str, offset: int, extension: str):
        stem = f"filex_{self._safe_stem(signature_id)}_{offset:016x}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        for suffix in range(10000):
            tail = "" if suffix == 0 else f"_{suffix}"
            destination = self.output_dir / f"{stem}{tail}{extension}"
            try:
                descriptor = os.open(destination, flags, 0o600)
                try:
                    return destination, os.fdopen(descriptor, "wb")
                except BaseException:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    destination.unlink(missing_ok=True)
                    raise
            except FileExistsError:
                continue
            except OSError as error:
                raise ExtractionError(f"Unable to create output file: {error}") from error
        raise ExtractionError("Could not reserve a unique output filename.")

    def extract(self, candidate: CarvedFileCandidate) -> ExtractionResult:
        """Copy and verify one candidate without overwriting existing files."""
        source_path, start, end, size = self._validate_candidate(candidate)
        destination = None
        source_hash = hashlib.sha256()
        bytes_written = 0
        try:
            source_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                source_flags |= os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                source_flags |= os.O_NONBLOCK
            source_fd = os.open(source_path, source_flags)
            with os.fdopen(source_fd, "rb") as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ExtractionError("Candidate source is not a regular file.")
                if end > before.st_size:
                    raise ExtractionError("Candidate range extends beyond the source file.")
                source.seek(start)
                destination, output = self._reserve_destination(
                    candidate.signature_id,
                    start,
                    self._safe_extension(candidate.extensions),
                )
                with output:
                    remaining = size
                    while remaining:
                        block = source.read(min(self.chunk_size, remaining))
                        if not block:
                            raise ExtractionError("Unexpected end of source during extraction.")
                        output.write(block)
                        source_hash.update(block)
                        bytes_written += len(block)
                        remaining -= len(block)
                    output.flush()
                    os.fsync(output.fileno())
                after = os.fstat(source.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size, after.st_mtime_ns, after.st_ino
                ):
                    raise ExtractionError("Source file changed during extraction.")
            # Re-read the new file without following a replaced symlink.
            output_hash = hashlib.sha256()
            verified_size = 0
            verify_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                verify_flags |= os.O_NOFOLLOW
            verify_fd = os.open(destination, verify_flags)
            with os.fdopen(verify_fd, "rb") as extracted:
                verify_stat = os.fstat(extracted.fileno())
                if not stat.S_ISREG(verify_stat.st_mode):
                    raise ExtractionError("Extracted output is not a regular file.")
                if verify_stat.st_size != size:
                    raise ExtractionError("Extracted output size does not match candidate size.")
                while True:
                    block = extracted.read(self.chunk_size)
                    if not block:
                        break
                    output_hash.update(block)
                    verified_size += len(block)
            source_digest = source_hash.hexdigest()
            if verified_size != size or bytes_written != size or output_hash.hexdigest() != source_digest:
                raise ExtractionError("Extracted-file integrity verification failed.")
            self._total_bytes_written += bytes_written
            return ExtractionResult(
                source_path=source_path,
                output_path=destination,
                signature_id=str(candidate.signature_id),
                start_offset=start,
                end_offset=end,
                bytes_written=bytes_written,
                sha256=source_digest,
                integrity_verified=True,
            )
        except BaseException as error:
            if destination is not None:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
            if isinstance(error, (ExtractionError, KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(error, (OSError, ValueError, TypeError)):
                raise ExtractionError(f"Extraction failed: {error}") from error
            raise

    def extract_many(self, candidates: Iterable[CarvedFileCandidate]) -> tuple[ExtractionResult, ...]:
        """Extract a batch atomically with respect to FILEX-created outputs.

        If any candidate fails, outputs created earlier in this batch are
        removed and the extractor's byte budget is restored.
        """
        results = []
        try:
            for candidate in candidates:
                results.append(self.extract(candidate))
        except BaseException:
            for result in reversed(results):
                try:
                    result.output_path.unlink(missing_ok=True)
                except OSError:
                    pass
            self._total_bytes_written = max(
                0, self._total_bytes_written - sum(item.bytes_written for item in results)
            )
            raise
        return tuple(results)


# Backward-friendly convenience function.
def extract_candidate(
    candidate: CarvedFileCandidate,
    output_dir: Union[str, Path] = EXTRACTED_DIR,
    max_output_size: int = MAX_EXTRACTION_SIZE,
) -> ExtractionResult:
    return SafeExtractor(
        output_dir=output_dir,
        max_output_size=max_output_size,
        max_total_output_size=max(max_output_size, MAX_TOTAL_EXTRACTION_SIZE),
    ).extract(candidate)
