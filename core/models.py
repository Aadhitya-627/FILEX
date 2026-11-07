"""
FILEX - Core Data Models

Contains shared data structures used by the signature engine,
file identifier, scanner and reporting modules.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# =====================================================
# FILE SIGNATURE MODEL
# =====================================================

@dataclass(frozen=True)
class FileSignature:
    """Represents one validated binary file signature."""

    id: str
    name: str
    category: str
    mime_type: str
    extensions: tuple
    magic_hex: str
    offsets: tuple
    scan_embedded: bool
    description: str

    @property
    def magic_bytes(self) -> bytes:
        """Convert hexadecimal signature into binary bytes."""
        return bytes.fromhex(self.magic_hex)

    @property
    def length(self) -> int:
        """Return signature length in bytes."""
        return len(self.magic_bytes)


# =====================================================
# SIGNATURE DATABASE MODEL
# =====================================================

@dataclass(frozen=True)
class SignatureDatabase:
    """Represents a complete validated signature database."""

    database_version: str
    description: str
    signatures: tuple

    @property
    def max_signature_length(self) -> int:
        """Return the length of the longest signature."""

        return max(
            (signature.length for signature in self.signatures),
            default=0,
        )

    def get_by_id(self, signature_id: str) -> Optional[FileSignature]:
        """Retrieve a signature using its unique ID."""

        for signature in self.signatures:
            if signature.id == signature_id:
                return signature

        return None


# =====================================================
# SIGNATURE MATCH MODEL
# =====================================================

@dataclass(frozen=True)
class SignatureMatch:
    """Represents a signature detected inside a file."""

    signature_id: str
    name: str
    category: str
    mime_type: str
    extensions: tuple
    offset: int
    magic_hex: str
    description: str

    @classmethod
    def from_signature(
        cls,
        signature: FileSignature,
        offset: int,
    ):
        """Create a match from a validated signature."""

        return cls(
            signature_id=signature.id,
            name=signature.name,
            category=signature.category,
            mime_type=signature.mime_type,
            extensions=signature.extensions,
            offset=offset,
            magic_hex=signature.magic_hex,
            description=signature.description,
        )

    def to_dict(self) -> dict:
        """Convert match information into JSON-friendly data."""

        return {
            "signature_id": self.signature_id,
            "name": self.name,
            "category": self.category,
            "mime_type": self.mime_type,
            "extensions": list(self.extensions),
            "offset": self.offset,
            "magic_hex": self.magic_hex,
            "description": self.description,
        }


# =====================================================
# FILE IDENTIFICATION RESULT
# =====================================================

@dataclass(frozen=True)
class FileIdentificationResult:
    """Contains the result of file format identification."""

    file_path: Path
    file_size: int
    extension: str
    matches: tuple

    @property
    def detected(self) -> bool:
        """Check whether at least one signature was detected."""

        return bool(self.matches)

    @property
    def primary_match(self) -> Optional[SignatureMatch]:
        """Return the first detected signature."""

        if not self.matches:
            return None

        return self.matches[0]

    @property
    def extension_status(self) -> str:
        """
        Compare detected format extensions with the file extension.

        Returns:
            match, mismatch or unknown.
        """

        if not self.matches:
            return "unknown"

        for match in self.matches:
            if self.extension in match.extensions:
                return "match"

        return "mismatch"

    @property
    def extension_mismatch(self) -> Optional[bool]:
        """Return whether the extension conflicts with detection."""

        if not self.detected:
            return None

        return self.extension_status == "mismatch"

    def to_dict(self) -> dict:
        """Convert the complete identification result into a dictionary."""

        primary = self.primary_match

        return {
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "extension": self.extension,
            "detected": self.detected,
            "extension_status": self.extension_status,
            "extension_mismatch": self.extension_mismatch,
            "primary_match": (
                primary.to_dict() if primary else None
            ),
            "matches": [
                match.to_dict() for match in self.matches
            ],
        }

        # =====================================================
# ENTROPY ANALYSIS MODELS
# =====================================================

@dataclass(frozen=True)
class EntropyWindowResult:
    """Stores the entropy analysis of one file window."""

    offset: int
    size: int
    entropy: float
    high_entropy: bool

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "size": self.size,
            "entropy": round(self.entropy, 4),
            "high_entropy": self.high_entropy,
        }


@dataclass(frozen=True)
class EntropyAnalysisResult:
    """Stores the complete entropy analysis of a file."""

    file_path: Path
    file_size: int
    window_size: int
    threshold: float
    windows: tuple

    @property
    def window_count(self) -> int:
        return len(self.windows)

    @property
    def high_entropy_windows(self) -> tuple:
        return tuple(
            window for window in self.windows
            if window.high_entropy
        )

    @property
    def high_entropy_count(self) -> int:
        return len(self.high_entropy_windows)

    @property
    def high_entropy_ratio(self) -> float:
        if not self.windows:
            return 0.0

        return self.high_entropy_count / self.window_count

    @property
    def average_window_entropy(self) -> float:
        """Calculate a size-weighted average of window entropy."""

        if self.file_size == 0:
            return 0.0

        weighted_total = sum(
            window.entropy * window.size
            for window in self.windows
        )

        return weighted_total / self.file_size

    @property
    def maximum_entropy(self) -> float:
        if not self.windows:
            return 0.0

        return max(window.entropy for window in self.windows)

    def to_dict(self) -> dict:
        """Return a JSON-friendly entropy report."""

        return {
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "window_size": self.window_size,
            "threshold": self.threshold,
            "window_count": self.window_count,
            "high_entropy_count": self.high_entropy_count,
            "high_entropy_ratio": round(
                self.high_entropy_ratio, 4
            ),
            "average_window_entropy": round(
                self.average_window_entropy, 4
            ),
            "maximum_entropy": round(
                self.maximum_entropy, 4
            ),
            "high_entropy_windows": [
                window.to_dict()
                for window in self.high_entropy_windows
            ],
            "windows": [
                window.to_dict()
                for window in self.windows
            ],
        }

# =====================================================
# FILE CARVING MODEL
# =====================================================

@dataclass(frozen=True)
class CarvedFileCandidate:
    """
    Represents a possible embedded file region.

    The offsets describe a candidate byte range.
    They do not prove that the candidate is a complete,
    valid file.
    """

    source_path: Path
    signature_id: str
    name: str
    category: str
    mime_type: str
    extensions: tuple
    start_offset: int
    end_offset: int
    boundary_reason: str

    @property
    def size(self) -> int:
        """Return candidate size in bytes."""

        return self.end_offset - self.start_offset

    def to_dict(self) -> dict:
        """Convert candidate metadata into JSON-friendly data."""

        return {
            "source_path": str(self.source_path),
            "signature_id": self.signature_id,
            "name": self.name,
            "category": self.category,
            "mime_type": self.mime_type,
            "extensions": list(self.extensions),
            "start_offset": self.start_offset,
            "end_offset_exclusive": self.end_offset,
            "size": self.size,
            "boundary_reason": self.boundary_reason,
        }