"""
FILEX - File Identification Engine

Identifies file formats using validated binary signatures.

This module checks configured offsets only.
It does not execute, modify or extract the target file.
"""

import os

from pathlib import Path
from typing import Optional, Union

from core.models import (
    FileIdentificationResult,
    SignatureMatch,
)

from core.signature_engine import (
    SignatureEngine,
)


# =====================================================
# CUSTOM EXCEPTION
# =====================================================

class FileIdentificationError(Exception):
    """Raised when file identification cannot be completed."""


# =====================================================
# FILE IDENTIFIER
# =====================================================

class FileIdentifier:
    """Identifies file formats using a signature database."""

    def __init__(
        self,
        engine: Optional[SignatureEngine] = None,
    ):

        # Reuse an existing engine if one is supplied.
        self.engine = engine if engine is not None else SignatureEngine()

    def identify(
        self,
        file_path: Union[str, Path],
    ) -> FileIdentificationResult:
        """
        Identify a file using signatures at configured offsets.

        Args:
            file_path: Path to the file being analyzed.

        Returns:
            FileIdentificationResult containing all matches.

        Raises:
            FileIdentificationError: If the file cannot be analyzed.
        """

        try:
            path = Path(file_path)

        except (TypeError, ValueError) as error:
            raise FileIdentificationError(
                "Invalid file path."
            ) from error

        if not path.exists():
            raise FileIdentificationError(
                f"File does not exist: {path}"
            )

        if not path.is_file():
            raise FileIdentificationError(
                f"Path is not a regular file: {path}"
            )

        matches = []

        # Open target as read-only binary data.
        try:
            with path.open("rb") as target:

                # Obtain size from the opened file.
                file_size = os.fstat(target.fileno()).st_size

                for signature in self.engine.signatures:

                    signature_bytes = signature.magic_bytes
                    signature_length = signature.length

                    for offset in signature.offsets:

                        # Skip offsets that cannot contain
                        # the complete signature.
                        if offset + signature_length > file_size:
                            continue

                        # Read only the required bytes.
                        target.seek(offset)

                        file_bytes = target.read(signature_length)

                        if file_bytes == signature_bytes:

                            matches.append(
                                SignatureMatch.from_signature(
                                    signature,
                                    offset,
                                )
                            )

        except OSError as error:
            raise FileIdentificationError(
                f"Unable to read target file: {error}"
            ) from error

        # Keep the result order deterministic.
        matches.sort(key=lambda match: match.offset)

        # Extract the filename extension.
        extension = path.suffix.lower()

        return FileIdentificationResult(
            file_path=path,
            file_size=file_size,
            extension=extension,
            matches=tuple(matches),
        )

    def identify_file(
        self,
        file_path: Union[str, Path],
    ) -> FileIdentificationResult:
        """Alternative method name for identification."""

        return self.identify(file_path)


# =====================================================
# CONVENIENCE FUNCTION
# =====================================================

def identify_file(
    file_path: Union[str, Path],
    engine: Optional[SignatureEngine] = None,
) -> FileIdentificationResult:
    """Identify a file without manually creating FileIdentifier."""

    identifier = FileIdentifier(engine=engine)

    return identifier.identify(file_path)