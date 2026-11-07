"""
FILEX - Signature Database Engine

Loads, validates and provides access to binary file signatures.
"""

import json
import re

from pathlib import Path
from typing import Optional, Union

from config.settings import (
    MAX_SIGNATURE_DB_SIZE,
    SIGNATURE_DB_PATH,
)

from core.models import (
    FileSignature,
    SignatureDatabase,
)


# =====================================================
# CONSTANTS
# =====================================================

HEX_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2})+$")

REQUIRED_FIELDS = {
    "id",
    "name",
    "category",
    "mime_type",
    "extensions",
    "magic_hex",
    "offsets",
    "scan_embedded",
    "description",
}


# =====================================================
# CUSTOM EXCEPTION
# =====================================================

class SignatureDatabaseError(Exception):
    """Raised when the signature database is invalid."""


# =====================================================
# VALIDATION HELPERS
# =====================================================

def _validate_string(value, field_name, index):
    """Validate a non-empty string."""

    if not isinstance(value, str) or not value.strip():
        raise SignatureDatabaseError(
            f"Entry #{index}: '{field_name}' must be a non-empty string."
        )

    return value.strip()


def _validate_signature(entry, index):
    """Validate and convert one signature entry."""

    if not isinstance(entry, dict):
        raise SignatureDatabaseError(
            f"Entry #{index} must be a JSON object."
        )

    missing = REQUIRED_FIELDS - entry.keys()

    if missing:
        raise SignatureDatabaseError(
            f"Entry #{index} is missing fields: "
            f"{', '.join(sorted(missing))}"
        )

    signature_id = _validate_string(entry["id"], "id", index)
    name = _validate_string(entry["name"], "name", index)
    category = _validate_string(entry["category"], "category", index)
    mime_type = _validate_string(entry["mime_type"], "mime_type", index)
    description = _validate_string(
        entry["description"], "description", index
    )

    # Validate hexadecimal signature.
    magic_hex = _validate_string(
        entry["magic_hex"], "magic_hex", index
    )

    if not HEX_PATTERN.fullmatch(magic_hex):
        raise SignatureDatabaseError(
            f"Entry #{index}: invalid hexadecimal signature."
        )

    # Validate extensions.
    extensions = entry["extensions"]

    if not isinstance(extensions, list) or not extensions:
        raise SignatureDatabaseError(
            f"Entry #{index}: extensions must be a non-empty list."
        )

    valid_extensions = []

    for extension in extensions:

        if (
            not isinstance(extension, str)
            or len(extension) < 2
            or not extension.startswith(".")
            or "/" in extension
            or "\\" in extension
            or any(char.isspace() for char in extension)
        ):
            raise SignatureDatabaseError(
                f"Entry #{index}: invalid extension {extension!r}."
            )

        normalized = extension.lower()

        if normalized in valid_extensions:
            raise SignatureDatabaseError(
                f"Entry #{index}: duplicate extension {extension!r}."
            )

        valid_extensions.append(normalized)

    # Validate offsets.
    offsets = entry["offsets"]

    if not isinstance(offsets, list) or not offsets:
        raise SignatureDatabaseError(
            f"Entry #{index}: offsets must be a non-empty list."
        )

    valid_offsets = []

    for offset in offsets:

        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise SignatureDatabaseError(
                f"Entry #{index}: offsets must be non-negative integers."
            )

        if offset in valid_offsets:
            raise SignatureDatabaseError(
                f"Entry #{index}: duplicate offset {offset}."
            )

        valid_offsets.append(offset)

    # Validate embedded scanning flag.
    scan_embedded = entry["scan_embedded"]

    if not isinstance(scan_embedded, bool):
        raise SignatureDatabaseError(
            f"Entry #{index}: scan_embedded must be boolean."
        )

    return FileSignature(
        id=signature_id,
        name=name,
        category=category,
        mime_type=mime_type,
        extensions=tuple(valid_extensions),
        magic_hex=magic_hex.upper(),
        offsets=tuple(valid_offsets),
        scan_embedded=scan_embedded,
        description=description,
    )


# =====================================================
# DATABASE LOADER
# =====================================================

def load_signature_database(
    database_path: Optional[Union[str, Path]] = None,
) -> SignatureDatabase:
    """
    Load and validate the signature database.

    A configurable size limit prevents unexpectedly large
    database files from being loaded into memory.
    """

    path = Path(
        database_path
        if database_path is not None
        else SIGNATURE_DB_PATH
    )

    # Read the database with a strict size limit.
    try:
        if not path.is_file():
            raise SignatureDatabaseError(
                f"Signature database not found: {path}"
            )

        with path.open("rb") as database_file:
            raw_data = database_file.read(
                MAX_SIGNATURE_DB_SIZE + 1
            )

    except OSError as error:
        raise SignatureDatabaseError(
            f"Unable to read signature database: {error}"
        ) from error

    if len(raw_data) > MAX_SIGNATURE_DB_SIZE:
        raise SignatureDatabaseError(
            "Signature database exceeds the configured size limit."
        )

    # Decode JSON as UTF-8.
    try:
        decoded_data = raw_data.decode("utf-8")

    except UnicodeDecodeError as error:
        raise SignatureDatabaseError(
            "Signature database must use UTF-8 encoding."
        ) from error

    # Parse JSON.
    try:
        data = json.loads(decoded_data)

    except json.JSONDecodeError as error:
        raise SignatureDatabaseError(
            f"Invalid JSON at line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error

    if not isinstance(data, dict):
        raise SignatureDatabaseError(
            "Database root must be a JSON object."
        )

    # Validate database metadata.
    database_version = _validate_string(
        data.get("database_version"),
        "database_version",
        0,
    )

    description = _validate_string(
        data.get("description"),
        "description",
        0,
    )

    entries = data.get("signatures")

    if not isinstance(entries, list) or not entries:
        raise SignatureDatabaseError(
            "'signatures' must be a non-empty JSON list."
        )

    # Validate all signatures.
    signatures = []
    seen_ids = set()

    for index, entry in enumerate(entries, start=1):

        signature = _validate_signature(entry, index)

        normalized_id = signature.id.casefold()

        if normalized_id in seen_ids:
            raise SignatureDatabaseError(
                f"Duplicate signature ID: {signature.id}"
            )

        seen_ids.add(normalized_id)
        signatures.append(signature)

    return SignatureDatabase(
        database_version=database_version,
        description=description,
        signatures=tuple(signatures),
    )


# =====================================================
# CONVENIENCE FUNCTION
# =====================================================

def load_signatures(
    database_path: Optional[Union[str, Path]] = None,
) -> tuple:
    """Load the database and return its signatures."""

    database = load_signature_database(database_path)

    return database.signatures


# =====================================================
# SIGNATURE ENGINE
# =====================================================

class SignatureEngine:
    """Provides access to the validated signature database."""

    def __init__(
        self,
        database_path: Optional[Union[str, Path]] = None,
    ):

        self.database = load_signature_database(database_path)

        self.signatures = self.database.signatures

        self.max_signature_length = (
            self.database.max_signature_length
        )

    def get_signature(
        self,
        signature_id: str,
    ) -> Optional[FileSignature]:
        """Retrieve a signature using its ID."""

        return self.database.get_by_id(signature_id)