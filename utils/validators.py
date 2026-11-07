"""Shared input validators used by the CLI and application layer."""

from pathlib import Path
from typing import Union


class ValidationError(ValueError):
    """Raised when a user-supplied value is invalid."""


def validate_input_file(value: Union[str, Path]) -> Path:
    try:
        path = Path(value).expanduser()
    except (TypeError, ValueError) as error:
        raise ValidationError("Invalid input file path.") from error
    if path.is_symlink():
        raise ValidationError("Symbolic-link input files are not accepted.")
    if not path.exists():
        raise ValidationError(f"Input file does not exist: {path}")
    if not path.is_file():
        raise ValidationError(f"Input path is not a regular file: {path}")
    return path.resolve(strict=True)


def validate_positive_int(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationError(f"{label} must be a positive integer.")
    return value
