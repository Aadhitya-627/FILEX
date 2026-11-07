"""Optional YARA integration. YARA is never required for core FILEX use."""

from dataclasses import dataclass
from pathlib import Path
from typing import Union

from config.settings import YARA_TIMEOUT_SECONDS


class YaraUnavailableError(Exception):
    """Raised when yara-python is not installed."""


class YaraScanError(Exception):
    """Raised when YARA rules or scanning fail."""


@dataclass(frozen=True)
class YaraScanResult:
    file_path: Path
    rules_path: Path
    matches: tuple

    @property
    def match_count(self) -> int:
        return len(self.matches)

    def to_dict(self) -> dict:
        return {
            "file_path": str(self.file_path),
            "rules_path": str(self.rules_path),
            "match_count": self.match_count,
            "matches": list(self.matches),
        }


class YaraScanner:
    """Compile a user-supplied rules file and scan a regular file."""

    def scan(self, file_path: Union[str, Path], rules_path: Union[str, Path]) -> YaraScanResult:
        target = Path(file_path)
        rules_file = Path(rules_path)
        if target.is_symlink() or not target.is_file():
            raise YaraScanError("YARA target must be a regular, non-symlink file.")
        if rules_file.is_symlink() or not rules_file.is_file():
            raise YaraScanError("YARA rules path must be a regular, non-symlink file.")
        try:
            import yara  # type: ignore
        except ImportError as error:
            raise YaraUnavailableError(
                "Optional dependency 'yara-python' is not installed. "
                "Install it with: pip install 'filex[yara]'"
            ) from error
        try:
            rules = yara.compile(filepath=str(rules_file))
            raw_matches = rules.match(filepath=str(target), timeout=YARA_TIMEOUT_SECONDS)
            matches = tuple(
                {
                    "rule": str(match.rule),
                    "namespace": str(getattr(match, "namespace", "default")),
                    "tags": list(getattr(match, "tags", ())),
                    "meta": dict(getattr(match, "meta", {})),
                }
                for match in raw_matches
            )
        except Exception as error:
            raise YaraScanError(f"YARA scan failed: {error}") from error
        return YaraScanResult(target, rules_file, matches)
