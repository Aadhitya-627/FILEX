"""High-level orchestration for the FILEX analysis pipeline."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union
import os

from config.settings import (
    CHUNK_SIZE,
    ENTROPY_THRESHOLD,
    ENTROPY_WINDOW_SIZE,
    MAX_EXTRACTION_SIZE,
)
from core.entropy import EntropyAnalyzer
from core.file_carver import FileCarver
from core.file_identifier import FileIdentifier
from core.models import EntropyAnalysisResult, FileIdentificationResult, SignatureMatch, CarvedFileCandidate
from core.signature_engine import SignatureEngine
from core.sliding_window import SlidingWindowScanner
from core.yara_scanner import (
    YaraScanner, YaraScanResult, YaraScanError, YaraUnavailableError,
)


class ScanError(Exception):
    """Raised when the complete analysis pipeline fails."""


@dataclass(frozen=True)
class FileAnalysisReport:
    file_path: Path
    file_size: int
    identification: FileIdentificationResult
    embedded_matches: tuple[SignatureMatch, ...]
    entropy: EntropyAnalysisResult
    candidates: tuple[CarvedFileCandidate, ...]
    yara: Optional[YaraScanResult] = None

    def to_dict(self) -> dict:
        return {
            "application": "FILEX",
            "report_version": "1.0",
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "identification": self.identification.to_dict(),
            "embedded_matches": [item.to_dict() for item in self.embedded_matches],
            "entropy": self.entropy.to_dict(),
            "carving_candidates": [item.to_dict() for item in self.candidates],
            "yara": self.yara.to_dict() if self.yara else None,
            "interpretation_notes": [
                "High entropy is a triage indicator, not proof of malware or encryption.",
                "Carving boundaries are heuristic and do not establish file validity.",
                "Extracted data is untrusted and must not be executed.",
            ],
        }


class FileXScanner:
    """Run identification, embedded scanning, entropy and carving."""

    def __init__(
        self,
        engine: Optional[SignatureEngine] = None,
        chunk_size: int = CHUNK_SIZE,
        entropy_window_size: int = ENTROPY_WINDOW_SIZE,
        entropy_threshold: float = ENTROPY_THRESHOLD,
        max_candidate_size: int = MAX_EXTRACTION_SIZE,
    ) -> None:
        self.engine = engine or SignatureEngine()
        self.identifier = FileIdentifier(self.engine)
        self.embedded_scanner = SlidingWindowScanner(self.engine, chunk_size)
        self.entropy_analyzer = EntropyAnalyzer(entropy_window_size, entropy_threshold)
        self.carver = FileCarver(self.engine, chunk_size, max_candidate_size)

    def analyze_file(
        self,
        file_path: Union[str, Path],
        yara_rules: Optional[Union[str, Path]] = None,
    ) -> FileAnalysisReport:
        path = Path(file_path).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ScanError("Input must be an existing regular, non-symlink file.")
        try:
            before = path.stat()
            identification = self.identifier.identify(path)
            embedded_matches = self.embedded_scanner.scan_file(path)
            entropy = self.entropy_analyzer.analyze_file(path)
            candidates = self.carver.carve(path)
            yara_result = YaraScanner().scan(path, yara_rules) if yara_rules else None
            after = path.stat()
        except (YaraScanError, YaraUnavailableError):
            raise
        except Exception as error:
            if isinstance(error, ScanError):
                raise
            raise ScanError(str(error)) from error
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size, after.st_mtime_ns, after.st_ino
        ):
            raise ScanError("Input file changed during analysis; results were discarded.")
        return FileAnalysisReport(
            file_path=path,
            file_size=after.st_size,
            identification=identification,
            embedded_matches=embedded_matches,
            entropy=entropy,
            candidates=candidates,
            yara=yara_result,
        )

    def scan(self, file_path: Union[str, Path], **kwargs) -> FileAnalysisReport:
        return self.analyze_file(file_path, **kwargs)
