"""FILEX command-line entry point."""

import argparse
import json
import sys
from pathlib import Path

from config.settings import APP_NAME, APP_VERSION, MAX_EXTRACTION_SIZE, MAX_TOTAL_EXTRACTION_SIZE
from core.entropy import EntropyAnalysisError
from core.extraction import SafeExtractor, ExtractionError
from core.file_carver import FileCarver, FileCarvingError
from core.file_identifier import FileIdentifier, FileIdentificationError
from core.scanner import FileXScanner, ScanError
from core.sliding_window import SlidingWindowError
from core.signature_engine import SignatureDatabaseError
from core.yara_scanner import YaraScanError, YaraUnavailableError
from utils.formatters import render_text_report, write_csv_report, write_json_report
from utils.logger import get_logger
from utils.validators import ValidationError, validate_input_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filex",
        description="FILEX: defensive binary file identification and analysis.",
        epilog="Extracted data is untrusted and is never executed by FILEX.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run the complete analysis pipeline")
    scan.add_argument("file", help="Input file to analyze")
    scan.add_argument("--chunk-size", type=int, default=4096)
    scan.add_argument("--entropy-window-size", type=int, default=4096)
    scan.add_argument("--entropy-threshold", type=float, default=7.2)
    scan.add_argument("--max-candidate-size", type=int, default=MAX_EXTRACTION_SIZE)
    scan.add_argument("--yara-rules", help="Optional YARA rules file (requires yara-python)")
    scan.add_argument("--json-out", help="Write JSON report; existing files are not overwritten")
    scan.add_argument("--csv-out", help="Write CSV report; existing files are not overwritten")

    identify = subparsers.add_parser("identify", help="Identify formats from registered header offsets")
    identify.add_argument("file")

    carve = subparsers.add_parser("carve", help="List heuristic embedded-file candidates")
    carve.add_argument("file")
    carve.add_argument("--chunk-size", type=int, default=4096)
    carve.add_argument("--max-candidate-size", type=int, default=MAX_EXTRACTION_SIZE)
    carve.add_argument("--json-out", help="Write candidate JSON; do not overwrite")

    extract = subparsers.add_parser("extract", help="Safely extract selected carving candidates")
    extract.add_argument("file")
    selection = extract.add_mutually_exclusive_group(required=True)
    selection.add_argument("--index", type=int, help="Zero-based candidate index from the carve command")
    selection.add_argument("--all", action="store_true", help="Extract all detected candidates")
    extract.add_argument("--output-dir", default="extracted")
    extract.add_argument("--max-output-size", type=int, default=MAX_EXTRACTION_SIZE)
    extract.add_argument("--max-total-output-size", type=int, default=MAX_TOTAL_EXTRACTION_SIZE)
    extract.add_argument("--chunk-size", type=int, default=4096)

    return parser


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def run(args: argparse.Namespace) -> int:
    logger = get_logger()
    try:
        input_path = validate_input_file(args.file)
        if args.command == "identify":
            result = FileIdentifier().identify(input_path)
            _print_json(result.to_dict())
            return 0

        if args.command == "carve":
            candidates = FileCarver(
                chunk_size=args.chunk_size,
                max_candidate_size=args.max_candidate_size,
            ).carve(input_path)
            data = {"file_path": str(input_path), "candidate_count": len(candidates),
                    "candidates": [candidate.to_dict() for candidate in candidates],
                    "note": "Candidate boundaries are heuristic."}
            _print_json(data)
            if args.json_out:
                json_path = Path(args.json_out).expanduser()
                json_path.parent.mkdir(parents=True, exist_ok=True)
                with json_path.open("x", encoding="utf-8") as target:
                    json.dump(data, target, indent=2)
                    target.write("\n")
                print(f"JSON written to: {args.json_out}")
            return 0

        if args.command == "extract":
            candidates = FileCarver().carve(input_path)
            if not candidates:
                print("No carving candidates were detected.")
                return 0
            if args.all:
                selected = candidates
            else:
                if args.index < 0 or args.index >= len(candidates):
                    raise ValidationError(
                        f"Candidate index must be between 0 and {len(candidates) - 1}."
                    )
                selected = (candidates[args.index],)
            extractor = SafeExtractor(
                output_dir=args.output_dir,
                max_output_size=args.max_output_size,
                max_total_output_size=args.max_total_output_size,
                chunk_size=args.chunk_size,
            )
            results = extractor.extract_many(selected)
            _print_json({"extracted_count": len(results),
                         "results": [result.to_dict() for result in results]})
            return 0

        if args.command == "scan":
            report = FileXScanner(
                chunk_size=args.chunk_size,
                entropy_window_size=args.entropy_window_size,
                entropy_threshold=args.entropy_threshold,
                max_candidate_size=args.max_candidate_size,
            ).analyze_file(input_path, yara_rules=args.yara_rules)
            print(render_text_report(report))
            if args.json_out:
                print(f"JSON report: {write_json_report(report, args.json_out)}")
            if args.csv_out:
                print(f"CSV report: {write_csv_report(report, args.csv_out)}")
            return 0

    except (ValidationError, FileIdentificationError, FileCarvingError,
            ExtractionError, ScanError, SignatureDatabaseError,
            EntropyAnalysisError, SlidingWindowError, YaraScanError, YaraUnavailableError,
            OSError, ValueError) as error:
        logger.error(str(error))
        return 2
    return 2


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
