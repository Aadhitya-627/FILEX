# FILEX — Defensive Binary File Analysis

FILEX is a local Python command-line utility for identifying registered file formats, finding embedded binary signatures, reviewing entropy patterns, and creating cautious carving candidates. It includes bounded, integrity-checked extraction and JSON/CSV reporting.

> **Safety note:** FILEX is an analysis aid, not an antivirus product or malware verdict engine. High entropy is not proof of encryption or malware. Carving boundaries are heuristic unless a format-specific parser validates them. Extracted content is untrusted and FILEX never executes it.

## Features

- Validates a JSON signature database before using it.
- Identifies file formats at configured header offsets and reports extension mismatches.
- Scans large files incrementally with overlap to detect signatures crossing chunk boundaries.
- Calculates Shannon entropy using non-overlapping windows.
- Creates possible embedded-file ranges from signature locations. Candidate ranges are not guaranteed to be complete files.
- Safely extracts selected candidate ranges with per-file and aggregate output limits, generated filenames, path-traversal resistance, exclusive file creation, SHA-256 verification, and cleanup after failed writes.
- Produces terminal, JSON, and CSV reports.
- Supports optional YARA rule scanning through `yara-python`.
- Includes unit and integration tests.

## Requirements

- Python 3.10 or newer.
- No mandatory third-party runtime packages.
- `pytest` is used for development tests.
- `yara-python` is optional and only needed for the `--yara-rules` option.

## Installation on Kali Linux / Debian-based Linux

```bash
git clone <your-repository-url> FILEX
cd FILEX
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run from the source directory without installing the package:

```bash
python main.py --help
```

After editable installation, the `filex` command is available:

```bash
filex --help
```

### Optional YARA support

```bash
python -m pip install -e ".[yara]"
```

YARA is optional. Core identification, entropy, carving, extraction, and reporting work without it. YARA uses only the rules file explicitly supplied by the user.

## Quick start

Display all commands:

```bash
filex --help
```

Run the complete analysis pipeline:

```bash
filex scan samples/example.bin
```

Save machine-readable reports (the destination files must not already exist):

```bash
filex scan samples/example.bin \
  --json-out reports/example.json \
  --csv-out reports/example.csv
```

Identify a file using registered signatures at their configured offsets:

```bash
filex identify samples/example.png
```

List heuristic embedded-file candidates:

```bash
filex carve samples/disk-image.bin
```

Safely extract one candidate by its zero-based index:

```bash
filex extract samples/disk-image.bin --index 0 --output-dir extracted
```

Extract all detected candidates while enforcing both per-file and total output limits:

```bash
filex extract samples/disk-image.bin --all \
  --max-output-size 52428800 \
  --max-total-output-size 209715200
```

Run optional YARA scanning:

```bash
filex scan samples/example.bin --yara-rules rules/local-rules.yar
```

Tune chunk and entropy window sizes:

```bash
filex scan samples/example.bin \
  --chunk-size 8192 \
  --entropy-window-size 4096 \
  --entropy-threshold 7.2
```

## Extraction safeguards

`SafeExtractor` validates candidate offsets against the source file, rejects non-positive or malformed ranges, and enforces a per-file output limit (50 MiB by default) plus an aggregate budget (200 MiB per extractor instance by default). It constructs a filename from a sanitized signature identifier and a validated extension rather than trusting source metadata. It writes with exclusive creation and restrictive file permissions, so an existing file is not overwritten. Data is copied in chunks, hashed with SHA-256, then read back and hashed again. An incomplete output is deleted when an extraction operation fails.

Extraction is not a file-format validation step. FILEX currently determines candidate ends from the next detected signature, a configured size cap, or end-of-file. This can include unrelated bytes or truncate an embedded object. Review the candidate metadata and verify extracted files with independent tools. Do not execute extracted files.

## Signature database

The default `config/signatures.json` database contains PNG, PDF, and ZIP header signatures. Entries include an identifier, display name, category, MIME type, allowed extensions, hexadecimal bytes, header offsets, embedded-scan flag, and description. The loader validates entries and caps the database file size. Add signatures only from trusted format references and test new entries before using them.

## Architecture

```text
CLI (main.py)
   |
   +--> SignatureEngine --> config/signatures.json
   |
   +--> FileIdentifier       (registered header offsets)
   +--> SlidingWindowScanner (incremental embedded signature scan)
   +--> EntropyAnalyzer      (windowed Shannon entropy)
   +--> FileCarver           (heuristic candidate ranges)
   +--> SafeExtractor        (bounded, verified byte-range extraction)
   +--> YaraScanner          (optional external YARA rules)
   |
   +--> Terminal / JSON / CSV reports
```

See [`docs/architecture.md`](docs/architecture.md) and [`docs/module_documentation.md`](docs/module_documentation.md) for details.

## Tests

Install development dependencies and run:

```bash
python -m pytest -v
```

The suite covers signature database validation, fixed-offset identification, chunk-boundary matching, entropy calculations, candidate boundaries, extraction safeguards, report writers, CLI commands, and end-to-end processing.

## Resource behavior and limitations

- File bytes are processed in bounded chunks/windows; FILEX does not read an entire large target file into memory for signature scanning or extraction.
- Result metadata is retained for reports. Very frequent signatures or very small entropy windows can therefore increase memory use.
- The current signature database is intentionally small. A signature match alone does not validate a complete file.
- Entropy thresholds are configurable triage heuristics and depend on the data and window size.
- Optional YARA scanning delegates matching to `yara-python`; the timeout is configured in `config/settings.py`.
- FILEX is intended for local defensive analysis and does not upload analyzed content.

## Project status

The implementation roadmap and phase completion checklist are in [`PROJECT_PLAN.md`](PROJECT_PLAN.md). Version `1.0.0` is the initial complete CLI implementation; future format-aware parsers and additional signatures should be introduced with dedicated tests.

## License

No license has been declared yet. Add a license file before redistributing the project under an open-source license.
