# FILEX Module Documentation

## Public command-line commands

### `filex scan FILE`

Runs header identification, embedded signature scanning, entropy analysis, heuristic carving, and optional YARA. It displays a concise terminal report. `--json-out` and `--csv-out` write complete machine-readable reports. Output report files are created exclusively and are not overwritten.

Options: `--chunk-size`, `--entropy-window-size`, `--entropy-threshold`, `--max-candidate-size`, `--yara-rules`, `--json-out`, and `--csv-out`.

### `filex identify FILE`

Checks configured signature bytes at the offsets declared in `config/signatures.json`. The result includes detected formats and extension status (`match`, `mismatch`, or `unknown`). This command is not a recursive or full-file signature scan.

### `filex carve FILE`

Uses the sliding-window scanner to return candidate regions. JSON output includes start offsets, exclusive end offsets, byte sizes and boundary reasons. Candidate indices in this output are zero-based and can be supplied to `extract`.

### `filex extract FILE --index N`

Extracts one candidate. `--all` selects all candidates. Both are mutually exclusive and one is required. `--output-dir`, `--max-output-size`, `--max-total-output-size`, and `--chunk-size` control the extraction destination and resource limits.

## Python APIs

### `SignatureEngine(database_path=None)`

Loads and validates the signature database. `signatures` returns validated `FileSignature` objects; `get_signature(identifier)` returns one matching signature or `None`.

### `FileIdentifier(engine=None).identify(path)`

Returns `FileIdentificationResult`. It tests the configured offsets only.

### `SlidingWindowScanner(engine=None, chunk_size=CHUNK_SIZE)`

`iter_matches(path)` yields `SignatureMatch` items. `scan_file(path)` returns a sorted tuple. Memory for file bytes is bounded by chunk size plus signature overlap; the returned match tuple grows with the number of findings.

### `EntropyAnalyzer(window_size=..., threshold=...).analyze_file(path)`

Returns `EntropyAnalysisResult`. `iter_windows(path)` yields results as they are calculated. Entropy values range from 0 to 8 bits per byte. High-entropy flags are threshold comparisons only.

### `FileCarver(engine=None, chunk_size=..., max_candidate_size=...).carve(path)`

Returns `CarvedFileCandidate` objects. End offsets are exclusive. `boundary_reason` is one of `next_detected_signature`, `max_size_limit`, or `end_of_file`.

### `SafeExtractor(output_dir=..., max_output_size=..., max_total_output_size=..., chunk_size=...)`

`extract(candidate)` returns `ExtractionResult` after verifying output length and SHA-256. `extract_many(candidates)` enforces the cumulative budget for that extractor instance. Invalid ranges, oversized candidates, source symlinks, and output-budget violations raise `ExtractionError`.

### `FileXScanner(...).analyze_file(path, yara_rules=None)`

Returns `FileAnalysisReport`, an aggregate of identification, embedded signature results, entropy windows, carving candidates, and optional YARA matches.

### `YaraScanner().scan(path, rules_path)`

Requires the optional `yara-python` package. Missing package, invalid rules, and scan errors are exposed as `YaraUnavailableError` or `YaraScanError`.

## Report data

Every model exposes `to_dict()` for JSON-friendly serialization. Byte offsets are absolute. Candidate and report end offsets are exclusive, matching Python slice conventions. SHA-256 is a checksum of the extracted bytes, not a trust or authenticity signal.

## Default limits

| Setting | Default |
|---|---:|
| Signature database file size | 2 MiB |
| Scanner chunk | 4 KiB |
| Entropy window | 4 KiB |
| High entropy threshold | 7.2 bits/byte |
| Single extracted candidate | 50 MiB |
| Total extraction per extractor | 200 MiB |
| YARA match timeout | 30 seconds |

All limits are defined in `config/settings.py` or overridden by the relevant CLI arguments.
