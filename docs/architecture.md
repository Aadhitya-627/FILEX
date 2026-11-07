# FILEX Architecture

## Design goals

FILEX is a local, read-only analysis pipeline with a narrow set of responsibilities: recognize registered signatures, inspect byte distributions, describe possible embedded ranges, and optionally copy selected ranges into a controlled output directory. It separates format detection from candidate extraction and does not execute analyzed content.

## Pipeline

1. **Input validation** resolves an input path and rejects missing files, directories, and symbolic links at the CLI boundary.
2. **Signature database loading** reads a bounded JSON file and validates every signature entry before constructing the engine.
3. **Header identification** checks signatures at configured offsets and compares detected extensions with the filename suffix.
4. **Embedded scanning** reads chunks with overlap equal to the longest eligible signature length minus one. Match ownership is based on the newly read portion, preventing duplicate reports across windows.
5. **Entropy analysis** calculates Shannon entropy for non-overlapping windows. The final window may be smaller.
6. **Carving** uses embedded signature offsets as candidate starts. A candidate ends at the next distinct signature, the per-candidate size cap, or end-of-file.
7. **Optional YARA** compiles only a user-supplied rules file and scans the given file when requested.
8. **Reporting** serializes model results to terminal text, JSON, or CSV.
9. **Safe extraction** validates a candidate's byte range, enforces individual and aggregate budgets, creates a sanitized name exclusively, copies incrementally, and verifies the resulting bytes with SHA-256.

## Module map

| Module | Responsibility |
|---|---|
| `core/models.py` | Immutable signatures, match records, analysis results and carving candidates |
| `core/signature_engine.py` | Bounded JSON read, schema validation and signature lookup |
| `core/file_identifier.py` | Fixed-offset file format identification |
| `core/sliding_window.py` | Overlapped, chunk-based embedded signature scanner |
| `core/entropy.py` | Shannon entropy calculation and window aggregation |
| `core/file_carver.py` | Heuristic byte-range candidate generation |
| `core/extraction.py` | Size-limited, safe and integrity-checked extraction |
| `core/yara_scanner.py` | Optional YARA integration |
| `core/scanner.py` | Orchestrates the analysis pipeline and returns one report model |
| `main.py` | CLI parsing, command dispatch and exit codes |
| `utils/formatters.py` | Human-readable, JSON and CSV report output |
| `utils/validators.py` | CLI path and numeric input validation |
| `utils/logger.py` | Consistent stderr logging |

## Memory and performance

The sliding scanner retains a chunk and a bounded overlap, not the entire source file. Entropy analysis reads one configured window at a time. Extraction copies at most one configured chunk per loop and calculates hashes incrementally. The full scan report retains match and window metadata in memory, so metadata consumption is proportional to the number of results and entropy windows.

## Trust boundaries

- Signature database entries are untrusted configuration until validated.
- File content and candidate metadata are untrusted input.
- Candidate ranges are only heuristic boundaries; no claim of file validity is made.
- Extraction names are derived from a restricted identifier and validated extension, never from arbitrary source filenames.
- Exclusive file creation prevents replacing an existing extraction output.
- SHA-256 confirms that the bytes written match the bytes read from the selected source range; it does not prove authenticity or safety.
- YARA rules are supplied by the user and are optional. The YARA engine is not a sandbox.
- Extracted files are never opened as programs or executed by FILEX.

## Extension points

Future format-aware carvers should introduce format-specific end-marker or length parsing behind a dedicated interface and test malformed/truncated inputs. New signatures should be added to the JSON database and accompanied by known-positive, known-negative, offset, and boundary tests. A future streaming report mode could reduce metadata retention for very large scans.
