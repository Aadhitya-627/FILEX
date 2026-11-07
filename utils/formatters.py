"""Human-readable and machine-readable FILEX report writers."""

import csv
import json
from pathlib import Path
from typing import Union


def render_text_report(report) -> str:
    data = report.to_dict() if hasattr(report, "to_dict") else report
    identification = data.get("identification", {})
    primary = identification.get("primary_match") or {}
    entropy = data.get("entropy", {})
    matches = data.get("embedded_matches", [])
    candidates = data.get("carving_candidates", [])
    lines = [
        "FILEX – File Analysis Report",
        "=" * 30,
        f"File: {data.get('file_path', 'unknown')}",
        f"Size: {data.get('file_size', 0)} bytes",
        "",
        "Identification",
        f"  Detected: {'yes' if identification.get('detected') else 'no'}",
        f"  Format: {primary.get('name', 'unknown')}",
        f"  Extension status: {identification.get('extension_status', 'unknown')}",
        "",
        "Embedded signatures",
        f"  Matches: {len(matches)}",
    ]
    for match in matches[:50]:
        lines.append(
            f"  - {match.get('name')} at offset {match.get('offset')} "
            f"({match.get('signature_id')})"
        )
    if len(matches) > 50:
        lines.append(f"  ... {len(matches) - 50} additional matches in JSON report")
    lines.extend([
        "",
        "Entropy analysis",
        f"  Windows: {entropy.get('window_count', 0)}",
        f"  Average: {entropy.get('average_window_entropy', 0)} bits/byte",
        f"  High-entropy windows: {entropy.get('high_entropy_count', 0)}",
        "  Note: high entropy is not a malware verdict.",
        "",
        "Carving candidates",
        f"  Candidates: {len(candidates)}",
    ])
    for item in candidates[:50]:
        lines.append(
            f"  - {item.get('signature_id')} [{item.get('start_offset')}, "
            f"{item.get('end_offset_exclusive')}) – {item.get('size')} bytes"
        )
    if len(candidates) > 50:
        lines.append(f"  ... {len(candidates) - 50} additional candidates in JSON report")
    if data.get("yara") is not None:
        lines.extend(["", f"YARA matches: {data['yara'].get('match_count', 0)}"])
    lines.extend([
        "",
        "Cautions",
        "  - Carving boundaries are heuristic; extracted data may be incomplete.",
        "  - Extracted content is untrusted. Never execute it.",
    ])
    return "\n".join(lines)



def write_json_report(report, output_path: Union[str, Path]) -> Path:
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = report.to_dict() if hasattr(report, "to_dict") else report
    try:
        with path.open("x", encoding="utf-8") as target:
            json.dump(data, target, indent=2, ensure_ascii=False)
            target.write("\n")
    except FileExistsError as error:
        raise FileExistsError(f"Report already exists (not overwritten): {path}") from error
    return path


def write_csv_report(report, output_path: Union[str, Path]) -> Path:
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = report.to_dict() if hasattr(report, "to_dict") else report
    fieldnames = [
        "record_type", "file_path", "file_size", "signature_id", "name",
        "offset", "start_offset", "end_offset_exclusive", "size",
        "entropy_average", "high_entropy_count", "extension_status",
        "boundary_reason", "sha256",
    ]
    rows = [{
        "record_type": "summary",
        "file_path": data.get("file_path"),
        "file_size": data.get("file_size"),
        "entropy_average": (data.get("entropy") or {}).get("average_window_entropy"),
        "high_entropy_count": (data.get("entropy") or {}).get("high_entropy_count"),
        "extension_status": (data.get("identification") or {}).get("extension_status"),
    }]
    for match in data.get("embedded_matches", []):
        rows.append({"record_type": "signature_match", "file_path": data.get("file_path"),
                     "signature_id": match.get("signature_id"), "name": match.get("name"),
                     "offset": match.get("offset")})
    for item in data.get("carving_candidates", []):
        rows.append({"record_type": "carving_candidate", "file_path": data.get("file_path"),
                     "signature_id": item.get("signature_id"), "name": item.get("name"),
                     "start_offset": item.get("start_offset"),
                     "end_offset_exclusive": item.get("end_offset_exclusive"),
                     "size": item.get("size"), "boundary_reason": item.get("boundary_reason")})
    try:
        with path.open("x", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    except FileExistsError as error:
        raise FileExistsError(f"Report already exists (not overwritten): {path}") from error
    return path
