import csv
import json

import pytest

from main import main
from core.scanner import FileXScanner
from utils.formatters import render_text_report, write_csv_report, write_json_report

PNG = bytes.fromhex("89504E470D0A1A0A")


def test_json_and_csv_report_writers(tmp_path):
    source = tmp_path / "sample.png"
    source.write_bytes(PNG + b"A" * 100)
    report = FileXScanner(entropy_window_size=32).analyze_file(source)
    json_path = write_json_report(report, tmp_path / "report.json")
    csv_path = write_csv_report(report, tmp_path / "report.csv")
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["application"] == "FILEX"
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["record_type"] == "summary"
    assert any(row["record_type"] == "signature_match" for row in rows)
    assert "Cautions" in render_text_report(report)


def test_report_writers_do_not_overwrite(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"data")
    report = FileXScanner().analyze_file(source)
    destination = tmp_path / "report.json"
    destination.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError, match="not overwritten"):
        write_json_report(report, destination)
    assert destination.read_text(encoding="utf-8") == "keep"


def test_cli_scan_json_and_csv(tmp_path, capsys):
    source = tmp_path / "sample.png"
    source.write_bytes(PNG + b"B" * 64)
    json_out = tmp_path / "scan.json"
    csv_out = tmp_path / "scan.csv"
    code = main(["scan", str(source), "--json-out", str(json_out), "--csv-out", str(csv_out)])
    assert code == 0
    assert "FILEX" in capsys.readouterr().out
    assert json_out.is_file() and csv_out.is_file()


def test_cli_identify(tmp_path, capsys):
    source = tmp_path / "sample.pdf"
    source.write_bytes(b"%PDF-1.7")
    assert main(["identify", str(source)]) == 0
    assert '"detected": true' in capsys.readouterr().out


def test_cli_extract_requires_selection():
    with pytest.raises(SystemExit):
        main(["extract", "some-file.bin"])


def test_cli_extract_candidate(tmp_path, capsys):
    source = tmp_path / "sample.png"
    source.write_bytes(PNG + b"PAYLOAD")
    out = tmp_path / "out"
    assert main(["extract", str(source), "--index", "0", "--output-dir", str(out)]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["extracted_count"] == 1
    assert response["results"][0]["integrity_verified"] is True
