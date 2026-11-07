import sys

import pytest

from core.yara_scanner import YaraScanError, YaraScanner, YaraUnavailableError


def test_yara_is_optional_when_dependency_is_missing(tmp_path, monkeypatch):
    target = tmp_path / "target.bin"
    target.write_bytes(b"sample")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule sample { condition: true }", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "yara", None)
    with pytest.raises(YaraUnavailableError, match="yara-python"):
        YaraScanner().scan(target, rules)


def test_yara_rejects_missing_rules(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"sample")
    with pytest.raises(YaraScanError, match="rules path"):
        YaraScanner().scan(target, tmp_path / "missing.yar")


def test_yara_returns_structured_rule_metadata(tmp_path, monkeypatch):
    from types import SimpleNamespace

    target = tmp_path / "target.bin"
    target.write_bytes(b"sample")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule sample { condition: true }", encoding="utf-8")

    class FakeRules:
        def match(self, filepath, timeout):
            assert filepath == str(target)
            assert timeout == 30
            return [SimpleNamespace(
                rule="sample_rule", namespace="default",
                tags=["demo"], meta={"severity": "low"},
            )]

    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(compile=lambda filepath: FakeRules()),
    )
    result = YaraScanner().scan(target, rules)
    assert result.match_count == 1
    assert result.to_dict()["matches"][0]["rule"] == "sample_rule"
    assert result.to_dict()["matches"][0]["meta"]["severity"] == "low"
