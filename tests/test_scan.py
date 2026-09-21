"""File sweeping, skipping and redaction."""

from pathlib import Path

import pytest

from sieve.core import scan
from sieve.core.rules import EXCLUDE, Recipe, Rule

RECIPE = Recipe(rules=[
    Rule(pattern=r"AKIA[A-Z0-9]{16}", label="an aws key id"),
])


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "app.conf").write_text(
        "key=AKIAIOSFODNN7EXAMPLE\nnothing here\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("plain text\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"AKIAIOSFODNN7EXAMPLE\x00binary")
    nested = tmp_path / "deep"
    nested.mkdir()
    (nested / "other.conf").write_text("AKIAIOSFODNN7EXAMPLX\n", encoding="utf-8")
    skipped = tmp_path / ".git"
    skipped.mkdir()
    (skipped / "config").write_text("AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    return tmp_path


def test_finds_hits_and_recurses(tree):
    result = scan.scan(RECIPE, tree)
    paths = {Path(h.path).name for h in result.hits}
    assert paths == {"app.conf", "other.conf"}


def test_binary_files_are_skipped_by_content_not_extension(tree):
    result = scan.scan(RECIPE, tree)
    assert not any(h.path.endswith("blob.bin") for h in result.hits)
    assert result.files_skipped >= 1


def test_version_control_directories_are_left_alone(tree):
    result = scan.scan(RECIPE, tree)
    assert not any(".git" in h.path for h in result.hits)


def test_include_globs_narrow_the_sweep(tree):
    result = scan.scan(RECIPE, tree, include="*.conf")
    assert {Path(h.path).name for h in result.hits} == {"app.conf", "other.conf"}
    result = scan.scan(RECIPE, tree, include="*.txt")
    assert not result.hits


def test_redaction_keeps_the_shape_and_loses_the_secret(tree):
    result = scan.scan(RECIPE, tree)
    hit = next(h for h in result.hits if h.path.endswith("app.conf"))
    redacted = hit.redacted()
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "█" * 20 in redacted
    assert redacted.startswith("key=")


def test_reports_do_not_leak_when_redacted(tree):
    result = scan.scan(RECIPE, tree)
    for writer in (scan.to_text, scan.to_csv, scan.to_json):
        assert "AKIAIOSFODNN7EXAMPLE" not in writer(result, redact=True)
        assert "AKIAIOSFODNN7EXAMPLE" in writer(result, redact=False)


def test_context_lines_are_carried(tree):
    result = scan.scan(RECIPE, tree, context=1)
    hit = next(h for h in result.hits if h.path.endswith("app.conf"))
    assert hit.after == ["nothing here"]


def test_stopping_is_honoured(tree):
    result = scan.scan(RECIPE, tree, should_stop=lambda: True)
    assert result.stopped_early


def test_a_missing_path_is_reported_not_raised(tmp_path):
    result = scan.scan(RECIPE, tmp_path / "nope")
    assert result.errors and not result.hits


def test_exclude_rules_apply_during_a_sweep(tree):
    recipe = Recipe(rules=[
        Rule(pattern=r"AKIA[A-Z0-9]{16}"),
        Rule(kind=EXCLUDE, pattern="EXAMPLX", literal=True)])
    result = scan.scan(recipe, tree)
    assert {Path(h.path).name for h in result.hits} == {"app.conf"}
