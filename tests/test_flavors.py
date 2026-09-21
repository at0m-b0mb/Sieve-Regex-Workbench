"""Flavor capability detection and translation."""

import pytest

from sieve.core import flavors


def test_re2_refuses_lookaround():
    report = flavors.check(r"^(?!.*noise).*error", "re2")
    assert not report.runs
    assert "no lookahead" in report.issues[0].message


def test_pcre_takes_everything():
    assert flavors.check(r"(?<=x)\d+(?!y)", "pcre").runs


def test_javascript_needs_named_groups_rewritten():
    report = flavors.check(r"(?P<ip>\d+)", "javascript")
    assert report.runs
    assert any(i.severity == flavors.REWRITE for i in report.issues)
    out, notes = flavors.translate(r"(?P<ip>\d+)", "javascript")
    assert out == r"(?<ip>\d+)"
    assert notes


def test_posix_loses_shorthand_and_non_capturing_groups():
    out, notes = flavors.translate(r"(?:\d{3})\w+", "posix_ere")
    assert r"\d" not in out and r"\w" not in out
    assert "(?:" not in out
    assert "[[:digit:]]" in out


def test_shorthand_inside_a_character_class_is_translated_too():
    out, _ = flavors.translate(r"[\d\-]+", "posix_ere")
    assert r"\d" not in out
    assert "[:digit:]" in out


def test_a_paren_inside_a_character_class_is_not_a_group():
    """A false alarm here teaches people to ignore the checker."""
    found = {c.id for c in flavors.constructs(r"[(?=x]")}
    assert "lookahead" not in found


def test_bre_inverts_the_escaping():
    out, notes = flavors.translate(r"(ab)+", "posix_bre")
    assert out == r"\(ab\)\+"
    assert notes


@pytest.mark.parametrize("fid", flavors.FLAVOR_ORDER)
def test_every_flavor_reports_something_for_a_hard_pattern(fid):
    report = flavors.check(r"(?<=a)(?P<x>\d+)(?!b)\1", fid)
    assert report.headline


def test_linear_time_engines_are_marked():
    assert flavors.FLAVORS["re2"].linear_time
    assert flavors.FLAVORS["rust"].linear_time
    assert not flavors.FLAVORS["pcre"].linear_time
