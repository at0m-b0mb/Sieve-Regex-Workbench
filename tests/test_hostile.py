"""
Hostile input.

A .sieve file is a document people share, so every value in one is untrusted.
Two of them reach the regex engine directly — a capture name, interpolated
into `(?P<name>…)`, and a repetition count, interpolated into `{n}` — and both
were taken on trust.

The corpus is untrusted too: it is a log, and logs contain whatever was written
to them. None of it may hang, crash, or quietly change what a pattern means.
"""

import re
import signal
import time

import pytest

from sieve.core import explain, flavors, matcher, scan
from sieve.core.rules import (MAX_REPEAT, Recipe, RecipeError, Repeat, Rule,
                              safe_count)


def within(seconds: float):
    """Fail rather than hang, on platforms that can."""
    class Guard:
        def __enter__(self):
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM,
                              lambda *_: (_ for _ in ()).throw(
                                  AssertionError(f"took over {seconds}s")))
                signal.setitimer(signal.ITIMER_REAL, seconds)
            self.start = time.perf_counter()
            return self

        def __exit__(self, *exc):
            if hasattr(signal, "SIGALRM"):
                signal.setitimer(signal.ITIMER_REAL, 0)
            return False
    return Guard()


# --- the capture name -------------------------------------------------------

@pytest.mark.parametrize("name", [
    "a>(?:",                    # closes the group, opens another
    "n>(a+)+$)(?P<z",           # injects a catastrophic shape
    "x>.*",                     # widens the match
    "1leading_digit",
    "has space",
    "",
    "has-hyphen",
    "unicodé",       # legal in Python, rejected by Go, Java and JavaScript
])
def test_a_crafted_capture_name_cannot_reach_the_pattern(name):
    fragment = Rule(pattern="x", capture=True, capture_name=name).fragment()
    assert "(?P<" not in fragment, f"{name!r} was interpolated into the pattern"
    re.compile(fragment)        # and whatever it produced is still valid


@pytest.mark.parametrize("name", ["user", "src_ip", "_x", "ok_2", "A1"])
def test_ordinary_capture_names_still_work(name):
    fragment = Rule(pattern="x", capture=True, capture_name=name).fragment()
    assert re.compile(fragment).match("x").group(name) == "x"


def test_the_injected_shape_really_was_dangerous():
    """Shows the fix is worth having: the payload compiles and backtracks."""
    from sieve.core import redos
    payload = "(?P<n>" + "(a+)+$" + ")"
    assert redos.static_findings(payload), "the payload was harmless anyway"


# --- repetition counts ------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (5, 5), ("7", 7), (-3, 0), (10 ** 9, MAX_REPEAT), (None, 0),
    ("NaN", 0), (2.9, 2), ([], 0), ({}, 0),
])
def test_repetition_counts_are_coerced_and_bounded(value, expected):
    assert safe_count(value) == expected


def test_an_enormous_count_cannot_reach_the_engine():
    suffix = Repeat(mode="exact", minimum=10 ** 9).suffix()
    assert suffix == "{%d}" % MAX_REPEAT
    with within(3):
        re.compile("x" + suffix)


def test_a_backwards_range_is_not_a_backwards_range():
    assert Repeat(mode="range", minimum=9, maximum=2).suffix() == "{9,9}"


# --- the document boundary --------------------------------------------------

@pytest.mark.parametrize("document,fragment_of_message", [
    ({"rules": [{"kind": "wat", "pattern": "x"}]}, "unknown kind"),
    ({"join": "wat", "rules": [{"pattern": "x"}]}, "unknown way"),
    ({"rules": [{"pattern": "x", "repeat": {"mode": "wat"}}]}, "unknown way"),
    ({"rules": "not-a-list"}, "should be a list"),
    ({"rules": [1, 2, 3]}, "not an object"),
    ({"schema": 99, "rules": []}, "newer Sieve"),
])
def test_a_crafted_document_is_refused_with_a_reason(document, fragment_of_message):
    with pytest.raises(RecipeError) as caught:
        Recipe.from_dict(document)
    assert fragment_of_message in str(caught.value)


def test_a_rule_with_an_unknown_kind_is_never_silently_dropped():
    """It used to load, then vanish inside of_kind() without a word — silent
    rule loss, in a tool whose whole argument is that it does not do that."""
    with pytest.raises(RecipeError):
        Recipe.from_dict({"rules": [{"kind": "excl", "pattern": "secret"}]})


@pytest.mark.parametrize("field", ["ignore_case", "multiline", "anchor_start"])
def test_flags_are_coerced_to_booleans(field):
    recipe = Recipe.from_dict({"rules": [{"pattern": "x"}], field: "yes"})
    assert getattr(recipe, field) is True


def test_a_document_round_trips_after_being_cleaned():
    recipe = Recipe.from_dict({
        "rules": [{"pattern": "x", "capture": 1, "capture_name": "bad name",
                   "repeat": {"mode": "exact", "minimum": "4"}}],
        "ignore_case": 1})
    again = Recipe.from_json(recipe.to_json())
    assert again.pattern() == recipe.pattern()
    re.compile(again.pattern())


# --- the corpus -------------------------------------------------------------

@pytest.mark.parametrize("corpus,label", [
    ("a" * 2_000_000, "one very long line"),
    ("x\n" * 200_000, "very many lines"),
    ("\udcff\udcfe bad", "lone surrogates"),
    ("a\x00b\nc", "null bytes"),
    ("‮​﻿", "bidi and zero-width characters"),
    ("", "nothing at all"),
    ("\n\n\n", "only newlines"),
])
def test_a_hostile_corpus_is_handled(corpus, label):
    recipe = Recipe(rules=[Rule(pattern=r"AKIA[A-Z0-9]{16}", label="a key")])
    with within(10):
        result = matcher.run(recipe, corpus)
    assert result.error == "" or "rule" in result.error


def test_a_zero_width_match_does_not_loop_forever():
    recipe = Recipe(rules=[Rule(pattern=r"(?:)", label="nothing at all")])
    with within(5):
        matcher.run(recipe, "abc\ndef")


def test_a_pattern_longer_than_the_corpus_is_fine():
    recipe = Recipe(rules=[Rule(pattern="a" * 50_000, label="enormous")])
    with within(10):
        matcher.run(recipe, "aaa")


# --- the explainer and the flavor checker -----------------------------------

@pytest.mark.parametrize("pattern,label", [
    ("(a|b)" * 20_000, "a very long pattern"),
    ("(" * 2_000 + ")" * 2_000, "deeply nested groups"),
    ("[" * 2_000, "unterminated classes"),
    ("\\" * 2_000, "trailing escapes"),
])
def test_the_explainer_survives_a_hostile_pattern(pattern, label):
    with within(12):
        tokens = explain.tokenise(pattern)
    assert "".join(t.text for t in tokens) == pattern, "lost or duplicated text"


@pytest.mark.parametrize("pattern", [
    "(" * 2_000 + ")" * 2_000, "[" * 500, "\\" * 500, "(?P<" * 200,
])
def test_the_flavor_checker_survives_a_hostile_pattern(pattern):
    with within(12):
        for flavor in flavors.FLAVOR_ORDER:
            flavors.check(pattern, flavor)


# --- the scanner ------------------------------------------------------------

def test_a_symlink_loop_does_not_trap_the_scanner(tmp_path):
    import os
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "a.log").write_text("AKIAIOSFODNN7REALKEYS\n",
                                             encoding="utf-8")
    try:
        os.symlink(tmp_path / "real", tmp_path / "real" / "loop")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable here")
    recipe = Recipe(rules=[Rule(pattern=r"AKIA[A-Z0-9]{16}", label="a key")])
    with within(20):
        result = scan.scan(recipe, tmp_path)
    assert len(result.hits) >= 1


def test_an_unreadable_file_is_reported_not_raised(tmp_path):
    import os
    target = tmp_path / "locked.log"
    target.write_text("AKIAIOSFODNN7REALKEYS\n", encoding="utf-8")
    try:
        os.chmod(target, 0o000)
    except OSError:
        pytest.skip("cannot change permissions here")
    recipe = Recipe(rules=[Rule(pattern=r"AKIA[A-Z0-9]{16}", label="a key")])
    try:
        result = scan.scan(recipe, tmp_path)
    finally:
        os.chmod(target, 0o644)
    if os.geteuid() == 0:
        pytest.skip("running as root, which can read it anyway")
    assert result.errors and not result.hits


def test_a_file_of_one_enormous_line(tmp_path):
    (tmp_path / "big.log").write_text("x" * 5_000_000, encoding="utf-8")
    recipe = Recipe(rules=[Rule(pattern="zzz", label="absent")])
    with within(20):
        result = scan.scan(recipe, tmp_path)
    assert not result.hits
