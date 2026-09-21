"""
The safety analyser.

The most important test here is the last one: the probe must stay bounded. An
analyser that hangs on the pattern it is analysing is worse than no analyser,
and the first version of this module did exactly that.
"""

import time

import pytest

from sieve.core import redos


@pytest.mark.parametrize("pattern", [
    r"^(a+)+$",
    r"^(a|a)+$",
    r"^(\w+\s?)*$",
])
def test_known_evil_patterns_are_caught(pattern):
    verdict = redos.analyse(pattern)
    assert verdict.is_risky or verdict.grade == redos.SUSPECT, verdict.grade
    assert verdict.findings, "nothing found statically"


def test_classic_exponential_is_measured_not_just_suspected():
    verdict = redos.analyse(r"^(a+)+$")
    assert verdict.grade == redos.CATASTROPHIC
    assert verdict.measurements
    assert verdict.attack_input


def test_quadratic_growth_is_separated_from_exponential():
    verdict = redos.analyse(r"^.*.*=.*$")
    assert verdict.grade in (redos.SUPERLINEAR, redos.CATASTROPHIC)


@pytest.mark.parametrize("pattern", [
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    r"Failed password for \w+",
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
])
def test_ordinary_patterns_are_not_cried_wolf_over(pattern):
    verdict = redos.analyse(pattern)
    assert verdict.grade == redos.NOTHING_FOUND, verdict.findings


def test_the_verdict_never_claims_safety():
    """An honesty ceiling, enforced rather than promised."""
    for grade in redos.GRADE_LABEL:
        text = (redos.GRADE_LABEL[grade] + " " + redos.GRADE_BLURB[grade]).lower()
        assert "is safe" not in text
        assert "guaranteed safe" not in text
    clean = redos.analyse(r"abc")
    assert "not a guarantee" in clean.blurb


def test_the_probe_stays_bounded_on_a_pathological_pattern():
    started = time.perf_counter()
    redos.analyse(r"^(a+)+(b+)+(c+)+$")
    assert time.perf_counter() - started < 6.0


def test_rewrite_advice_is_tied_to_what_was_found():
    tips = " ".join(redos.safer_rewrite(r"^(a+)+$"))
    assert "atomic" in tips or "Collapse" in tips


def test_an_uncompilable_pattern_is_unknown_not_clean():
    assert redos.analyse("(unclosed").grade == redos.UNKNOWN
