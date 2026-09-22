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
    # It must blow up while the input is still small — that, rather than a
    # fitted slope, is what separates exponential from merely slow.
    assert verdict.measurements[-1].length <= 256


def test_quadratic_growth_is_separated_from_exponential():
    """Asserted as an invariant, not as a number.

    The exact grade depends on how fast the machine is, and a shared CI runner
    under load is not fast. What must hold everywhere is that a known-bad
    shape is never waved through as clean.
    """
    verdict = redos.analyse(r"^.*.*=.*$")
    assert verdict.grade != redos.NOTHING_FOUND
    assert any(f.kind == "adjacent unbounded repeats" for f in verdict.findings)


@pytest.mark.parametrize("exponent", [1.0, 2.0, 3.0])
def test_the_slope_fit_recovers_a_known_exponent(exponent):
    """The curve fitting itself, with no clock involved."""
    runs = [redos.Measurement(n, (n / 100.0) ** exponent)
            for n in (100, 200, 400, 800, 1600)]
    assert abs(redos._slope(runs) - exponent) < 0.05


def test_timing_noise_cannot_manufacture_a_trend():
    """The bug this guards: jitter at the microsecond scale fitted a
    'quadratic' curve through a plainly linear pattern on a loaded CI runner,
    and the tool told the user their innocent pattern was dangerous."""
    noisy = [redos.Measurement(n, s) for n, s in
             [(100, 1e-6), (200, 9e-7), (400, 3e-6), (800, 1.1e-6)]]
    assert redos._slope(noisy) == 0.0, "sub-noise-floor points must not fit"


def test_too_few_points_is_no_evidence_rather_than_a_guess():
    assert redos._slope([redos.Measurement(100, 0.001)]) == 0.0
    assert redos._slope([redos.Measurement(100, 0.001),
                         redos.Measurement(200, 0.002)]) == 0.0


@pytest.mark.parametrize("pattern", [
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    r"Failed password for \w+",
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
])
def test_ordinary_patterns_are_not_cried_wolf_over(pattern):
    verdict = redos.analyse(pattern)
    assert verdict.grade == redos.NOTHING_FOUND, verdict.findings


def test_a_verdict_is_stable_across_repeated_runs():
    """A measurement that changes its mind between runs is not a measurement."""
    for pattern in (r"Failed password for \w+", r"^(a+)+$"):
        grades = {redos.analyse(pattern).grade for _ in range(5)}
        assert len(grades) == 1, f"{pattern} graded {grades} across five runs"


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
