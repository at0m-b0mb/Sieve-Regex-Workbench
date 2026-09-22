"""
Comparing a pattern against a baseline.

The question after every edit is "what did that let in?". It is a set
difference, which is why it is worth having: trivial to compute, and the thing
people are worst at doing by eye across two screens of highlighted text.
"""

import pytest

from sieve.core import matcher
from sieve.core.compare import Baseline, compare
from sieve.core.rules import EXCLUDE, Recipe, Rule
from sieve.core.samples import SSH

TIGHT = Recipe(rules=[Rule(pattern=r"Failed password for root", label="root")])
LOOSE = Recipe(rules=[Rule(pattern=r"Failed password for \w+", label="any user")])


def baseline_of(recipe, text=SSH.text):
    return Baseline.of(matcher.run(recipe, text))


def test_loosening_a_rule_is_reported_as_looser():
    difference = compare(baseline_of(TIGHT), matcher.run(LOOSE, SSH.text))
    assert difference.gained and not difference.lost
    assert "looser" in difference.direction()
    assert "newly kept" in difference.headline()


def test_tightening_a_rule_is_reported_as_stricter():
    difference = compare(baseline_of(LOOSE), matcher.run(TIGHT, SSH.text))
    assert difference.lost and not difference.gained
    assert "stricter" in difference.direction()


def test_an_edit_that_changes_nothing_says_so():
    difference = compare(baseline_of(TIGHT), matcher.run(TIGHT, SSH.text))
    assert not difference.changed
    assert "changed nothing" in difference.direction()
    assert "No change" in difference.headline()


def test_a_sideways_edit_is_not_called_looser_or_stricter():
    """Gaining some lines and losing others is not a direction, and saying it
    is would be the kind of confident wrong answer this tool avoids."""
    other = Recipe(rules=[Rule(pattern=r"Accepted \w+ for \w+", label="success")])
    difference = compare(baseline_of(TIGHT), matcher.run(other, SSH.text))
    assert difference.gained and difference.lost
    assert "sideways" in difference.direction()


def test_returning_to_the_baseline_reads_as_unchanged():
    """Loosen, then exclude what you loosened into: back where you started."""
    restored = Recipe(rules=[
        Rule(pattern=r"Failed password for \w+", label="any user"),
        Rule(kind=EXCLUDE, pattern="invalid user", literal=True, label="skip")])
    difference = compare(baseline_of(TIGHT), matcher.run(restored, SSH.text))
    assert not difference.changed


def test_the_comparison_keys_on_text_not_line_number():
    """So it survives the corpus being scrolled, re-pasted or reordered."""
    forward = "alpha one\nbeta two\ngamma three"
    backward = "gamma three\nbeta two\nalpha one"
    recipe = Recipe(rules=[Rule(pattern="beta", label="b")])
    base = Baseline.of(matcher.run(recipe, forward))
    assert not compare(base, matcher.run(recipe, backward)).changed


def test_the_listing_is_bounded():
    text = "\n".join(f"ERROR {i}" for i in range(500))
    empty = Baseline.of(matcher.run(Recipe(rules=[Rule(pattern="nope")]), text))
    difference = compare(empty, matcher.run(
        Recipe(rules=[Rule(pattern="ERROR")]), text), limit=10)
    assert len(difference.gained) == 10, "the listing should be bounded"
    assert difference.gained_total == 500, "but the count should not be"
    assert "500 newly kept" in difference.headline()
    assert "10 listed" in difference.headline()
    assert difference.listing_is_partial


def test_counts_are_carried_even_when_the_listing_is_cut():
    text = "\n".join(f"ERROR {i}" for i in range(50))
    base = Baseline.of(matcher.run(Recipe(rules=[Rule(pattern="nope")]), text))
    difference = compare(base, matcher.run(
        Recipe(rules=[Rule(pattern="ERROR")]), text), limit=5)
    assert difference.baseline_kept == 0
    assert difference.now_kept == 50
