"""
The library's own proof.

Every entry declares what it must match and what it must not, and this runs
all of it. A library that is not tested is a library of plausible-looking
regexes, and a plausible-looking regex in a detection rule is a rule that
quietly matches nothing.
"""

import re

import pytest

from sieve.core.library import ENTRIES, BY_ID, FAMILIES, search


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.id)
def test_entry_compiles(entry):
    re.compile(entry.pattern)


@pytest.mark.parametrize(
    "entry,sample",
    [(e, s) for e in ENTRIES for s in e.matches],
    ids=lambda v: v.id if hasattr(v, "id") else str(v)[:40])
def test_entry_matches_its_examples(entry, sample):
    assert entry.search(sample), f"{entry.id} should match {sample!r}"


@pytest.mark.parametrize(
    "entry,sample",
    [(e, s) for e in ENTRIES for s in e.avoids],
    ids=lambda v: v.id if hasattr(v, "id") else str(v)[:40])
def test_entry_rejects_its_counterexamples(entry, sample):
    assert not entry.search(sample), f"{entry.id} should not match {sample!r}"


def test_every_entry_has_a_caveat():
    """The caveat is the part an analyst needs before trusting a hit."""
    for entry in ENTRIES:
        assert entry.caveat.strip(), f"{entry.id} has no caveat"
        assert len(entry.caveat) > 30, f"{entry.id}'s caveat is too thin"


def test_every_entry_is_proved_both_ways():
    for entry in ENTRIES:
        assert entry.matches, f"{entry.id} has no positive example"
        assert entry.avoids, f"{entry.id} has no counterexample"


def test_ids_and_families_are_sane():
    assert len(BY_ID) == len(ENTRIES), "duplicate entry id"
    for entry in ENTRIES:
        assert entry.family in FAMILIES, f"{entry.id} has an unknown family"


def test_search_finds_by_tag_and_title():
    assert any(e.id == "jwt" for e in search("jwt"))
    assert any(e.id == "ipv4_private" for e in search("rfc1918"))
    assert search("") == list(ENTRIES)


def test_no_entry_is_catastrophic():
    """A shipped pattern that can hang is a shipped vulnerability."""
    from sieve.core import redos
    for entry in ENTRIES:
        verdict = redos.analyse(entry.pattern, measure=True)
        assert verdict.grade != redos.CATASTROPHIC, (
            f"{entry.id} backtracks catastrophically: {verdict.growth}")


def test_no_entry_carries_a_global_inline_flag():
    """A leading (?i) is legal alone and illegal once concatenated into a
    recipe. Entries carry the intent in `ignore_case` instead."""
    import re as _re
    for entry in ENTRIES:
        # Non-capturing groups and lookbehinds are fine; a *flag* group is not.
        assert not _re.match(r"\(\?[aimsuxL]+\)", entry.pattern), (
            f"{entry.id} starts with a global inline flag group")
        assert "(?i)" not in entry.pattern, f"{entry.id} embeds (?i)"


def test_every_entry_composes_inside_a_recipe():
    """The failure that motivated the test above: a library pattern has to
    survive being joined to another one."""
    from sieve.core.rules import Recipe, Rule
    for entry in ENTRIES:
        recipe = Recipe(rules=[
            Rule(pattern=entry.pattern, source=entry.id,
                 ignore_case=entry.ignore_case or None),
            Rule(pattern=r"\s*trailing"),
        ])
        recipe.compile()          # raises if the composition is invalid
