"""
The explainer.

The strong invariant: the tokens must reconstruct the pattern byte for byte.
A tokeniser that drops or duplicates a character would explain a pattern that
is not the one being run, and the editor highlights from the same tokens.
"""

import pytest

from sieve.core import explain
from sieve.core.library import ENTRIES


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.id)
def test_tokens_reconstruct_the_pattern(entry):
    tokens = explain.tokenise(entry.pattern)
    assert "".join(t.text for t in tokens) == entry.pattern


@pytest.mark.parametrize("pattern", [
    r"^(?!.*x)(?P<a>\d{2,4})[a-z]+|\bfoo\b",
    r"(?i)(?:ab)*?\1\k<name>\p{L}",
    r"[\]\\^-]+",
    r"a{2}b{3,}c{1,5}",
])
def test_tokens_reconstruct_awkward_patterns(pattern):
    tokens = explain.tokenise(pattern)
    assert "".join(t.text for t in tokens) == pattern


def test_spans_are_contiguous_and_in_order():
    tokens = explain.tokenise(r"^\d+[a-z](?:x|y)$")
    assert tokens[0].start == 0
    for previous, nxt in zip(tokens, tokens[1:]):
        assert previous.end == nxt.start


def test_group_depth_tracks_nesting():
    tokens = explain.tokenise(r"a(b(c)d)e")
    depths = {t.text: t.depth for t in tokens if t.kind == "literal"}
    assert depths["a"] == 0
    assert depths["b"] == 1
    assert depths["c"] == 2


def test_lookahead_is_described_as_not_consuming():
    meanings = [t.meaning for t in explain.tokenise(r"(?=x)")]
    assert any("not consumed" in m for m in meanings)


def test_lazy_and_greedy_read_differently():
    lazy = [t.meaning for t in explain.tokenise(r"a*?") if t.kind == "quantifier"]
    greedy = [t.meaning for t in explain.tokenise(r"a*") if t.kind == "quantifier"]
    assert "as few" in lazy[0]
    assert "as few" not in greedy[0]


def test_summary_notices_anchoring():
    assert explain.summary(r"^abc").startswith("Anchored")
    assert explain.summary(r"abc").startswith("Unanchored")
