"""The recipe model: compilation, grouping, and round-tripping."""

import re

import pytest

from sieve.core.rules import (EXCLUDE, FIND, JOIN_ANY, REQUIRE, Recipe,
                              RecipeError, Repeat, Rule, escape_literal,
                              group, _needs_group)


def test_literal_escaping_keeps_text_readable():
    assert escape_literal("10.0.0.1") == r"10\.0\.0\.1"
    assert escape_literal("a b") == "a b", "spaces need no escape"
    assert escape_literal("a\tb") == r"a\tb"


@pytest.mark.parametrize("fragment,needs", [
    ("a", False), (r"\d", False), ("[abc]", False), ("(?:ab)", False),
    ("ab", True), ("a|b", True), ("(a)(b)", True), (r"\d{3}", True),
])
def test_grouping_decision(fragment, needs):
    assert _needs_group(fragment) is needs


def test_quantifier_binds_to_the_whole_fragment():
    """The classic bug: ab+ repeats only the b."""
    rule = Rule(pattern="ab", repeat=Repeat(mode="some"))
    assert re.fullmatch(rule.fragment(), "abab")


def test_alternation_is_grouped_before_repeating():
    rule = Rule(pattern="cat|dog", repeat=Repeat(mode="some"))
    compiled = re.compile(rule.fragment())
    assert compiled.fullmatch("catdog")


def test_whole_word_uses_a_boundary_that_works_on_punctuation():
    """\\b before a hyphen never matches — a trap worth hours."""
    rule = Rule(pattern="-enc", literal=True, whole_word=True)
    assert re.search(rule.fragment(), "powershell -enc AAAA")


def test_exclude_rules_become_negative_lookaheads():
    recipe = Recipe(rules=[
        Rule(pattern="error"),
        Rule(kind=EXCLUDE, pattern="healthcheck", literal=True)])
    compiled = recipe.compile()
    assert compiled.search("error in module")
    assert not compiled.search("error from healthcheck probe")


def test_require_rules_gate_the_line():
    recipe = Recipe(rules=[
        Rule(pattern="error"),
        Rule(kind=REQUIRE, pattern="auth", literal=True)])
    compiled = recipe.compile()
    assert compiled.search("auth error")
    assert not compiled.search("disk error")


def test_capture_survives_a_quantifier():
    rule = Rule(pattern=r"\d", repeat=Repeat(mode="some"),
                capture=True, capture_name="number")
    match = re.search(rule.fragment(), "abc 4096 def")
    assert match.group("number") == "4096"


def test_capture_does_not_redefine_a_group_the_pattern_already_names():
    rule = Rule(pattern=r"(?P<user>\w+)", capture=True, capture_name="user")
    match = re.search(rule.fragment(), "root")
    assert match.group("user") == "root"


def test_join_any_is_an_alternation():
    recipe = Recipe(join=JOIN_ANY, rules=[
        Rule(pattern="alpha"), Rule(pattern="beta")])
    compiled = recipe.compile()
    assert compiled.search("beta") and compiled.search("alpha")


def test_disabled_rules_are_left_out():
    recipe = Recipe(rules=[
        Rule(pattern="keep"),
        Rule(kind=EXCLUDE, pattern="drop", enabled=False)])
    assert "drop" not in recipe.pattern()


def test_round_trip_through_json():
    recipe = Recipe(name="Test", intent="why", ignore_case=True, rules=[
        Rule(pattern=r"\d+", label="a number", capture=True,
             capture_name="n", repeat=Repeat(mode="range", minimum=2, maximum=5)),
        Rule(kind=EXCLUDE, pattern="noise", literal=True)])
    again = Recipe.from_json(recipe.to_json())
    assert again.pattern() == recipe.pattern()
    assert again.name == "Test" and again.ignore_case
    assert again.rules[0].repeat.maximum == 5


def test_a_newer_schema_is_refused_rather_than_misread():
    with pytest.raises(RecipeError):
        Recipe.from_dict({"schema": 99, "rules": []})


def test_empty_recipe_explains_itself():
    with pytest.raises(RecipeError):
        Recipe().compile()


def test_broken_pattern_gets_a_human_message():
    recipe = Recipe(rules=[Rule(pattern="(unclosed")])
    with pytest.raises(RecipeError) as caught:
        recipe.compile()
    assert "never closed" in str(caught.value)


def test_description_reads_as_english():
    recipe = Recipe(rules=[
        Rule(pattern="fail", label="a failure"),
        Rule(kind=EXCLUDE, pattern="test", label="our test traffic")])
    text = " ".join(recipe.describe())
    assert "Find a failure" in text
    assert "Never when the line contains our test traffic" in text
