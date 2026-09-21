"""Every target emits, and the ones without lookaround say so."""

import json

import pytest

from sieve.core import export, flavors
from sieve.core.rules import EXCLUDE, REQUIRE, Recipe, Rule

RECIPE = Recipe(
    name="SSH brute force",
    intent="Repeated auth failures, minus our own scanner.",
    rules=[
        Rule(pattern=r"Failed password for (?P<user>\w+)", label="a failure"),
        Rule(kind=REQUIRE, pattern="sshd", literal=True, label="the service"),
        Rule(kind=EXCLUDE, pattern="10.20.0.9", literal=True, label="scanner"),
    ])


@pytest.mark.parametrize("target", export.TARGETS, ids=lambda t: t.id)
def test_every_target_emits_something(target):
    emission = export.emit(RECIPE, target.id)
    assert emission.code.strip()
    assert emission.target.id == target.id


@pytest.mark.parametrize("target", export.TARGETS, ids=lambda t: t.id)
def test_no_target_silently_drops_an_exclude_rule(target):
    """The whole point. If the flavor cannot express the exclusion, the
    emission must carry it some other way — never just leave it out."""
    emission = export.emit(RECIPE, target.id)
    flat = emission.code.replace("\\", "")
    assert "20.0.9" in flat, "the Exclude rule vanished"
    assert "sshd" in flat, "the Require rule vanished"


def test_lookaround_free_flavors_get_a_pipeline():
    for target_id in ("grep_e", "ripgrep", "go", "rust", "elastic"):
        assert export.emit(RECIPE, target_id).pipeline


def test_pcre_flavors_get_one_pattern():
    assert not export.emit(RECIPE, "grep_p").pipeline


def test_a_pipeline_reports_its_guards_incompatibilities_too():
    """A Require rule with its own lookahead cannot run in grep -E either,
    and reporting only on the Find part would hide that."""
    recipe = Recipe(rules=[
        Rule(pattern="error"),
        Rule(kind=REQUIRE, pattern=r"(?!skip)\w+", label="guard")])
    emission = export.emit(recipe, "grep_e")
    assert not emission.report.runs


def test_the_sieve_file_round_trips():
    emission = export.emit(RECIPE, "json")
    again = Recipe.from_dict(json.loads(emission.code))
    assert again.pattern() == RECIPE.pattern()


def test_sigma_and_yara_carry_the_intent():
    assert "minus our own scanner" in export.emit(RECIPE, "sigma").code
    assert "minus our own scanner" in export.emit(RECIPE, "yara").code


def test_go_uses_plain_checks_rather_than_lookaround():
    code = export.emit(RECIPE, "go").code
    assert "regexp.MustCompile" in code
    assert "!exclude0.MatchString" in code
    assert "(?!" not in code


def test_posix_export_has_no_constructs_posix_cannot_run():
    code = export.emit(RECIPE, "grep_e").code
    assert "(?:" not in code
    assert r"\w" not in code and r"\d" not in code


def test_shell_quoting_survives_a_quote_in_the_pattern():
    recipe = Recipe(rules=[Rule(pattern="it's", literal=True)])
    code = export.emit(recipe, "grep_p").code
    assert "'\"'\"'" in code or '"' in code


def test_each_target_names_a_flavor_that_exists():
    for target in export.TARGETS:
        assert target.flavor in flavors.FLAVORS
