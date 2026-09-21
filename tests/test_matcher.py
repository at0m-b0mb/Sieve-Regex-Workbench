"""Per-line verdicts, and the reason each one was reached."""

from sieve.core import matcher
from sieve.core.proof import Case, SHOULD_MATCH, SHOULD_NOT, Suite
from sieve.core.rules import EXCLUDE, REQUIRE, Recipe, Rule

TEXT = "\n".join([
    "auth failure for root from 8.8.8.8",
    "auth ok for alice",
    "auth failure for healthcheck from 10.0.0.9",
    "auth failure for bob",
])

RECIPE = Recipe(rules=[
    Rule(pattern=r"auth failure for (?P<user>\w+)", label="a failure"),
    Rule(kind=REQUIRE, pattern="from", literal=True, label="a source"),
    Rule(kind=EXCLUDE, pattern="healthcheck", literal=True, label="monitoring"),
])


def test_each_line_gets_the_right_verdict():
    result = matcher.run(RECIPE, TEXT)
    verdicts = [l.verdict for l in result.lines]
    assert verdicts == [matcher.KEPT, matcher.NO_MATCH,
                        matcher.EXCLUDED, matcher.MISSING_REQUIRE]


def test_the_blaming_rule_is_named():
    result = matcher.run(RECIPE, TEXT)
    assert result.lines[2].blamed == "monitoring"
    assert result.lines[3].blamed == "a source"


def test_gates_are_judged_in_the_order_the_flow_chart_shows():
    """Find, then Require, then Exclude. A line that fails several should be
    blamed on the first gate it reached, or the explanation teaches the wrong
    mental model of the pipeline."""
    recipe = Recipe(rules=[
        Rule(pattern="x"),
        Rule(kind=REQUIRE, pattern="never-present", literal=True),
        Rule(kind=EXCLUDE, pattern="drop", literal=True)])
    assert matcher.run(recipe, "x drop").lines[0].verdict == matcher.MISSING_REQUIRE
    assert matcher.run(recipe, "nothing").lines[0].verdict == matcher.NO_MATCH

    kept_then_excluded = Recipe(rules=[
        Rule(pattern="x"),
        Rule(kind=EXCLUDE, pattern="drop", literal=True)])
    assert matcher.run(kept_then_excluded, "x drop").lines[0].verdict == matcher.EXCLUDED


def test_named_fields_are_captured():
    result = matcher.run(RECIPE, TEXT)
    assert result.kept[0].groups == {"user": "root"}


def test_spans_mark_the_matched_text():
    result = matcher.run(RECIPE, TEXT)
    start, end = result.kept[0].spans[0]
    assert TEXT.split("\n")[0][start:end] == "auth failure for root"


def test_a_broken_rule_reports_rather_than_raises():
    recipe = Recipe(rules=[Rule(pattern="(")])
    assert matcher.run(recipe, "anything").error


def test_an_empty_recipe_asks_for_a_rule():
    assert "Add a rule" in matcher.run(Recipe(), "text").error


def test_long_input_is_truncated_not_hung():
    result = matcher.run(RECIPE, "line\n" * 9000, max_lines=100)
    assert result.truncated and len(result.lines) == 100


def test_bisect_names_the_rule_that_breaks_the_chain():
    recipe = Recipe(rules=[
        Rule(pattern="auth", label="the word auth"),
        Rule(pattern=" failure", label="the word failure"),
        Rule(pattern=" NOPE", label="a thing that is not there")])
    hint = matcher.first_difference(recipe, TEXT)
    assert "rule 3" in hint and "not there" in hint


def test_proof_cases_pass_and_fail_as_expected():
    suite = Suite([
        Case("auth failure for root from 8.8.8.8", SHOULD_MATCH),
        Case("auth ok for alice", SHOULD_NOT),
        Case("auth failure for healthcheck from 10.0.0.9", SHOULD_NOT),
    ])
    outcome = suite.run(RECIPE)
    assert outcome.green and outcome.passed == 3


def test_a_failing_case_explains_which_rule_rejected_it():
    suite = Suite([Case("auth failure for healthcheck from 10.0.0.9",
                        SHOULD_MATCH)])
    outcome = suite.run(RECIPE)
    assert not outcome.green
    assert "Exclude" in outcome.results[0].explanation
