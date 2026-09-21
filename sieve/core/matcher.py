"""
Running a recipe over text.

The Proof page needs more than "did it match". It needs, per line: was the
line kept or thrown away, and by which rule? A line rejected by an Exclude
rule and a line that simply never matched look identical in every other tool,
and telling them apart is most of the debugging.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .rules import Recipe, Rule, RecipeError

KEPT = "kept"
NO_MATCH = "no_match"
EXCLUDED = "excluded"
MISSING_REQUIRE = "missing_require"

VERDICT_LABEL = {
    KEPT: "Kept",
    NO_MATCH: "No match",
    EXCLUDED: "Excluded",
    MISSING_REQUIRE: "Missing a Require",
}


@dataclass
class LineResult:
    number: int
    text: str
    verdict: str
    spans: list[tuple[int, int]] = field(default_factory=list)
    groups: dict[str, str] = field(default_factory=dict)
    blamed: str = ""          # the rule label responsible for a rejection

    @property
    def kept(self) -> bool:
        return self.verdict == KEPT


@dataclass
class RunResult:
    lines: list[LineResult] = field(default_factory=list)
    error: str = ""
    seconds: float = 0.0
    truncated: bool = False

    @property
    def kept(self) -> list[LineResult]:
        return [l for l in self.lines if l.kept]

    @property
    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in VERDICT_LABEL}
        for l in self.lines:
            out[l.verdict] += 1
        return out

    @property
    def match_total(self) -> int:
        return sum(len(l.spans) for l in self.lines)

    def summary(self) -> str:
        if self.error:
            return self.error
        c = self.counts
        parts = [f"{c[KEPT]} kept"]
        if c[EXCLUDED]:
            parts.append(f"{c[EXCLUDED]} excluded")
        if c[MISSING_REQUIRE]:
            parts.append(f"{c[MISSING_REQUIRE]} missing a Require")
        if c[NO_MATCH]:
            parts.append(f"{c[NO_MATCH]} without a match")
        return ", ".join(parts) + f" · {self.match_total} matches"


def _compiled_guards(recipe: Recipe) -> tuple[list[tuple[Rule, re.Pattern]],
                                              list[tuple[Rule, re.Pattern]]]:
    flags = recipe.flags()
    reqs = [(r, re.compile(r.fragment(), flags)) for r in recipe.requires]
    excs = [(r, re.compile(r.fragment(), flags)) for r in recipe.excludes]
    return reqs, excs


def run(recipe: Recipe, text: str, *, max_lines: int = 5000,
        max_spans_per_line: int = 200) -> RunResult:
    """Evaluate every line, keeping the reason for each verdict.

    The rules are applied separately rather than as one compiled regex — the
    combined pattern is what gets exported, but it cannot tell you *why* a
    line lost, and the why is the product.
    """
    started = time.perf_counter()
    result = RunResult()

    if recipe.is_empty():
        result.error = "Add a rule to get started."
        return result

    try:
        reqs, excs = _compiled_guards(recipe)
        core = recipe.compile_core() if recipe.finds else None
    except RecipeError as exc:
        result.error = str(exc)
        return result
    except re.error as exc:
        result.error = f"A rule will not compile: {exc}"
        return result

    lines = text.split("\n")
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        result.truncated = True

    for n, line in enumerate(lines, start=1):
        verdict = KEPT
        blamed = ""
        spans: list[tuple[int, int]] = []
        groups: dict[str, str] = {}

        # Find, then Require, then Exclude — the order on the flow chart, so
        # a line that never matched is reported as never matching rather than
        # as failing a guard it was never going to reach.
        if core is not None:
            found = False
            for m in core.finditer(line):
                found = True
                if m.end() == m.start():
                    # A zero-width match would loop forever in a naive scan;
                    # finditer handles it, but drawing a highlight of width
                    # zero is just a confusing flicker, so we skip it.
                    continue
                spans.append(m.span())
                if not groups:
                    groups = {k: v for k, v in (m.groupdict() or {}).items()
                              if v is not None}
                    if not groups and m.groups():
                        groups = {str(i + 1): g for i, g in enumerate(m.groups())
                                  if g is not None}
                if len(spans) >= max_spans_per_line:
                    break
            if not found:
                verdict, blamed = NO_MATCH, ""

        if verdict == KEPT:
            for rule, rx in reqs:
                if not rx.search(line):
                    verdict, blamed = MISSING_REQUIRE, rule.label or rule.pattern
                    break

        if verdict == KEPT:
            for rule, rx in excs:
                if rx.search(line):
                    verdict, blamed = EXCLUDED, rule.label or rule.pattern
                    break

        result.lines.append(LineResult(n, line, verdict, spans, groups, blamed))

    result.seconds = time.perf_counter() - started
    return result


def first_difference(recipe: Recipe, text: str) -> str | None:
    """A one-line hint about why nothing matched, when nothing matched.

    Rather than leaving the user staring at an empty result, walk the FIND
    rules one at a time and name the first one that fails on its own. In
    practice it is almost always the third rule in a chain, and finding that
    by bisecting by hand is the tedium this removes.
    """
    if not recipe.finds:
        return None
    flags = recipe.flags()
    accumulated = ""
    for i, rule in enumerate(recipe.finds):
        accumulated += rule.fragment()
        try:
            rx = re.compile(accumulated, flags)
        except re.error:
            return f"Rule {i + 1} ({rule.label or rule.pattern}) will not compile."
        if not rx.search(text):
            if i == 0:
                return (f"Nothing matches even the first rule "
                        f"({rule.label or rule.pattern}).")
            return (f"Rules 1–{i} match, but adding rule {i + 1} "
                    f"({rule.label or rule.pattern}) matches nothing. "
                    "That is where the pattern breaks.")
    return None
