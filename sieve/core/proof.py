"""
Proof cases.

A pattern that matches your sample is not a pattern that works. A pattern that
matches these five lines and refuses those four is. Sieve keeps both kinds of
case with the recipe, runs them on every edit, and shows the count — because a
detection you cannot re-run is a detection you cannot safely change.

This is the same idea as the library's own self-test, handed to the user for
their own patterns.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .rules import Recipe, RecipeError
from . import matcher

SHOULD_MATCH = "should_match"
SHOULD_NOT = "should_not_match"


@dataclass
class Case:
    text: str
    expect: str = SHOULD_MATCH
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Case":
        return cls(text=d.get("text", ""),
                   expect=d.get("expect", SHOULD_MATCH),
                   note=d.get("note", ""))


@dataclass
class CaseResult:
    case: Case
    passed: bool
    actual: str
    spans: list[tuple[int, int]] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        if self.passed:
            return "as expected"
        if self.case.expect == SHOULD_MATCH:
            return {
                matcher.EXCLUDED: "an Exclude rule threw this line away",
                matcher.MISSING_REQUIRE: "a Require rule was not satisfied",
                matcher.NO_MATCH: "no Find rule matched",
            }.get(self.actual, "did not match")
        return "matched, and should not have"


@dataclass
class Suite:
    cases: list[Case] = field(default_factory=list)

    def run(self, recipe: Recipe) -> "SuiteResult":
        out = SuiteResult()
        for case in self.cases:
            if not case.text:
                continue
            try:
                res = matcher.run(recipe, case.text, max_lines=50)
            except RecipeError as exc:
                out.error = str(exc)
                return out
            if res.error:
                out.error = res.error
                return out
            kept = res.kept
            actual = kept[0].verdict if kept else (
                res.lines[0].verdict if res.lines else matcher.NO_MATCH)
            matched = bool(kept)
            passed = matched if case.expect == SHOULD_MATCH else not matched
            spans = kept[0].spans if kept else []
            out.results.append(CaseResult(case, passed, actual, spans))
        return out

    def to_list(self) -> list[dict]:
        return [c.to_dict() for c in self.cases]

    @classmethod
    def from_list(cls, data) -> "Suite":
        if not isinstance(data, list):
            return cls()
        return cls([Case.from_dict(d) for d in data if isinstance(d, dict)])


@dataclass
class SuiteResult:
    results: list[CaseResult] = field(default_factory=list)
    error: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def green(self) -> bool:
        return self.total > 0 and self.failed == 0 and not self.error

    def headline(self) -> str:
        if self.error:
            return self.error
        if not self.total:
            return "No proof cases yet"
        if self.green:
            return f"{self.passed} of {self.total} passing"
        return f"{self.failed} of {self.total} failing"
