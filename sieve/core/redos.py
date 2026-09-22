"""
Catastrophic backtracking analysis.

A regex is code, and this is the one place where a plausible-looking pattern
can take down the thing running it. `(a+)+b` against forty a's is 2^40 steps.
Put that in a WAF rule, a log parser or an input validator and you have handed
someone a denial of service with a forty-character request.

Two methods, because neither alone is honest:

  1. A static read of the pattern's shape, looking for the three published
     families of ambiguity. Fast, explains itself, and can be wrong in both
     directions.
  2. A measured probe: build adversarial input, run the real engine against
     growing lengths under a hard timeout, and fit the growth curve. Slower,
     but it is evidence rather than suspicion.

The verdict never says "safe". It says what was checked and what was found,
because a pattern this module likes can still be pathological against an input
shape nobody thought to generate.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

# Verdict grades, worst first.
CATASTROPHIC = "catastrophic"
SUPERLINEAR = "superlinear"
SUSPECT = "suspect"
NOTHING_FOUND = "nothing_found"
UNKNOWN = "unknown"

GRADE_LABEL = {
    CATASTROPHIC: "Catastrophic backtracking",
    SUPERLINEAR: "Super-linear growth measured",
    SUSPECT: "Risky shape, not reproduced",
    NOTHING_FOUND: "Nothing found by these checks",
    UNKNOWN: "Could not be analysed",
}

GRADE_BLURB = {
    CATASTROPHIC: "Runtime explodes on crafted input. Do not deploy this "
                  "where an attacker controls the text.",
    SUPERLINEAR: "Runtime grows faster than the input does. Safe on short "
                 "lines, dangerous on a long one.",
    SUSPECT: "The pattern has a shape known to backtrack badly, but the "
             "probe did not reproduce it. Treat as unproven, not as cleared.",
    NOTHING_FOUND: "No ambiguity found by the static checks and no blow-up "
                   "measured. This is the absence of evidence, not a "
                   "guarantee.",
    UNKNOWN: "The pattern could not be compiled or probed.",
}


@dataclass
class Finding:
    kind: str
    detail: str
    span: tuple[int, int] | None = None
    excerpt: str = ""


@dataclass
class Measurement:
    length: int
    seconds: float
    timed_out: bool = False


@dataclass
class Verdict:
    grade: str
    findings: list[Finding] = field(default_factory=list)
    measurements: list[Measurement] = field(default_factory=list)
    attack_input: str = ""
    growth: str = ""
    checked: list[str] = field(default_factory=list)

    @property
    def headline(self) -> str:
        return GRADE_LABEL[self.grade]

    @property
    def blurb(self) -> str:
        return GRADE_BLURB[self.grade]

    @property
    def is_risky(self) -> bool:
        return self.grade in (CATASTROPHIC, SUPERLINEAR)


# --- static analysis --------------------------------------------------------

# A quantified group that itself contains a quantifier: (a+)+, (\d*)*, (\w+)*.
_NESTED = re.compile(
    r"\((?!\?[:=!<P#])"           # a group that is not a lookaround
    r"(?P<body>[^()]*?"
    r"(?:[*+]|\{\d+,\d*\})"       # something unbounded inside
    r"[^()]*?)"
    r"\)"
    r"(?P<outer>[*+]|\{\d+,\d*\})(?!\+)"   # ...and quantified outside
)
_NESTED_NC = re.compile(
    r"\(\?:(?P<body>[^()]*?(?:[*+]|\{\d+,\d*\})[^()]*?)\)"
    r"(?P<outer>[*+]|\{\d+,\d*\})(?!\+)"
)

# Alternatives that can match the same text, under a quantifier: (a|a)+, (\w|\d)+
_ALT_QUANT = re.compile(r"\((?:\?:)?(?P<body>[^()]*\|[^()]*)\)(?P<outer>[*+])(?!\+)")

# Two adjacent unbounded quantifiers over overlapping classes: \s*\s*, .*.*
_ADJACENT = re.compile(r"(\\[dwsDWS]|\[[^\]]+\]|\.)([*+])\s*(\\[dwsDWS]|\[[^\]]+\]|\.)([*+])")


def _classes_overlap(a: str, b: str) -> bool:
    """Do two single-token classes accept any character in common?

    Approximate on purpose, and biased towards saying yes: a false alarm costs
    the user a glance, a missed overlap costs them an outage.
    """
    if a == b:
        return True
    if a == "." or b == ".":
        return True
    probe = ("a", "Z", "0", " ", "\t", "_", "-", ".", "/", "@", "%", "\x80")
    try:
        ra, rb = re.compile(a), re.compile(b)
    except re.error:
        return True
    return any(ra.fullmatch(c) and rb.fullmatch(c) for c in probe)


def _alternation_overlaps(body: str) -> bool:
    parts = [p for p in _split_top_alternation(body) if p]
    for i, x in enumerate(parts):
        for y in parts[i + 1:]:
            if x == y:
                return True
            if len(x) <= 4 and len(y) <= 4 and _classes_overlap(x, y):
                return True
    return False


def _split_top_alternation(body: str) -> list[str]:
    parts, depth, cur, i = [], 0, [], 0
    in_class = False
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            cur.append(body[i:i + 2]); i += 2; continue
        if in_class:
            cur.append(ch)
            if ch == "]":
                in_class = False
            i += 1; continue
        if ch == "[":
            in_class = True; cur.append(ch); i += 1; continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur)); cur = []; i += 1; continue
        cur.append(ch); i += 1
    parts.append("".join(cur))
    return parts


def static_findings(pattern: str) -> list[Finding]:
    """The shapes known to cause exponential or polynomial blow-up."""
    out: list[Finding] = []

    for rx in (_NESTED, _NESTED_NC):
        for m in rx.finditer(pattern):
            out.append(Finding(
                "nested quantifier",
                "A group that already repeats is repeated again. Every way of "
                "splitting the input between the two is a separate path the "
                "engine has to try before it can fail.",
                m.span(), m.group(0)))

    for m in _ALT_QUANT.finditer(pattern):
        if _alternation_overlaps(m.group("body")):
            out.append(Finding(
                "overlapping alternation",
                "Two branches of this alternation can match the same text, "
                "and the whole group repeats. The engine must try both "
                "branches at every position.",
                m.span(), m.group(0)))

    for m in _ADJACENT.finditer(pattern):
        if _classes_overlap(m.group(1), m.group(3)):
            out.append(Finding(
                "adjacent unbounded repeats",
                f"{m.group(1)}{m.group(2)} and {m.group(3)}{m.group(4)} accept "
                "the same characters, so the boundary between them is "
                "ambiguous and every split gets tried.",
                m.span(), m.group(0)))

    # Unbounded .* either side of something is not ambiguous by itself, but
    # inside a group that repeats it is the classic parser-killer.
    if re.search(r"\(\?:?[^()]*\.\*[^()]*\)[*+]", pattern):
        out.append(Finding(
            "dot-star inside a repeat",
            "A greedy .* inside a repeating group makes the number of ways to "
            "divide the input grow with its length.", None, ".*"))

    deduped: list[Finding] = []
    seen = set()
    for f in out:
        key = (f.kind, f.excerpt)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


# --- adversarial probe ------------------------------------------------------

def _attack_seeds(pattern: str) -> list[str]:
    """Characters likely to force the ambiguous path, read off the pattern."""
    seeds: list[str] = []
    for m in re.finditer(r"\\([dwsDWS])|\[([^\]]{1,40})\]|([A-Za-z0-9])", pattern):
        if m.group(1):
            seeds.append({"d": "1", "w": "a", "s": " ",
                          "D": "!", "W": "!", "S": "a"}[m.group(1)])
        elif m.group(2):
            body = m.group(2)
            if body.startswith("^"):
                seeds.append("!")
            else:
                for c in "a1 _-.":
                    try:
                        if re.fullmatch(f"[{body}]", c):
                            seeds.append(c); break
                    except re.error:
                        pass
        elif m.group(3):
            seeds.append(m.group(3))
    out, seen = [], set()
    for s in seeds:
        if s not in seen:
            seen.add(s); out.append(s)
    return out[:4] or ["a"]


def _suffixes(pattern: str) -> list[str]:
    """Tails that make the match fail, which is what forces full backtracking."""
    tails = ["!", "\x00", "\u2028"]
    # A literal at the end of the pattern is a good thing to withhold.
    m = re.search(r"([A-Za-z0-9])\$?$", pattern)
    if m:
        tails.insert(0, "!")
    return tails


# The ladder is the whole safety story. You cannot time-box a backtracking
# regex by measuring after it returns — `^(a+)+$` against 200 characters never
# returns at all. So the lengths start tiny and grow in small additive steps
# while an exponential pattern would still be cheap, then geometrically once
# only a polynomial pattern could still be running. We stop the instant a step
# exceeds the budget, which bounds the step after it to a few times the budget
# rather than to the heat death of the universe.
LADDER = (4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 36, 40,
          48, 56, 64, 80, 100, 128, 160, 200, 256, 320, 400, 512, 640, 800,
          1000, 1280, 1600, 2000, 2560, 3200)

# Below this, we are measuring the clock and the scheduler rather than the
# pattern. A shared CI runner under load produced enough jitter at the
# microsecond scale to fit a "quadratic" curve through a plainly linear
# pattern — and a checker that cries wolf is one people learn to ignore.
NOISE_FLOOR = 50e-6

# Each length is timed several times and the BEST run kept. Timing noise is
# one-sided: interference can only ever make a run slower, so the minimum is
# the closest thing to the true cost.
REPEATS = 3


def probe(pattern: str, flags: int = 0, *, budget: float = 0.05,
          total_budget: float = 1.5,
          lengths: tuple[int, ...] = LADDER,
          ) -> tuple[list[Measurement], str]:
    """Time the real engine against growing adversarial input.

    Returns the measurements and the worst input found. `budget` bounds one
    run; `total_budget` bounds the whole probe, so the window stays responsive
    however pathological the pattern is.
    """
    try:
        rx = re.compile(pattern, flags)
    except re.error:
        return [], ""

    started = time.perf_counter()
    best: list[Measurement] = []
    best_slope = -1.0
    worst_input = ""

    for seed in _attack_seeds(pattern):
        for tail in _suffixes(pattern):
            if time.perf_counter() - started > total_budget:
                return best, worst_input
            runs: list[Measurement] = []
            blew_up = False
            for n in lengths:
                text = seed * n + tail
                elapsed = None
                try:
                    for _ in range(REPEATS):
                        start = time.perf_counter()
                        rx.search(text)
                        run = time.perf_counter() - start
                        elapsed = run if elapsed is None else min(elapsed, run)
                        if run > budget:
                            break        # no point repeating a blow-up
                except Exception:
                    break
                if elapsed is None:
                    break
                over = elapsed > budget
                runs.append(Measurement(n, elapsed, over))
                if over:
                    blew_up = True
                    break
                if time.perf_counter() - started > total_budget:
                    break
            if not runs:
                continue
            slope = _slope(runs)
            if blew_up or slope > best_slope:
                best, best_slope = runs, slope
                sample = seed * runs[-1].length + tail
                worst_input = sample[:120] + ("\u2026" if len(sample) > 120 else "")
            if blew_up:
                return best, worst_input
    return best, worst_input


def _slope(runs: list[Measurement]) -> float:
    """Growth exponent: 1.0 is linear, 2.0 is quadratic, above that is trouble.

    Fitted by least squares across every usable point rather than taken from
    the first and last, because two noisy endpoints can describe any curve you
    like. Points under NOISE_FLOOR are dropped: at that scale the number is
    the clock's resolution and the scheduler's mood, not the pattern's cost.
    Returns 0.0 — "no evidence of growth" — when there is not enough signal to
    say anything, which is the honest answer far more often than a slope is.
    """
    import math
    usable = [m for m in runs if m.seconds >= NOISE_FLOOR]
    if len(usable) < 3:
        return 0.0
    xs = [math.log(m.length) for m in usable]
    ys = [math.log(m.seconds) for m in usable]
    # Need real spread on both axes before a fit means anything.
    if max(xs) - min(xs) < 0.7 or max(ys) - min(ys) < 0.7:
        return 0.0
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom <= 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom


def analyse(pattern: str, flags: int = 0, *, measure: bool = True,
            budget: float = 0.35) -> Verdict:
    """Static read plus, optionally, a measured probe."""
    checked = ["nested quantifiers", "overlapping alternation",
               "adjacent unbounded repeats", "dot-star inside a repeat"]
    if not pattern:
        return Verdict(UNKNOWN, checked=checked)
    try:
        re.compile(pattern, flags)
    except re.error:
        return Verdict(UNKNOWN, checked=checked)

    findings = static_findings(pattern)
    measurements: list[Measurement] = []
    attack = ""
    if measure:
        checked.append("timed probe against adversarial input")
        measurements, attack = probe(pattern, flags, budget=budget)

    exponent = _slope(measurements)
    timed_out = any(m.timed_out for m in measurements)
    blew_at = measurements[-1].length if timed_out and measurements else None

    # Where it blew up matters more than a slope fitted to the handful of
    # points before it did. An exponential pattern exceeds the budget while
    # the input is still tiny, and by then there are too few measurements
    # above the noise floor to fit anything — so the length is the evidence.
    if blew_at is not None and blew_at <= 256:
        grade = CATASTROPHIC
    elif exponent >= 2.6:
        grade = CATASTROPHIC
    elif timed_out or exponent >= 1.35:
        grade = SUPERLINEAR
    elif findings:
        grade = SUSPECT
    else:
        grade = NOTHING_FOUND

    if blew_at is not None:
        growth = (f"exceeded the time limit at {blew_at} characters of "
                  "crafted input")
        if exponent > 0:
            growth += f"; time ≈ input^{exponent:.2f}"
    elif exponent > 0:
        growth = f"time ≈ input^{exponent:.2f}"
        if exponent < 1.2:
            growth += " (linear)"
        elif exponent < 2.2:
            growth += " (quadratic)"
        else:
            growth += " (worse than quadratic)"
    else:
        growth = "ran too fast at every length to show a trend"

    return Verdict(grade, findings, measurements, attack, growth, checked)


def safer_rewrite(pattern: str) -> list[str]:
    """Concrete suggestions, tied to what was actually found."""
    tips: list[str] = []
    kinds = {f.kind for f in static_findings(pattern)}
    if "nested quantifier" in kinds:
        tips.append("Collapse the nesting: (a+)+ and a+ match the same strings, "
                    "and only one of them backtracks.")
        tips.append("If the inner group must stay, make it atomic — (?>a+)+ — "
                    "so the engine cannot revisit it.")
    if "overlapping alternation" in kinds:
        tips.append("Make the branches mutually exclusive, so only one can ever "
                    "match at a given position.")
    if "adjacent unbounded repeats" in kinds:
        tips.append("Replace .*X.* with a negated class: [^X]*X[^X]* has exactly "
                    "one way to match.")
    if ".*" in pattern or ".+" in pattern:
        tips.append("Bound the repetition. .{0,200} says what you mean and "
                    "cannot run away.")
    tips.append("Whatever the shape, an engine with linear-time guarantees — "
                "RE2, Go, Rust, ripgrep — removes the risk entirely.")
    return tips
