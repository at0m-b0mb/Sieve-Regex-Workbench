"""
Flavor compatibility.

The regex you tested in Python is not the regex that will run in your SIEM.
Go's RE2 has no lookaround at all; POSIX grep has no \\d; JavaScript's older
engines choke on a lookbehind; Java spells named groups differently. Finding
that out from a silent zero-hit rule at three in the morning is the failure
this module exists to prevent.

The approach is deliberately conservative: detect the constructs we are sure
about, report them against a capability matrix, and say plainly when we are
guessing. A compatibility checker that quietly passes a pattern it did not
understand is worse than none.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --- capabilities -----------------------------------------------------------

@dataclass(frozen=True)
class Flavor:
    id: str
    title: str
    engine: str
    lookahead: bool = True
    lookbehind: bool = True
    variable_lookbehind: bool = False
    named_groups: bool = True
    named_syntax: str = "(?P<name>…)"
    non_capturing: bool = True
    atomic_groups: bool = False
    possessive: bool = False
    backrefs: bool = True
    shorthand_classes: bool = True      # \d \w \s
    word_boundary: bool = True
    unicode_props: bool = False         # \p{L}
    inline_flags: bool = True
    scoped_flags: bool = False          # (?i:…)
    lazy: bool = True                   # +? *?
    hex_escape: bool = True             # \xNN
    linear_time: bool = False           # immune to catastrophic backtracking
    note: str = ""


FLAVORS: dict[str, Flavor] = {
    "python": Flavor(
        "python", "Python re", "backtracking",
        variable_lookbehind=False, named_syntax="(?P<name>…)",
        atomic_groups=True, possessive=True, unicode_props=False,
        scoped_flags=True,
        note="Atomic groups and possessive quantifiers need Python 3.11+.",
    ),
    "pcre": Flavor(
        "pcre", "PCRE2 (grep -P, PHP, nginx)", "backtracking",
        variable_lookbehind=False, named_syntax="(?P<name>…) or (?<name>…)",
        atomic_groups=True, possessive=True, unicode_props=True,
        scoped_flags=True,
        note="The most featureful engine here, and the easiest to write a "
             "catastrophic pattern in.",
    ),
    "re2": Flavor(
        "re2", "RE2 (Go, ripgrep, CloudFlare)", "automaton",
        lookahead=False, lookbehind=False, backrefs=False,
        named_syntax="(?P<name>…)", unicode_props=True, scoped_flags=True,
        linear_time=True,
        note="Runs in guaranteed linear time, and pays for it by dropping "
             "lookaround and backreferences entirely.",
    ),
    "javascript": Flavor(
        "javascript", "JavaScript (ES2018+)", "backtracking",
        variable_lookbehind=True, named_syntax="(?<name>…)",
        unicode_props=True, scoped_flags=False,
        note="Lookbehind needs ES2018 — Safari only shipped it in 16.4. "
             "Inline flags like (?i) are not supported at all.",
    ),
    "java": Flavor(
        "java", "Java", "backtracking",
        variable_lookbehind=False, named_syntax="(?<name>…)",
        atomic_groups=True, possessive=True, unicode_props=True,
        scoped_flags=True,
        note="Bounded-width lookbehind only: {0,20} is fine, + is not.",
    ),
    "dotnet": Flavor(
        "dotnet", ".NET", "backtracking",
        variable_lookbehind=True, named_syntax="(?<name>…)",
        atomic_groups=True, possessive=False, unicode_props=True,
        scoped_flags=True,
        note="The only common engine with true variable-length lookbehind.",
    ),
    "rust": Flavor(
        "rust", "Rust regex crate", "automaton",
        lookahead=False, lookbehind=False, backrefs=False,
        named_syntax="(?P<name>…)", unicode_props=True, scoped_flags=True,
        linear_time=True,
        note="RE2's design in Rust. Same guarantees, same omissions.",
    ),
    "posix_ere": Flavor(
        "posix_ere", "POSIX ERE (grep -E, awk)", "automaton",
        lookahead=False, lookbehind=False, backrefs=False,
        named_groups=False, named_syntax="not supported",
        non_capturing=False,
        shorthand_classes=False, word_boundary=False, lazy=False,
        inline_flags=False, hex_escape=False, linear_time=True,
        note="No \\d, no \\w, no lazy quantifiers. Use [[:digit:]] and "
             "[[:alnum:]_] instead.",
    ),
    "posix_bre": Flavor(
        "posix_bre", "POSIX BRE (grep, sed)", "automaton",
        lookahead=False, lookbehind=False,
        named_groups=False, named_syntax="not supported",
        non_capturing=False,
        shorthand_classes=False, word_boundary=False, lazy=False,
        inline_flags=False, hex_escape=False, linear_time=True,
        note="Even ( ) and + must be backslash-escaped. Reach for -E instead "
             "unless something forces your hand.",
    ),
}

FLAVOR_ORDER = ("python", "pcre", "re2", "javascript", "java", "dotnet",
                "rust", "posix_ere", "posix_bre")


# --- construct detection ----------------------------------------------------

@dataclass(frozen=True)
class Construct:
    id: str
    label: str
    where: tuple[int, int]
    text: str


# Each probe is (id, label, compiled finder). The finders run on the raw
# pattern text, so they must skip escaped characters and character classes —
# a "(" inside [] is a literal, and reporting it as a group is the kind of
# false alarm that teaches people to ignore the checker.
_PROBES: list[tuple[str, str, re.Pattern]] = [
    ("noncapture", "non-capturing group", re.compile(r"\(\?:")),
    ("lookahead", "lookahead", re.compile(r"\(\?=|\(\?!")),
    ("lookbehind", "lookbehind", re.compile(r"\(\?<=|\(\?<!")),
    ("named_python", "named group, Python style", re.compile(r"\(\?P<\w+>")),
    ("named_dotnet", "named group, .NET/Java style", re.compile(r"\(\?<(?!=|!)\w+>")),
    ("atomic", "atomic group", re.compile(r"\(\?>")),
    ("possessive", "possessive quantifier",
     re.compile(r"(?:[*+?]|\{\d+(?:,\d*)?\})\+")),
    ("backref", "backreference", re.compile(r"\\[1-9]\d?|\(\?P=\w+\)|\\k<\w+>")),
    ("shorthand", "shorthand class", re.compile(r"\\[dDwWsS]")),
    ("boundary", "word boundary", re.compile(r"\\[bB]")),
    ("unicode_prop", "unicode property", re.compile(r"\\[pP]\{\w+\}")),
    ("inline_flag", "inline flag", re.compile(r"\(\?[aimsuxL]+\)")),
    ("scoped_flag", "scoped inline flag", re.compile(r"\(\?[aimsux]*-?[imsx]+:")),
    ("lazy", "lazy quantifier",
     re.compile(r"(?:[*+?]|\{\d+(?:,\d*)?\})\?")),
    ("hex", "hex escape", re.compile(r"\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}")),
    ("conditional", "conditional group", re.compile(r"\(\?\(")),
    ("recursion", "recursion", re.compile(r"\(\?R\)|\(\?\d+\)|\(\?&\w+\)")),
]


def _class_spans(pattern: str) -> list[tuple[int, int]]:
    """Character-class ranges, so probes can ignore what is inside them."""
    spans = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "[":
            start = i
            i += 1
            if i < len(pattern) and pattern[i] == "^":
                i += 1
            if i < len(pattern) and pattern[i] == "]":
                i += 1                      # a leading ] is a literal
            while i < len(pattern) and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            spans.append((start, min(i + 1, len(pattern))))
        i += 1
    return spans


def constructs(pattern: str) -> list[Construct]:
    """Every notable construct in a pattern, outside character classes."""
    skip = _class_spans(pattern)

    def inside_class(pos: int) -> bool:
        return any(a <= pos < b for a, b in skip)

    found: list[Construct] = []
    for cid, label, rx in _PROBES:
        for m in rx.finditer(pattern):
            if inside_class(m.start()):
                continue
            if cid == "named_dotnet" and pattern[m.start():m.start() + 4] == "(?P<":
                continue
            found.append(Construct(cid, label, m.span(), m.group(0)))
    found.sort(key=lambda c: c.where[0])
    return found


# --- the verdict ------------------------------------------------------------

BLOCKING = "blocking"
REWRITE = "rewrite"
CAUTION = "caution"

SEVERITY_ORDER = {BLOCKING: 0, REWRITE: 1, CAUTION: 2}


@dataclass
class Issue:
    severity: str
    construct: str
    message: str
    fix: str = ""


@dataclass
class Report:
    flavor: Flavor
    issues: list[Issue] = field(default_factory=list)

    @property
    def runs(self) -> bool:
        return not any(i.severity == BLOCKING for i in self.issues)

    @property
    def clean(self) -> bool:
        return not self.issues

    @property
    def headline(self) -> str:
        if self.clean:
            return "Runs as written"
        if not self.runs:
            return "Will not run"
        if any(i.severity == REWRITE for i in self.issues):
            return "Runs after a rewrite"
        return "Runs, with caveats"


def _issue_for(cid: str, text: str, f: Flavor) -> Issue | None:
    if cid == "noncapture" and not f.non_capturing:
        return Issue(REWRITE, text,
                     f"{f.title} has no (?:…) non-capturing group.",
                     "Sieve turns these into ordinary groups on export, which "
                     "shifts the numbering of any group you capture.")
    if cid == "lookahead" and not f.lookahead:
        return Issue(BLOCKING, text,
                     f"{f.title} has no lookahead.",
                     "Sieve can emit your Require and Exclude rules as a "
                     "second pass instead — see the pipeline form on Ship.")
    if cid == "lookbehind" and not f.lookbehind:
        return Issue(BLOCKING, text,
                     f"{f.title} has no lookbehind.",
                     "Capture the leading context in a group and drop it "
                     "afterwards, or filter in a second pass.")
    if cid == "lookbehind" and f.lookbehind and not f.variable_lookbehind:
        return Issue(CAUTION, text,
                     f"{f.title} needs a fixed-width lookbehind.",
                     "A + or * inside the lookbehind will be rejected at "
                     "compile time.")
    if cid in ("named_python", "named_dotnet") and not f.named_groups:
        return Issue(REWRITE, text,
                     f"{f.title} has no named groups at all.",
                     "Exported as a plain numbered group; count the "
                     "parentheses to find your field.")
    if cid == "named_python" and f.named_syntax not in ("(?P<name>…)",
                                                        "(?P<name>…) or (?<name>…)"):
        return Issue(REWRITE, text,
                     f"{f.title} spells named groups {f.named_syntax}.",
                     "Sieve rewrites this for you on export.")
    if cid == "named_dotnet" and f.named_syntax == "(?P<name>…)":
        return Issue(REWRITE, text,
                     f"{f.title} spells named groups {f.named_syntax}.",
                     "Sieve rewrites this for you on export.")
    if cid == "atomic" and not f.atomic_groups:
        return Issue(BLOCKING, text, f"{f.title} has no atomic groups.",
                     "Rewrite the inner pattern so it cannot backtrack.")
    if cid == "possessive" and not f.possessive:
        return Issue(BLOCKING, text, f"{f.title} has no possessive quantifiers.",
                     "Use an atomic group where available, or accept the "
                     "backtracking and bound the repetition.")
    if cid == "backref" and not f.backrefs:
        return Issue(BLOCKING, text, f"{f.title} has no backreferences.",
                     "No workaround inside one pattern — this needs code.")
    if cid == "shorthand" and not f.shorthand_classes:
        return Issue(REWRITE, text, f"{f.title} has no \\d, \\w or \\s.",
                     "Sieve substitutes the POSIX classes on export.")
    if cid == "boundary" and not f.word_boundary:
        return Issue(REWRITE, text, f"{f.title} has no \\b.",
                     "Left as written — GNU grep and gawk accept it. Replace "
                     "it by hand with \\< or \\> if your tool is stricter.")
    if cid == "unicode_prop" and not f.unicode_props:
        return Issue(BLOCKING, text, f"{f.title} has no \\p{{…}} properties.",
                     "Spell the ranges out, or use the `regex` module in "
                     "Python.")
    if cid == "inline_flag" and not f.inline_flags:
        return Issue(REWRITE, text, f"{f.title} has no inline flags.",
                     "Sieve moves them to the call site on export.")
    if cid == "scoped_flag" and not f.scoped_flags:
        return Issue(BLOCKING, text, f"{f.title} has no scoped inline flags.",
                     "Apply the flag to the whole pattern, or spell the "
                     "affected characters out as a class.")
    if cid == "lazy" and not f.lazy:
        return Issue(BLOCKING, text, f"{f.title} has no lazy quantifiers.",
                     "Negate the class instead: [^\"]* rather than .*?.")
    if cid == "hex" and not f.hex_escape:
        return Issue(CAUTION, text, f"{f.title} may not understand \\xNN.",
                     "Write the character itself where you can.")
    if cid == "conditional" and f.id not in ("pcre", "dotnet"):
        return Issue(BLOCKING, text, "Conditional groups are PCRE and .NET only.",
                     "Split into alternatives.")
    if cid == "recursion" and f.id != "pcre":
        return Issue(BLOCKING, text, "Recursion is PCRE only.",
                     "Balanced structures need a parser, not a regex.")
    return None


def check(pattern: str, flavor_id: str) -> Report:
    """Everything that would go wrong running `pattern` in one flavor."""
    f = FLAVORS[flavor_id]
    report = Report(flavor=f)
    seen: set[tuple[str, str]] = set()
    for c in constructs(pattern):
        issue = _issue_for(c.id, c.text, f)
        if issue is None:
            continue
        key = (issue.severity, issue.message)
        if key in seen:
            continue
        seen.add(key)
        report.issues.append(issue)
    report.issues.sort(key=lambda i: SEVERITY_ORDER[i.severity])
    return report


def check_all(pattern: str) -> dict[str, Report]:
    return {fid: check(pattern, fid) for fid in FLAVOR_ORDER}


# --- translation ------------------------------------------------------------

_POSIX_SUBS = [
    (r"\\d", "[[:digit:]]"), (r"\\D", "[^[:digit:]]"),
    (r"\\w", "[[:alnum:]_]"), (r"\\W", "[^[:alnum:]_]"),
    (r"\\s", "[[:space:]]"), (r"\\S", "[^[:space:]]"),
]


def translate(pattern: str, flavor_id: str) -> tuple[str, list[str]]:
    """Rewrite a Python-flavored pattern for a target, listing what changed.

    Only mechanical, meaning-preserving rewrites happen here. Anything that
    cannot be translated is left alone and reported by `check` as blocking —
    silently producing a pattern that compiles but means something else is the
    one outcome worth avoiding at all costs.
    """
    f = FLAVORS[flavor_id]
    notes: list[str] = []
    out = pattern

    if f.named_syntax == "(?<name>…)":
        new = re.sub(r"\(\?P<(\w+)>", r"(?<\1>", out)
        if new != out:
            notes.append("Named groups rewritten to (?<name>…).")
            out = new
        new = re.sub(r"\(\?P=(\w+)\)", r"\\k<\1>", out)
        if new != out:
            notes.append("Named backreferences rewritten to \\k<name>.")
            out = new
    elif not f.named_groups:
        new = re.sub(r"\(\?P<\w+>", "(", out)
        if new != out:
            notes.append("Named groups flattened to numbered groups.")
            out = new

    if not f.non_capturing:
        new = out.replace("(?:", "(")
        if new != out:
            notes.append("Non-capturing groups became ordinary groups; any "
                         "group numbers you rely on have shifted.")
            out = new

    if not f.shorthand_classes:
        changed = False
        # Inside a character class, \d becomes the bare class name.
        spans = _class_spans(out)
        pieces = []
        last = 0
        for a, b in spans:
            pieces.append(("out", out[last:a]))
            pieces.append(("in", out[a:b]))
            last = b
        pieces.append(("out", out[last:]))
        rebuilt = []
        for where, text in pieces:
            if where == "in":
                for old, new in [(r"\\d", "[:digit:]"), (r"\\w", "[:alnum:]_"),
                                 (r"\\s", "[:space:]")]:
                    if re.search(old, text):
                        text = re.sub(old, new, text)
                        changed = True
            else:
                for old, new in _POSIX_SUBS:
                    if re.search(old, text):
                        text = re.sub(old, new, text)
                        changed = True
            rebuilt.append(text)
        out = "".join(rebuilt)
        if changed:
            notes.append("Shorthand classes replaced with POSIX classes.")

    if not f.word_boundary and r"\b" in out:
        # Deliberately NOT rewritten. GNU grep and gawk understand \b; strict
        # POSIX tools have \< and \> for the two edges separately, and this
        # function cannot tell which edge a given \b is. Substituting the
        # wrong one would silently change the pattern's meaning, which is the
        # one outcome worth avoiding at all costs — so it is reported, not
        # guessed at.
        notes.append("\\b left as written: GNU grep and gawk accept it, strict "
                     "POSIX tools do not, and \\< / \\> cannot be chosen "
                     "safely without knowing which edge is meant.")

    if not f.inline_flags:
        m = re.match(r"^\(\?([aimsux]+)\)", out)
        if m:
            out = out[m.end():]
            notes.append(f"Leading (?{m.group(1)}) moved to the call site.")

    if f.id == "posix_bre":
        # BRE inverts which characters need escaping.
        converted = []
        i = 0
        while i < len(out):
            ch = out[i]
            if ch == "\\" and i + 1 < len(out):
                nxt = out[i + 1]
                converted.append(nxt if nxt in "(){}|+?" else ch + nxt)
                i += 2
                continue
            converted.append("\\" + ch if ch in "(){}|+?" else ch)
            i += 1
        out = "".join(converted)
        notes.append("Escaping inverted for BRE: ( ) { } | + ? now take a "
                     "backslash, and the escaped forms lose theirs.")

    return out, notes
