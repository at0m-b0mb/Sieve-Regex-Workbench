"""
The recipe model.

A working pattern is almost never one regex. It is "find these, but only when
that is also present, and never when this other thing is". Sieve keeps those
three intentions as separate, named, individually switchable rules and only
joins them into a regex at the last moment — which is what makes a pattern
editable a month later by someone who did not write it.

Nothing in this module imports a GUI toolkit. The recipe is plain data plus a
compiler, so the same object serves the window, the command line and the tests.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict

SCHEMA = 1

# A .sieve file is a document people share, so every value in one is untrusted
# input. Two of them reach the regex engine directly.
#
# A capture name is interpolated into `(?P<name>…)`. Left unchecked, the name
# "n>(a+)+$)(?P<z" closes the group and opens another, so a crafted file can
# inject arbitrary regex — including a catastrophic shape — through a field
# that is supposed to be an identifier.
# ASCII only, deliberately. Python would accept "unicodé" as a group name,
# but this name is exported to nine engines and Go, Java and JavaScript
# would each reject it — so a name that works here and fails there is worse
# than no name at all.
_GROUP_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# A repetition count is interpolated into `{n}`. `{1000000000}` compiles
# happily and then tries to do it. No legitimate pattern needs more than this.
MAX_REPEAT = 10_000


def safe_group_name(name: str) -> str:
    """The name if it is a plain identifier, otherwise nothing.

    Returning "" makes the caller fall back to an unnamed capture group: the
    field is lost, which is visible, rather than the pattern silently becoming
    something else, which is not.
    """
    return name if isinstance(name, str) and _GROUP_NAME.match(name) else ""


def safe_count(value, default: int = 0) -> int:
    """A repetition count from a file, coerced and bounded."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(n, MAX_REPEAT))

# --- rule kinds -------------------------------------------------------------
#
# FIND is the thing you are looking for. REQUIRE and EXCLUDE are conditions on
# the surrounding unit of text (a line, by default) rather than on the match
# itself, which is the distinction most regex tools blur and most analysts
# actually need.

FIND = "find"
REQUIRE = "require"
EXCLUDE = "exclude"
KINDS = (FIND, REQUIRE, EXCLUDE)

KIND_LABEL = {
    FIND: "Find",
    REQUIRE: "Require",
    EXCLUDE: "Exclude",
}

KIND_BLURB = {
    FIND: "What the match itself is made of.",
    REQUIRE: "Must also appear on the line, anywhere.",
    EXCLUDE: "Throws the line away if it appears.",
}

# How several FIND rules relate to each other.
JOIN_SEQUENCE = "sequence"   # one after another
JOIN_ANY = "any"             # any one of them
JOIN_ALL = "all"             # all present, order irrelevant
JOINS = (JOIN_SEQUENCE, JOIN_ANY, JOIN_ALL)

JOIN_LABEL = {
    JOIN_SEQUENCE: "one after another",
    JOIN_ANY: "any one of them",
    JOIN_ALL: "all of them, any order",
}


class RecipeError(ValueError):
    """A recipe that cannot be compiled, carrying a message fit to show."""


def escape_literal(text: str) -> str:
    """Escape text for use inside a pattern.

    `re.escape` is correct but noisy — it escapes characters that no flavor
    treats as special, and the result is what the user reads on screen. We
    escape exactly the metacharacters shared across the flavors Sieve emits,
    so the pattern stays legible.
    """
    out = []
    for ch in text:
        if ch in "\\^$.|?*+()[]{}/":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        else:
            out.append(ch)
    return "".join(out)


def _atoms(fragment: str) -> list[tuple[str, str]]:
    """Split a fragment into top-level (atom, quantifier) pairs.

    Deliberately shallow: it walks the string tracking escapes, character
    classes and paren depth, and stops at the first thing it does not
    recognise. Everything that consumes it treats "unsure" as "wrap it", so a
    gap here costs a redundant (?:…) rather than a wrong pattern.
    """
    atoms: list[tuple[str, str]] = []
    i = 0
    n = len(fragment)
    while i < n:
        start = i
        ch = fragment[i]

        if ch == "|":
            atoms.append(("|", ""))
            i += 1
            continue

        if ch == "\\":
            i += 2
            m = re.match(r"\\[pP]\{\w+\}", fragment[start:])
            if m:
                i = start + m.end()
        elif ch == "[":
            i += 1
            if i < n and fragment[i] == "^":
                i += 1
            if i < n and fragment[i] == "]":
                i += 1
            while i < n and fragment[i] != "]":
                i += 2 if fragment[i] == "\\" else 1
            i = min(i + 1, n)
        elif ch == "(":
            depth = 0
            while i < n:
                here = fragment[i]
                if here == "\\":
                    i += 2
                    continue
                if here == "[":
                    # Skip the character class wholesale. Every step needs its
                    # own bound: `([a` is not exotic input, it is the state
                    # you pass through while typing `([a-z]+)`, and reading
                    # one character past the end of it used to raise
                    # IndexError out of the Build page's live validator.
                    i += 1
                    if i < n and fragment[i] == "^":
                        i += 1
                    if i < n and fragment[i] == "]":
                        i += 1          # a leading ] is a literal
                    while i < n and fragment[i] != "]":
                        i += 2 if fragment[i] == "\\" else 1
                    i = min(i + 1, n)
                    continue
                if here == "(":
                    depth += 1
                elif here == ")":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            if depth != 0:
                return []                 # unbalanced: caller must wrap
        elif ch in ")]":
            return []                     # unbalanced: caller must wrap
        else:
            i += 1

        quant = ""
        m = re.match(r"(?:[*+?]|\{\d+(?:,\d*)?\})[?+]?", fragment[i:])
        if m:
            quant = m.group(0)
            i += m.end()
        atoms.append((fragment[start:i - len(quant)], quant))
    return atoms


def _needs_group(fragment: str) -> bool:
    """True when a fragment must be wrapped before a quantifier is appended.

    Only a single unquantified atom survives on its own. `ab` does not: `ab+`
    repeats the b alone, which is the single most common hand-written regex
    bug and the reason this function exists rather than a `len() == 1` check.
    """
    if fragment == "":
        return False
    atoms = _atoms(fragment)
    if len(atoms) != 1:
        return True
    text, quant = atoms[0]
    return bool(quant) or text == "|"


def _has_top_alternation(fragment: str) -> bool:
    """True when concatenating this fragment would break it apart.

    `a|b` followed by `c` concatenates to `a|bc`, which means something else
    entirely. Wrapping only in this case keeps the emitted pattern readable
    instead of burying it in non-capturing groups.
    """
    atoms = _atoms(fragment)
    if not atoms:
        return True
    return any(text == "|" for text, _ in atoms)


def for_concat(fragment: str) -> str:
    """A fragment safe to place next to another one."""
    return f"(?:{fragment})" if _has_top_alternation(fragment) else fragment


def group(fragment: str, capturing: bool = False, name: str = "") -> str:
    """Wrap a fragment only if it would not survive being quantified."""
    if capturing and name:
        return f"(?P<{name}>{fragment})"
    if capturing:
        return f"({fragment})"
    return f"(?:{fragment})" if _needs_group(fragment) else fragment


# --- repetition -------------------------------------------------------------

ONCE = "once"
OPTIONAL = "optional"
ANY = "any"          # zero or more
SOME = "some"        # one or more
EXACT = "exact"
RANGE = "range"
AT_LEAST = "at_least"
REPEATS = (ONCE, OPTIONAL, ANY, SOME, EXACT, RANGE, AT_LEAST)

REPEAT_LABEL = {
    ONCE: "exactly once",
    OPTIONAL: "optional",
    ANY: "any number of times",
    SOME: "one or more times",
    EXACT: "an exact number of times",
    RANGE: "between two counts",
    AT_LEAST: "at least",
}


@dataclass
class Repeat:
    """How many times a rule's fragment may occur."""

    mode: str = ONCE
    minimum: int = 1
    maximum: int = 1
    greedy: bool = True

    def suffix(self) -> str:
        if self.mode == ONCE:
            return ""
        if self.mode == OPTIONAL:
            core = "?"
        elif self.mode == ANY:
            core = "*"
        elif self.mode == SOME:
            core = "+"
        elif self.mode == EXACT:
            core = "{%d}" % safe_count(self.minimum)
        elif self.mode == AT_LEAST:
            core = "{%d,}" % safe_count(self.minimum)
        elif self.mode == RANGE:
            lo = safe_count(self.minimum)
            hi = max(lo, safe_count(self.maximum))
            core = "{%d,%d}" % (lo, hi)
        else:
            raise RecipeError(f"unknown repeat mode {self.mode!r}")
        if not self.greedy and self.mode != EXACT:
            core += "?"
        return core

    def describe(self) -> str:
        lazy = "" if self.greedy else ", as few as possible"
        if self.mode == ONCE:
            return ""
        if self.mode == OPTIONAL:
            return "optionally" + lazy
        if self.mode == ANY:
            return "any number of times" + lazy
        if self.mode == SOME:
            return "one or more times" + lazy
        if self.mode == EXACT:
            return f"exactly {self.minimum} times"
        if self.mode == AT_LEAST:
            return f"at least {self.minimum} times" + lazy
        if self.mode == RANGE:
            return f"{self.minimum} to {self.maximum} times" + lazy
        return ""


# --- rules ------------------------------------------------------------------

@dataclass
class Rule:
    """One named intention.

    `pattern` is a regex fragment. `literal` means treat it as plain text and
    escape it — which is how most people should start, and how you avoid the
    classic incident where a dot in a hostname quietly matched everything.
    """

    kind: str = FIND
    pattern: str = ""
    label: str = ""
    literal: bool = False
    whole_word: bool = False
    capture: bool = False
    capture_name: str = ""
    ignore_case: bool | None = None       # None: follow the recipe
    enabled: bool = True
    repeat: Repeat = field(default_factory=Repeat)
    note: str = ""
    source: str = ""                      # library id, when it came from one

    # -- compilation --------------------------------------------------------

    def fragment(self, *, for_flavor_case: bool = True) -> str:
        """The rule as a regex fragment, with its own modifiers applied."""
        core = escape_literal(self.pattern) if self.literal else self.pattern
        if core == "":
            return ""

        # A leading (?i) is a *global* flag. It is legal on its own and
        # illegal the moment this fragment is concatenated with another, which
        # is exactly what a recipe does. Scope it to this fragment instead, so
        # a pattern pasted in from anywhere composes rather than explodes.
        leading = re.match(r"\(\?([aimsuxL]+)\)", core)
        if leading:
            core = f"(?{leading.group(1)}:{core[leading.end():]})"

        if self.whole_word:
            lead = r"\b" if _word_edge(core, start=True) else r"(?<!\S)"
            tail = r"\b" if _word_edge(core, start=False) else r"(?!\S)"
            core = f"{lead}{group(core)}{tail}"

        suffix = self.repeat.suffix()
        # A pattern that already names this group captures it itself; wrapping
        # again is a redefinition error, and taking a library pattern with a
        # named group and ticking "Keep as field" would hit it every time.
        name = safe_group_name(self.capture_name)
        already_named = name and f"(?P<{name}>" in core
        capture = self.capture and not already_named
        if suffix:
            core = group(core, capturing=False) + suffix
            if capture:
                core = group(core, capturing=True, name=name)
        elif capture:
            core = group(core, capturing=True, name=name)

        # A per-rule case override becomes an inline scoped flag. Scoped flags
        # are a modern-Python / PCRE feature; flavors.py warns where they are
        # not available rather than silently dropping the intent.
        if for_flavor_case and self.ignore_case is not None:
            flag = "i" if self.ignore_case else ""
            off = "" if self.ignore_case else "i"
            core = f"(?{flag}-{off}:{core})" if off else f"(?{flag}:{core})"
        return core

    def describe(self) -> str:
        """One plain sentence, used by the builder and the CLI."""
        what = self.label or ("the text " + repr(self.pattern) if self.literal
                              else "the pattern " + self.pattern)
        bits = [what]
        if self.whole_word:
            bits.append("as a whole word")
        rep = self.repeat.describe()
        if rep:
            bits.append(rep)
        if self.ignore_case is True:
            bits.append("ignoring case")
        elif self.ignore_case is False:
            bits.append("case-sensitively")
        if self.capture:
            name = self.capture_name or "unnamed"
            bits.append(f"kept as the field “{name}”")
        return " ".join(bits)

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Build a rule from an untrusted document.

        Unknown values are refused rather than coerced quietly. A rule whose
        `kind` is a typo used to be dropped on the floor by `of_kind` and
        never mentioned again — silent rule loss, in a tool whose entire
        argument is that it does not silently lose rules.
        """
        data = dict(data)
        rep = data.pop("repeat", None) or {}
        if isinstance(rep, str):
            rep = {"mode": rep}
        if not isinstance(rep, dict):
            rep = {}

        kind = data.get("kind", FIND)
        if kind not in KINDS:
            raise RecipeError(
                f"This rule has an unknown kind, {kind!r}. "
                f"Expected one of: {', '.join(KINDS)}.")
        mode = rep.get("mode", ONCE)
        if mode not in REPEATS:
            raise RecipeError(f"This rule repeats in an unknown way, {mode!r}.")

        known = {f for f in cls.__dataclass_fields__ if f != "repeat"}
        clean = {k: v for k, v in data.items() if k in known}
        for flag in ("literal", "whole_word", "capture", "enabled"):
            if flag in clean:
                clean[flag] = bool(clean[flag])
        if "ignore_case" in clean and clean["ignore_case"] is not None:
            clean["ignore_case"] = bool(clean["ignore_case"])
        for text in ("pattern", "label", "capture_name", "note", "source"):
            if text in clean and not isinstance(clean[text], str):
                clean[text] = str(clean[text])

        repeat = Repeat(
            mode=mode,
            minimum=safe_count(rep.get("minimum", 1), 1),
            maximum=safe_count(rep.get("maximum", 1), 1),
            greedy=bool(rep.get("greedy", True)))
        return cls(repeat=repeat, **clean)


def _word_edge(fragment: str, *, start: bool) -> bool:
    """Would \\b actually do the right thing at this edge?

    `\\b` sits between a word character and a non-word character, so anchoring
    a fragment that begins with punctuation — `-Encoded`, `/etc/passwd` — with
    `\\b` silently never matches. That trap eats hours. We detect it and use a
    whitespace-boundary lookaround instead.
    """
    probe = fragment
    for opener in ("(?:", "(?=", "(?!", "(?P<", "("):
        if start and probe.startswith(opener):
            probe = probe[len(opener):]
            probe = probe.split(">", 1)[-1] if opener == "(?P<" else probe
            break
    if not start:
        probe = probe.rstrip(")")
        probe = re.sub(r"(?:[*+?]|\{\d+(?:,\d*)?\})[?+]?$", "", probe)
    if not probe:
        return True
    if start:
        if probe[0] == "\\":
            return probe[1:2] in "dwsSWDbB" or probe[1:2].isalnum()
        return probe[0].isalnum() or probe[0] in "_[."
    if probe[-1] == "]":
        return True
    if len(probe) >= 2 and probe[-2] == "\\":
        return probe[-1] in "dwsSWDbB" or probe[-1].isalnum()
    return probe[-1].isalnum() or probe[-1] in "_."


# --- the recipe -------------------------------------------------------------

# Guards are conditions on the line, always. Spelling them `.*` let them reach
# across a newline as soon as dot_matches_newline was set, so the emitted regex
# and the Proof page disagreed about the same text. `[^\n]` is immune to the
# flag and says what is actually meant.
LINE_RUN = "[^\\n]*"


@dataclass
class Recipe:
    """A named, savable set of rules plus the flags they run under."""

    name: str = "Untitled pattern"
    intent: str = ""                      # what this is for, in the author's words
    rules: list[Rule] = field(default_factory=list)
    join: str = JOIN_SEQUENCE
    ignore_case: bool = False
    dot_matches_newline: bool = False
    multiline: bool = True
    anchor_start: bool = False
    anchor_end: bool = False

    # -- rule access --------------------------------------------------------

    def of_kind(self, kind: str, *, enabled_only: bool = True) -> list[Rule]:
        return [r for r in self.rules
                if r.kind == kind and (r.enabled or not enabled_only)
                and r.pattern.strip() != ""]

    @property
    def finds(self) -> list[Rule]:
        return self.of_kind(FIND)

    @property
    def requires(self) -> list[Rule]:
        return self.of_kind(REQUIRE)

    @property
    def excludes(self) -> list[Rule]:
        return self.of_kind(EXCLUDE)

    # -- compilation --------------------------------------------------------

    def core_pattern(self) -> str:
        """The FIND rules alone — what is highlighted as a match."""
        frags = [r.fragment() for r in self.finds]
        frags = [f for f in frags if f]
        if not frags:
            return ""
        if self.join == JOIN_ANY:
            return "|".join(group(f) if "|" in f else f for f in frags)
        if self.join == JOIN_ALL:
            # Order-free "all present" is a lookahead set over the line, with
            # the match itself being the whole line. This is the only honest
            # reading: there is no single contiguous span to highlight.
            return "".join(f"(?=.*{group(f)})" for f in frags) + ".*"
        return "".join(for_concat(f) for f in frags)

    def guard_prefix(self) -> str:
        """REQUIRE/EXCLUDE rules as lookarounds over the line."""
        out = []
        for r in self.requires:
            out.append(f"(?={LINE_RUN}{group(r.fragment())})")
        for r in self.excludes:
            out.append(f"(?!{LINE_RUN}{group(r.fragment())})")
        return "".join(out)

    def pattern(self) -> str:
        """The whole recipe as one regex string."""
        core = self.core_pattern()
        guards = self.guard_prefix()
        if not core and not guards:
            return ""
        if not core:
            core = LINE_RUN

        # Wrap before anything is attached. `^passwd|shadow$` does NOT mean
        # "the line is exactly passwd or exactly shadow" — | binds loosest, so
        # the anchors land on one branch each and both leak. for_concat wraps
        # only when there is a top-level alternation, so simple patterns stay
        # readable.
        body = for_concat(core)

        if guards:
            # Guards are conditions on the line, so they sit behind a line
            # anchor even when the user has not asked to anchor the match.
            bridge = "" if self.anchor_start else f"{LINE_RUN}?"
            body = f"^{guards}{bridge}{body}"
        elif self.anchor_start:
            body = "^" + body
        if self.anchor_end:
            body = body + "$"
        return body

    def flags(self) -> int:
        f = 0
        if self.ignore_case:
            f |= re.IGNORECASE
        if self.dot_matches_newline:
            f |= re.DOTALL
        if self.multiline:
            f |= re.MULTILINE
        return f

    def flag_letters(self) -> str:
        """Inline-flag letters, in the conventional order."""
        s = ""
        if self.ignore_case:
            s += "i"
        if self.multiline:
            s += "m"
        if self.dot_matches_newline:
            s += "s"
        return s

    def compile(self) -> re.Pattern:
        pat = self.pattern()
        if not pat:
            raise RecipeError("This recipe has no enabled rules yet.")
        try:
            return re.compile(pat, self.flags())
        except re.error as exc:
            raise RecipeError(_friendly_re_error(exc, pat)) from exc

    def anchored_core(self) -> str:
        """The FIND part carrying the recipe's anchors, and nothing else.

        The anchors have to live *inside* this pattern rather than be applied
        to the match spans afterwards. Filtering the results of finditer
        cannot reproduce backtracking: `(?:a|b)|alpha` against "alpha" reports
        a one-character match at position 0, whereas the real engine, on
        finding that `$` fails there, backtracks into the `alpha` branch and
        matches the whole line. Post-hoc filtering would call that line a
        miss, and the Proof page would contradict the pattern it exports.
        """
        core = self.core_pattern()
        if not core:
            return ""
        body = for_concat(core)
        if self.anchor_start:
            body = "^" + body
        if self.anchor_end:
            body = body + "$"
        return body

    def compile_core(self) -> re.Pattern:
        """The FIND part plus anchors — what decides whether a line matches."""
        core = self.anchored_core()
        if not core:
            raise RecipeError("No Find rule is enabled.")
        try:
            return re.compile(core, self.flags())
        except re.error as exc:
            raise RecipeError(_friendly_re_error(exc, core)) from exc

    def is_empty(self) -> bool:
        return not any(r.pattern.strip() for r in self.rules if r.enabled)

    # -- narration ----------------------------------------------------------

    def describe(self) -> list[str]:
        """The recipe read back as English, one line per clause."""
        lines: list[str] = []
        finds = self.finds
        if finds:
            if len(finds) == 1:
                lines.append("Find " + finds[0].describe() + ".")
            else:
                lines.append(f"Find {JOIN_LABEL[self.join]}:")
                for r in finds:
                    lines.append("  · " + r.describe())
        else:
            lines.append("Find every line (no Find rule is enabled).")
        for r in self.requires:
            lines.append("Only when the line also contains " + r.describe() + ".")
        for r in self.excludes:
            lines.append("Never when the line contains " + r.describe() + ".")
        extras = []
        if self.ignore_case:
            extras.append("case is ignored")
        if self.anchor_start:
            extras.append("the match must start the line")
        if self.anchor_end:
            extras.append("the match must end the line")
        if self.dot_matches_newline:
            extras.append("a dot also matches a line break")
        if extras:
            lines.append("Throughout, " + ", ".join(extras) + ".")
        return lines

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "intent": self.intent,
            "join": self.join,
            "ignore_case": self.ignore_case,
            "dot_matches_newline": self.dot_matches_newline,
            "multiline": self.multiline,
            "anchor_start": self.anchor_start,
            "anchor_end": self.anchor_end,
            "rules": [r.to_dict() for r in self.rules],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "Recipe":
        if not isinstance(data, dict):
            raise RecipeError("That file does not hold a Sieve pattern.")
        schema = data.get("schema", SCHEMA)
        if not isinstance(schema, int) or schema > SCHEMA:
            raise RecipeError(
                f"This pattern was written by a newer Sieve (format {schema}).")
        raw = data.get("rules", [])
        if not isinstance(raw, list):
            raise RecipeError("The 'rules' field should be a list.")
        rules = []
        for index, entry in enumerate(raw, start=1):
            if not isinstance(entry, dict):
                raise RecipeError(f"Rule {index} is not an object.")
            try:
                rules.append(Rule.from_dict(entry))
            except RecipeError as exc:
                raise RecipeError(f"Rule {index}: {exc}") from exc

        known = {f for f in cls.__dataclass_fields__ if f != "rules"}
        clean = {k: v for k, v in data.items() if k in known}
        join = clean.get("join", JOIN_SEQUENCE)
        if join not in JOINS:
            raise RecipeError(
                f"This pattern joins its Find rules in an unknown way, "
                f"{join!r}. Expected one of: {', '.join(JOINS)}.")
        for flag in ("ignore_case", "dot_matches_newline", "multiline",
                     "anchor_start", "anchor_end"):
            if flag in clean:
                clean[flag] = bool(clean[flag])
        for text in ("name", "intent"):
            if text in clean and not isinstance(clean[text], str):
                clean[text] = str(clean[text])
        return cls(rules=rules, **clean)

    @classmethod
    def from_json(cls, text: str) -> "Recipe":
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise RecipeError(f"That is not valid JSON: {exc.msg}") from exc

    def copy(self) -> "Recipe":
        return Recipe.from_dict(self.to_dict())


def recipe_from_pattern(pattern: str, name: str = "Imported pattern") -> Recipe:
    """Wrap a raw regex as a one-rule recipe, so anything can be imported."""
    return Recipe(name=name, rules=[Rule(kind=FIND, pattern=pattern,
                                         label="imported pattern")])


_ERROR_HELP = {
    "nothing to repeat": "A +, * or ? has nothing in front of it to repeat.",
    "missing ), unterminated subpattern": "A ( was opened and never closed.",
    "unbalanced parenthesis": "There is a ) with no matching (.",
    "unterminated character set": "A [ was opened and never closed.",
    "bad escape": "A backslash is followed by a character that means nothing.",
    "multiple repeat": "Two quantifiers in a row — wrap the first in a group.",
    "bad character range": "A range like [z-a] runs backwards.",
    "look-behind requires fixed-width pattern":
        "A lookbehind has to be a fixed length — no + or * inside it.",
}


def _friendly_re_error(exc: re.error, pattern: str) -> str:
    msg = str(exc.msg) if hasattr(exc, "msg") else str(exc)
    for needle, help_text in _ERROR_HELP.items():
        if needle in msg:
            where = f" (around character {exc.pos})" if exc.pos is not None else ""
            return f"{help_text}{where}"
    where = f" at character {exc.pos}" if getattr(exc, "pos", None) is not None else ""
    return f"{msg.capitalize()}{where}."
