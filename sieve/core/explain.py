"""
Reading a regex back in English.

Half of security regex work is inheriting someone else's pattern from a blog
post, a vendor rule or a five-year-old detection, and having to decide whether
it does what its name claims. This module tokenises a pattern and says what
each piece means, in order, with the nesting shown — so the answer comes from
reading rather than from guessing.

It is a pretty-printer, not a parser with a formal grammar. Where it is unsure
it says "unrecognised" rather than inventing a plausible description.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Token:
    start: int
    end: int
    text: str
    kind: str
    meaning: str
    depth: int = 0
    note: str = ""

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)


_SHORTHAND = {
    r"\d": ("class", "any digit, 0 to 9"),
    r"\D": ("class", "any character that is not a digit"),
    r"\w": ("class", "any letter, digit or underscore"),
    r"\W": ("class", "any character that is not a letter, digit or underscore"),
    r"\s": ("class", "any whitespace: space, tab or line break"),
    r"\S": ("class", "any character that is not whitespace"),
    r"\b": ("anchor", "a word boundary — the edge between a word character and anything else"),
    r"\B": ("anchor", "not a word boundary"),
    r"\A": ("anchor", "the very start of the text, ignoring the multiline flag"),
    r"\Z": ("anchor", "the very end of the text"),
    r"\z": ("anchor", "the absolute end of the text"),
    r"\n": ("literal", "a line break"),
    r"\r": ("literal", "a carriage return"),
    r"\t": ("literal", "a tab"),
    r"\f": ("literal", "a form feed"),
    r"\v": ("literal", "a vertical tab"),
    r"\0": ("literal", "a null byte"),
}

_GROUP_OPENERS = [
    ("(?:", "group", "a group that holds things together but keeps nothing"),
    ("(?=", "lookahead", "only if what follows matches — this text is checked, not consumed"),
    ("(?!", "lookahead", "only if what follows does NOT match"),
    ("(?<=", "lookbehind", "only if what came before matches"),
    ("(?<!", "lookbehind", "only if what came before does NOT match"),
    ("(?>", "group", "an atomic group — once it matches, the engine will not reconsider it"),
    ("(?#", "comment", "a comment; the engine ignores it"),
]

_FLAG_MEANING = {
    "i": "ignore case",
    "m": "^ and $ match at every line break",
    "s": "a dot also matches a line break",
    "x": "whitespace in the pattern is ignored",
    "a": "shorthand classes match ASCII only",
    "u": "unicode matching",
    "L": "locale-dependent matching",
}


def _quantifier_meaning(q: str) -> str:
    lazy = q.endswith("?") and len(q) > 1 and q not in ("??",)
    possessive = q.endswith("+") and q not in ("+",)
    base = q.rstrip("?+") if (lazy or possessive) else q
    if q == "?":
        base, lazy, possessive = "?", False, False
    text = {
        "*": "repeated any number of times, including none",
        "+": "repeated one or more times",
        "?": "optional — zero or one time",
    }.get(base)
    if text is None:
        m = re.fullmatch(r"\{(\d*),?(\d*)\}", base)
        if m:
            lo, hi = m.group(1), m.group(2)
            if "," not in base:
                text = f"repeated exactly {lo} times"
            elif hi == "":
                text = f"repeated {lo} or more times"
            elif lo == "":
                text = f"repeated up to {hi} times"
            else:
                text = f"repeated between {lo} and {hi} times"
        else:
            text = "repeated"
    if lazy:
        text += ", as few times as possible"
    elif possessive:
        text += ", and never given back"
    return text


def _class_meaning(body: str) -> str:
    negated = body.startswith("^")
    if negated:
        body = body[1:]
    parts: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            tok = body[i:i + 2]
            parts.append(_SHORTHAND.get(tok, ("", tok))[1] or tok)
            i += 2
            continue
        if body.startswith("[:", i):
            end = body.find(":]", i)
            if end != -1:
                parts.append(f"a POSIX {body[i + 2:end]} character")
                i = end + 2
                continue
        if i + 2 < len(body) and body[i + 1] == "-":
            parts.append(f"{body[i]} to {body[i + 2]}")
            i += 3
            continue
        parts.append(repr(body[i]))
        i += 1
    joined = ", ".join(parts) if parts else "nothing"
    if negated:
        return f"any character EXCEPT: {joined}"
    return f"any one of: {joined}"


def tokenise(pattern: str) -> list[Token]:
    """Split a pattern into described pieces, tracking group depth."""
    tokens: list[Token] = []
    i = 0
    depth = 0
    group_number = 0
    n = len(pattern)

    def attach_quantifier(start_of_quant: int) -> int:
        """If a quantifier follows, fold it into the previous token's meaning."""
        m = re.match(r"(?:[*+?]|\{\d*,?\d*\})[?+]?", pattern[start_of_quant:])
        if not m or not tokens:
            return start_of_quant
        q = m.group(0)
        tokens.append(Token(start_of_quant, start_of_quant + len(q), q,
                            "quantifier", _quantifier_meaning(q), depth))
        return start_of_quant + len(q)

    while i < n:
        ch = pattern[i]

        # --- escapes -------------------------------------------------------
        if ch == "\\" and i + 1 < n:
            two = pattern[i:i + 2]
            if two in _SHORTHAND:
                kind, meaning = _SHORTHAND[two]
                tokens.append(Token(i, i + 2, two, kind, meaning, depth))
                i = attach_quantifier(i + 2)
                continue
            m = re.match(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|N\{[^}]+\})", pattern[i:])
            if m:
                tokens.append(Token(i, i + m.end(), m.group(0), "literal",
                                    f"the character {m.group(0)}", depth))
                i = attach_quantifier(i + m.end())
                continue
            m = re.match(r"\\([pP])\{(\w+)\}", pattern[i:])
            if m:
                neg = "not " if m.group(1) == "P" else ""
                tokens.append(Token(i, i + m.end(), m.group(0), "class",
                                    f"{neg}a unicode {m.group(2)} character", depth))
                i = attach_quantifier(i + m.end())
                continue
            m = re.match(r"\\([1-9]\d?)", pattern[i:])
            if m:
                tokens.append(Token(i, i + m.end(), m.group(0), "backref",
                                    f"the same text that group {m.group(1)} matched",
                                    depth,
                                    "Backreferences make a pattern much more "
                                    "expensive, and RE2-family engines refuse them."))
                i = attach_quantifier(i + m.end())
                continue
            m = re.match(r"\\k<(\w+)>|\(\?P=(\w+)\)", pattern[i:])
            if m:
                name = m.group(1) or m.group(2)
                tokens.append(Token(i, i + m.end(), m.group(0), "backref",
                                    f"the same text the group “{name}” matched", depth))
                i = attach_quantifier(i + m.end())
                continue
            tokens.append(Token(i, i + 2, two, "literal",
                                f"a literal {two[1]!r}", depth))
            i = attach_quantifier(i + 2)
            continue

        # --- character class ----------------------------------------------
        if ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            body = pattern[i + 1:j]
            tokens.append(Token(i, min(j + 1, n), pattern[i:min(j + 1, n)],
                                "class", _class_meaning(body), depth))
            i = attach_quantifier(min(j + 1, n))
            continue

        # --- groups ---------------------------------------------------------
        if ch == "(":
            matched = False
            for opener, kind, meaning in _GROUP_OPENERS:
                if pattern.startswith(opener, i):
                    tokens.append(Token(i, i + len(opener), opener, kind, meaning, depth))
                    depth += 1
                    i += len(opener)
                    matched = True
                    break
            if matched:
                continue
            m = re.match(r"\(\?P<(\w+)>|\(\?<(\w+)>|\(\?'(\w+)'", pattern[i:])
            if m:
                name = m.group(1) or m.group(2) or m.group(3)
                group_number += 1
                tokens.append(Token(i, i + m.end(), m.group(0), "group",
                                    f"a group kept as the field “{name}” "
                                    f"(also group {group_number})", depth))
                depth += 1
                i += m.end()
                continue
            m = re.match(r"\(\?([aimsuxL]*)-?([imsx]*):", pattern[i:])
            if m:
                on = ", ".join(_FLAG_MEANING.get(c, c) for c in m.group(1))
                off = ", ".join(_FLAG_MEANING.get(c, c) for c in m.group(2))
                bits = []
                if on:
                    bits.append("from here on: " + on)
                if off:
                    bits.append("and not: " + off)
                tokens.append(Token(i, i + m.end(), m.group(0), "flags",
                                    "a group where " + "; ".join(bits), depth))
                depth += 1
                i += m.end()
                continue
            m = re.match(r"\(\?([aimsuxL]+)\)", pattern[i:])
            if m:
                meaning = ", ".join(_FLAG_MEANING.get(c, c) for c in m.group(1))
                tokens.append(Token(i, i + m.end(), m.group(0), "flags",
                                    f"for the whole pattern: {meaning}", depth))
                i += m.end()
                continue
            group_number += 1
            tokens.append(Token(i, i + 1, "(", "group",
                                f"a group, kept as group {group_number}", depth))
            depth += 1
            i += 1
            continue

        if ch == ")":
            depth = max(0, depth - 1)
            tokens.append(Token(i, i + 1, ")", "group", "end of the group", depth))
            i = attach_quantifier(i + 1)
            continue

        # --- anchors and alternation ----------------------------------------
        if ch == "^":
            tokens.append(Token(i, i + 1, "^", "anchor",
                                "the start of a line", depth))
            i += 1
            continue
        if ch == "$":
            tokens.append(Token(i, i + 1, "$", "anchor",
                                "the end of a line", depth))
            i += 1
            continue
        if ch == "|":
            tokens.append(Token(i, i + 1, "|", "alternation",
                                "or — either what came before, or what follows", depth))
            i += 1
            continue
        if ch == ".":
            tokens.append(Token(i, i + 1, ".", "class",
                                "any character except a line break", depth))
            i = attach_quantifier(i + 1)
            continue
        if ch in "*+?":
            tokens.append(Token(i, i + 1, ch, "quantifier",
                                _quantifier_meaning(ch), depth,
                                "This quantifier has nothing before it."))
            i += 1
            continue
        if ch == "{":
            m = re.match(r"\{\d*,?\d*\}", pattern[i:])
            if m:
                tokens.append(Token(i, i + m.end(), m.group(0), "quantifier",
                                    _quantifier_meaning(m.group(0)), depth))
                i += m.end()
                continue

        # --- runs of plain text ---------------------------------------------
        j = i
        while j < n and pattern[j] not in "\\[](){}^$|.*+?":
            j += 1
        if j == i:
            tokens.append(Token(i, i + 1, ch, "unrecognised",
                                "unrecognised — Sieve is not sure what this does", depth))
            i += 1
            continue
        # A trailing character may belong to a following quantifier.
        if j < n and pattern[j] in "*+?{" and j - 1 > i:
            j -= 1
        run = pattern[i:j]
        tokens.append(Token(i, j, run, "literal",
                            f"the text {run!r}, exactly", depth))
        i = attach_quantifier(j)
        continue

    return tokens


def prose(pattern: str) -> list[str]:
    """The pattern as indented English, one line per token."""
    out = []
    for t in tokenise(pattern):
        indent = "    " * t.depth
        out.append(f"{indent}{t.text}   — {t.meaning}")
    return out


def summary(pattern: str) -> str:
    """One sentence about the pattern's overall shape."""
    toks = tokenise(pattern)
    kinds = [t.kind for t in toks]
    bits = []
    groups = sum(1 for t in toks if t.kind == "group" and t.text != ")")
    if groups:
        bits.append(f"{groups} group{'s' if groups != 1 else ''}")
    looks = sum(1 for t in toks if t.kind in ("lookahead", "lookbehind"))
    if looks:
        bits.append(f"{looks} lookaround{'s' if looks != 1 else ''}")
    alts = kinds.count("alternation")
    if alts:
        bits.append(f"{alts} alternation{'s' if alts != 1 else ''}")
    quants = kinds.count("quantifier")
    if quants:
        bits.append(f"{quants} quantifier{'s' if quants != 1 else ''}")
    anchored = any(t.text in ("^", r"\A") for t in toks)
    lead = "Anchored to the start" if anchored else "Unanchored"
    if not bits:
        return f"{lead}; a plain literal pattern."
    return f"{lead}; {', '.join(bits)}."
