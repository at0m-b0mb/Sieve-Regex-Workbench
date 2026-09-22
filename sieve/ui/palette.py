"""
The construct palette.

The gap between "I know what I want to match" and "I know how to spell it in
regex" is where most people give up. This is the bridge: every construct named
in English, inserted at the cursor, with the selection placed on the part you
are meant to replace.

Each entry is (label, snippet, cursor-hint). `‹›` inside a snippet marks the
text to select after insertion, so typing straight over it does the obvious
thing. Angle brackets would have been the natural choice and are exactly wrong:
`(?P<name>)` and `(?<=)` use them already. It is not a mode or a wizard — you are still editing the real pattern,
which is the only way anyone learns the syntax.
"""

from __future__ import annotations

# (group heading, [(label, snippet, explanation)])
GROUPS: list[tuple[str, list[tuple[str, str, str]]]] = [
    ("A single character", [
        ("Any digit", r"\d", "0 to 9"),
        ("Any letter or digit", r"\w", "a letter, a digit or an underscore"),
        ("Any whitespace", r"\s", "a space, a tab or a line break"),
        ("Any character at all", r".", "anything except a line break"),
        ("One of these…", r"[‹abc›]", "any single character you list"),
        ("Anything except…", r"[^‹abc›]", "any character you did not list"),
        ("A character range", r"[‹a-z›]", "a span of characters"),
        ("Not a digit", r"\D", "anything that is not 0 to 9"),
        ("Not whitespace", r"\S", "anything that is not a space or tab"),
    ]),
    ("How many times", [
        ("One or more", r"+", "at least one, as many as possible"),
        ("Any number, including none", r"*", "zero or more"),
        ("Optional", r"?", "zero or one"),
        ("Exactly this many…", r"{‹3›}", "a fixed count"),
        ("Between two counts…", r"{‹2,5›}", "a range"),
        ("At least this many…", r"{‹2›,}", "a floor with no ceiling"),
        ("As FEW as possible", r"?", "add after + or * to stop it being greedy"),
    ]),
    ("Grouping and choice", [
        ("Either this or that", r"(?:‹this›|‹that›)", "one of several alternatives"),
        ("Group these together", r"(?:‹…›)", "so a quantifier applies to all of it"),
        ("Keep this as a field…", r"(?P<‹name›>‹…›)", "a named capture you can export"),
    ]),
    ("Where it sits", [
        ("Start of the line", r"^", "the match must begin the line"),
        ("End of the line", r"$", "the match must end the line"),
        ("A whole word", r"\\b‹word›\\b", "not part of a longer word"),
        ("Only if followed by…", r"(?=‹…›)", "checked, but not consumed"),
        ("Only if NOT followed by…", r"(?!‹…›)", "checked, but not consumed"),
        ("Only if preceded by…", r"(?<=‹…›)", "looks backwards; needs a fixed width"),
    ]),
    ("Things in log lines", [
        ("A run of spaces", r"\s+", "one or more of any whitespace"),
        ("Up to the next space", r"\S+", "one whole whitespace-delimited token"),
        ("Anything in quotes", r'"[^"]*"', "a quoted field, without crossing the closing quote"),
        ("Anything in brackets", r"\[[^\]]*\]", "a bracketed field, e.g. a timestamp"),
        ("A number", r"\d+", "one or more digits"),
        ("A decimal number", r"\d+\.\d+", "digits, a dot, digits"),
        ("A hex value", r"[0-9a-fA-F]+", "one or more hex characters"),
        ("Up to the end of the line", r"[^\n]*", "the rest of the line, and no further"),
    ]),
]


def flat() -> list[tuple[str, str, str, str]]:
    """(group, label, snippet, explanation) for every entry."""
    return [(g, lab, snip, why) for g, items in GROUPS for lab, snip, why in items]


def expand(snippet: str) -> tuple[str, int, int]:
    """Turn a snippet into (text, selection_start, selection_length).

    The first `‹…›` placeholder becomes the selection, so whatever the user
    types next replaces the part they were always going to replace. Remaining
    placeholders keep their markers off the final text but are not
    selected — Tab-through would be a nice touch and is not worth the state.
    """
    out = []
    sel_start = -1
    sel_len = 0
    i = 0
    while i < len(snippet):
        if snippet[i] == "‹":
            end = snippet.find("›", i)
            if end != -1:
                inner = snippet[i + 1:end]
                if sel_start < 0:
                    sel_start = len(out)
                    sel_len = len(inner)
                out.append(inner)
                i = end + 1
                continue
        out.append(snippet[i])
        i += 1
    text = "".join(out)
    if sel_start < 0:
        sel_start, sel_len = len(text), 0
    return text, sel_start, sel_len
