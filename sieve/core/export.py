"""
Emitting the pattern for the tool that will run it.

The gap Sieve exists to close is between "it works in the tester" and "it works
in the thing I deploy to". Each target here knows its own flavor, its own
quoting, and — the part that matters — what to do when the flavor cannot
express the recipe.

That last point is the design decision worth stating. RE2, ripgrep and POSIX
grep have no lookaround, so a recipe with Exclude rules cannot be one pattern
there. Rather than dropping the exclusions and handing over something that
silently over-matches, those targets emit a **two-pass pipeline**: find, then
filter. It is longer, it is honest, and it is what an engineer would have
written by hand.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

from .rules import LINE_RUN, Recipe
from . import flavors


@dataclass(frozen=True)
class Target:
    id: str
    title: str
    family: str
    flavor: str
    language: str          # for syntax highlighting in the GUI
    blurb: str


CLI = "Command line"
CODE = "Code"
SIEM = "Detection and SIEM"
KEEP = "Version control"

TARGETS: list[Target] = [
    Target("grep_e", "grep -E", CLI, "posix_ere", "bash",
           "Everywhere, including a busybox on an appliance."),
    Target("grep_p", "grep -P", CLI, "pcre", "bash",
           "GNU grep with PCRE. Not present on macOS or BSD."),
    Target("ripgrep", "ripgrep", CLI, "re2", "bash",
           "Fast and linear-time. Pass --pcre2 if you need lookaround."),
    Target("sed", "sed", CLI, "posix_bre", "bash",
           "For rewriting rather than searching."),
    Target("awk", "awk", CLI, "posix_ere", "bash",
           "When you want fields as well as a match."),
    Target("powershell", "PowerShell", CLI, "dotnet", "powershell",
           "Select-String, .NET flavor underneath."),
    Target("python", "Python", CODE, "python", "python",
           "With the flags set explicitly rather than inline."),
    Target("javascript", "JavaScript", CODE, "javascript", "javascript",
           "ES2018 or later for lookbehind."),
    Target("go", "Go", CODE, "re2", "go",
           "RE2: linear time, no lookaround, no backreferences."),
    Target("java", "Java", CODE, "java", "java",
           "Named groups use the (?<name>…) spelling."),
    Target("csharp", "C#", CODE, "dotnet", "csharp",
           "The only engine here with variable-length lookbehind."),
    Target("rust", "Rust", CODE, "rust", "rust",
           "RE2's guarantees, with the same omissions."),
    Target("php", "PHP", CODE, "pcre", "php",
           "PCRE2 with delimiters around the pattern."),
    Target("splunk", "Splunk", SIEM, "pcre", "splunk",
           "rex extracts fields; search filters lines."),
    Target("elastic", "Elasticsearch", SIEM, "re2", "json",
           "Lucene regexp is anchored and has no lookaround."),
    Target("sigma", "Sigma rule", SIEM, "re2", "yaml",
           "A portable detection skeleton around your pattern."),
    Target("yara", "YARA rule", SIEM, "pcre", "yara",
           "As a regex string inside a rule."),
    Target("suricata", "Suricata", SIEM, "pcre", "suricata",
           "A pcre keyword inside a rule; remember to anchor on content first."),
    Target("json", "Sieve pattern file", KEEP, "python", "json",
           "The whole recipe, rules and proof cases, for version control."),
]

BY_ID = {t.id: t for t in TARGETS}


def _q(s: str) -> str:
    """Single-quote for a POSIX shell, the way shlex does it."""
    return shlex.quote(s)


def _rust_raw(pattern: str) -> str:
    hashes = "#"
    while f'"{hashes}' in pattern:
        hashes += "#"
    return f'r{hashes}"{pattern}"{hashes}'


def _needs_pipeline(recipe: Recipe, target: Target) -> bool:
    f = flavors.FLAVORS[target.flavor]
    return bool(recipe.excludes or recipe.requires) and not f.lookahead


def _translated(recipe: Recipe, target: Target) -> tuple[str, list[str]]:
    """The whole pattern in the target's flavor, plus what changed."""
    pat = recipe.pattern()
    return flavors.translate(pat, target.flavor)


def _core_translated(recipe: Recipe, target: Target) -> tuple[str, list[str]]:
    """Just the FIND part — what a pipeline's first pass searches for."""
    core = recipe.anchored_core() or LINE_RUN
    return flavors.translate(core, target.flavor)


def _siem_core(recipe: Recipe, flavor: str = "pcre") -> str:
    """The FIND part WITH the recipe's anchors, for the detection targets.

    These builders used to start from core_pattern(), which by construction
    carries no ^ or $ — so a rule anchored on Build shipped to Splunk or Sigma
    unanchored, matching far more than the author had proved.
    """
    return flavors.translate(recipe.anchored_core() or LINE_RUN, flavor)[0]


def _guard_patterns(recipe: Recipe, target: Target) -> tuple[list[str], list[str]]:
    reqs = [flavors.translate(r.fragment(), target.flavor)[0]
            for r in recipe.requires]
    excs = [flavors.translate(r.fragment(), target.flavor)[0]
            for r in recipe.excludes]
    return reqs, excs


@dataclass
class Emission:
    target: Target
    code: str
    notes: list[str]
    report: flavors.Report
    pipeline: bool = False


def emit(recipe: Recipe, target_id: str, *, source: str = "logfile",
         suite=None) -> Emission:
    """Render `recipe` for one target.

    `suite` is the recipe's proof cases. Only the .sieve target carries them,
    and it advertises that it does — so without them the file you commit fails
    `sieve test` in the CI you wrote it for.
    """
    t = BY_ID[target_id]
    pipeline = _needs_pipeline(recipe, t)
    notes: list[str] = []

    if pipeline:
        pattern, xnotes = _core_translated(recipe, t)
        report = flavors.check(recipe.core_pattern() or ".*", t.flavor)
        # The guards are emitted as their own commands, so their own
        # constructs have to be checked as well. A Require rule that itself
        # contains a lookahead cannot run in grep -E either.
        seen = {(i.severity, i.message) for i in report.issues}
        for rule in recipe.requires + recipe.excludes:
            for issue in flavors.check(rule.fragment(), t.flavor).issues:
                key = (issue.severity, issue.message)
                if key not in seen:
                    seen.add(key)
                    report.issues.append(issue)
        report.issues.sort(key=lambda i: flavors.SEVERITY_ORDER[i.severity])
        notes.append("This flavor has no lookaround, so the Require and "
                     "Exclude rules run as a second pass instead of "
                     "disappearing.")
    else:
        pattern, xnotes = _translated(recipe, t)
        report = flavors.check(recipe.pattern(), t.flavor)
    notes.extend(xnotes)

    f = flavors.FLAVORS[t.flavor]
    ci = recipe.ignore_case
    reqs, excs = _guard_patterns(recipe, t)
    builder = _BUILDERS[t.id]
    if t.id == "json":
        code = _b_json(recipe, suite)
    else:
        code = builder(recipe, t, pattern, reqs, excs, pipeline, ci, source)

    if f.linear_time:
        notes.append(f"{f.title} runs in guaranteed linear time — this "
                     "pattern cannot be made to hang.")
    if f.note:
        notes.append(f.note)
    return Emission(t, code, notes, report, pipeline)


# --- per-target builders ----------------------------------------------------
# Each takes the same arguments so the table above stays declarative.

def _b_grep_e(r, t, pat, reqs, excs, pipe, ci, src):
    flag = "-Ei" if ci else "-E"
    parts = [f"grep {flag} {_q(pat)} {src}"]
    for p in reqs:
        parts.append(f"grep {flag} {_q(p)}")
    for p in excs:
        parts.append(f"grep {flag} -v {_q(p)}")
    return " \\\n  | ".join(parts)


def _b_grep_p(r, t, pat, reqs, excs, pipe, ci, src):
    flag = "-Pi" if ci else "-P"
    return f"grep {flag} {_q(pat)} {src}"


def _b_ripgrep(r, t, pat, reqs, excs, pipe, ci, src):
    flag = "-i " if ci else ""
    parts = [f"rg {flag}{_q(pat)} {src}"]
    for p in reqs:
        parts.append(f"rg {flag}{_q(p)}")
    for p in excs:
        parts.append(f"rg {flag}-v {_q(p)}")
    body = " \\\n  | ".join(parts)
    if r.excludes or r.requires:
        body += ("\n\n# Or in one pass, giving up the linear-time guarantee:\n"
                 f"rg --pcre2 {flag}{_q(r.pattern())} {src}")
    return body


def _b_sed(r, t, pat, reqs, excs, pipe, ci, src):
    lines = [f"sed -n {_q('/' + pat + '/p')} {src}"]
    for p in reqs:
        lines.append(f"sed -n {_q('/' + p + '/p')}")
    for p in excs:
        lines.append(f"sed {_q('/' + p + '/d')}")
    out = " \\\n  | ".join(lines)
    return out + "\n\n# To rewrite rather than select:\n" \
                 f"sed {_q('s/' + pat + '/REPLACEMENT/g')} {src}"


def _b_awk(r, t, pat, reqs, excs, pipe, ci, src):
    cond = [f"/{pat}/"]
    for p in reqs:
        cond.append(f"/{p}/")
    for p in excs:
        cond.append(f"!/{p}/")
    expr = " && ".join(cond)
    body = f"awk {_q(expr + ' { print }')} {src}"
    if ci:
        body = f"awk {_q('BEGIN{IGNORECASE=1} ' + expr + ' { print }')} {src}" \
               "   # IGNORECASE is a gawk extension"
    return body


def _b_powershell(r, t, pat, reqs, excs, pipe, ci, src):
    opt = "" if ci else " -CaseSensitive"
    lines = [f"Select-String{opt} -Pattern '{pat}' -Path '{src}'"]
    for p in excs:
        lines.append(f"Where-Object {{ $_ -notmatch '{p}' }}")
    for p in reqs:
        lines.append(f"Where-Object {{ $_ -match '{p}' }}")
    return " |\n  ".join(lines)


def _b_python(r, t, pat, reqs, excs, pipe, ci, src):
    flagbits = []
    if r.ignore_case:
        flagbits.append("re.IGNORECASE")
    if r.multiline:
        flagbits.append("re.MULTILINE")
    if r.dot_matches_newline:
        flagbits.append("re.DOTALL")
    flags = " | ".join(flagbits) or "0"
    name = re.sub(r"\W+", "_", r.name.strip().lower()).strip("_") or "pattern"
    fields = [g for g in re.findall(r"\(\?P<(\w+)>", pat)]
    extract = ""
    if fields:
        extract = ("\n        # captured fields: "
                   + ", ".join(fields)
                   + "\n        print(match.groupdict())")
    return f'''import re

{name.upper()} = re.compile(
    r"""{pat}""",
    {flags},
)


def scan(path):
    """Yield every line of `path` that the {r.name} recipe keeps."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            match = {name.upper()}.search(line)
            if match:{extract}
                yield number, line.rstrip("\\n")
'''


def _b_javascript(r, t, pat, reqs, excs, pipe, ci, src):
    flags = "g" + ("i" if r.ignore_case else "") + ("m" if r.multiline else "") \
            + ("s" if r.dot_matches_newline else "")
    escaped = pat.replace("\\", "\\\\").replace("/", "\\/")
    return f'''const pattern = /{escaped}/{flags};

/** Lines of `text` kept by the {r.name} recipe. */
export function scan(text) {{
  return text.split("\\n").filter((line) => {{
    pattern.lastIndex = 0;
    return pattern.test(line);
  }});
}}'''


def _b_go(r, t, pat, reqs, excs, pipe, ci, src):
    prefix = "(?i)" if r.ignore_case else ""
    filt = ""
    if excs or reqs:
        decls = []
        checks = []
        for i, p in enumerate(reqs):
            decls.append(f'\trequire{i} = regexp.MustCompile(`{prefix}{p}`)')
            checks.append(f"require{i}.MatchString(line)")
        for i, p in enumerate(excs):
            decls.append(f'\texclude{i} = regexp.MustCompile(`{prefix}{p}`)')
            checks.append(f"!exclude{i}.MatchString(line)")
        filt = "\n" + "\n".join(decls)
        cond = " && ".join(["find.MatchString(line)"] + checks)
    else:
        cond = "find.MatchString(line)"
    return f'''package main

import (
\t"bufio"
\t"fmt"
\t"os"
\t"regexp"
)

// RE2 has no lookaround, so the recipe's guards are plain checks.
var ({filt}
\tfind = regexp.MustCompile(`{prefix}{pat}`)
)

func main() {{
\tscanner := bufio.NewScanner(os.Stdin)
\tfor scanner.Scan() {{
\t\tline := scanner.Text()
\t\tif {cond} {{
\t\t\tfmt.Println(line)
\t\t}}
\t}}
}}'''


def _b_java(r, t, pat, reqs, excs, pipe, ci, src):
    flagbits = []
    if r.ignore_case:
        flagbits.append("Pattern.CASE_INSENSITIVE")
    if r.multiline:
        flagbits.append("Pattern.MULTILINE")
    if r.dot_matches_newline:
        flagbits.append("Pattern.DOTALL")
    flags = ", " + " | ".join(flagbits) if flagbits else ""
    escaped = pat.replace("\\", "\\\\").replace('"', '\\"')
    return f'''import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SievePattern {{
    private static final Pattern PATTERN = Pattern.compile(
        "{escaped}"{flags});

    public static boolean keeps(String line) {{
        return PATTERN.matcher(line).find();
    }}
}}'''


def _b_csharp(r, t, pat, reqs, excs, pipe, ci, src):
    flagbits = ["RegexOptions.Compiled"]
    if r.ignore_case:
        flagbits.append("RegexOptions.IgnoreCase")
    if r.multiline:
        flagbits.append("RegexOptions.Multiline")
    if r.dot_matches_newline:
        flagbits.append("RegexOptions.Singleline")
    return f'''using System.Text.RegularExpressions;

public static class SievePattern
{{
    private static readonly Regex Pattern = new(
        @"{pat.replace('"', '""')}",
        {" | ".join(flagbits)},
        TimeSpan.FromMilliseconds(250));   // a timeout is cheap insurance

    public static bool Keeps(string line) => Pattern.IsMatch(line);
}}'''


def _b_rust(r, t, pat, reqs, excs, pipe, ci, src):
    prefix = "(?i)" if r.ignore_case else ""
    decls, checks = [], ["find.is_match(&line)"]
    for i, p in enumerate(reqs):
        decls.append(f'    let require{i} = Regex::new({_rust_raw(prefix + p)})'
                     f'.expect("valid pattern");')
        checks.append(f"require{i}.is_match(&line)")
    for i, p in enumerate(excs):
        decls.append(f'    let exclude{i} = Regex::new({_rust_raw(prefix + p)})'
                     f'.expect("valid pattern");')
        checks.append(f"!exclude{i}.is_match(&line)")
    guards = ("\n" + "\n".join(decls)) if decls else ""
    return f'''use regex::Regex;
use std::io::{{self, BufRead}};

fn main() {{
    // The regex crate is linear-time: no lookaround, and no way to hang, so
    // the recipe's guards are plain checks rather than lookarounds.
    let find = Regex::new({_rust_raw(prefix + pat)}).expect("valid pattern");{guards}
    let stdin = io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {{
        if {" && ".join(checks)} {{
            println!("{{line}}");
        }}
    }}
}}'''


def _b_php(r, t, pat, reqs, excs, pipe, ci, src):
    mods = ("i" if r.ignore_case else "") + ("m" if r.multiline else "") \
           + ("s" if r.dot_matches_newline else "")
    delim = "#" if "#" not in pat else "~"
    return f'''<?php
$pattern = '{delim}{pat}{delim}{mods}';

foreach (file($argv[1], FILE_IGNORE_NEW_LINES) as $n => $line) {{
    if (preg_match($pattern, $line, $m)) {{
        echo ($n + 1) . ": $line\\n";
    }}
}}'''


def _b_splunk(r, t, pat, reqs, excs, pipe, ci, src):
    fields = re.findall(r"\(\?P?<(\w+)>", pat)
    core = _siem_core(r, "pcre")
    lines = ["index=* sourcetype=*"]
    for p in reqs:
        lines.append(f'| regex _raw="{p}"')
    for p in excs:
        lines.append(f'| regex _raw!="{p}"')
    if fields:
        lines.append(f'| rex field=_raw "{core}"')
        lines.append("| table _time " + " ".join(fields))
    else:
        lines.append(f'| regex _raw="{core}"')
    note = ("\n\n``` Splunk's regex command filters; rex extracts. "
            "Case folding is done with (?i) inside the pattern. ```")
    return "\n".join(lines) + note


def _b_elastic(r, t, pat, reqs, excs, pipe, ci, src):
    core = _siem_core(r, "re2")
    # Lucene regexp is anchored to the whole field, so an unanchored pattern
    # needs .* on each side — and an anchored one must NOT get it, or the
    # anchor the author set is undone by the wrapper.
    lead = "" if r.anchor_start else ".*"
    tail = "" if r.anchor_end else ".*"
    body = {
        "query": {
            "bool": {
                "must": [{"regexp": {"message": {"value": f"{lead}{core}{tail}",
                                                 "flags": "ALL"}}}],
                "must_not": [{"regexp": {"message": {"value": f".*{p}.*",
                                                     "flags": "ALL"}}}
                             for p in excs],
                "filter": [{"regexp": {"message": {"value": f".*{p}.*",
                                                   "flags": "ALL"}}}
                           for p in reqs],
            }
        }
    }
    head = ("// Lucene regexp is anchored to the whole field, which is why\n"
            "// every pattern is wrapped in .* — and why \\b does not exist.\n")
    return head + json.dumps(body, indent=2)


def _b_sigma(r, t, pat, reqs, excs, pipe, ci, src):
    core = _siem_core(r, "re2")
    title = r.name.strip() or "Untitled"
    intent = r.intent.strip() or "Written with Sieve."
    yaml = [
        f"title: {title}",
        "id: 00000000-0000-0000-0000-000000000000   # generate a real UUID",
        "status: experimental",
        f"description: {intent}",
        "logsource:",
        "  product: <product>",
        "  service: <service>",
        "detection:",
        "  selection:",
        f"    message|re: '{core}'",
    ]
    # One named block per Require. Repeating `message|re:` inside a single
    # mapping is not a list — YAML keeps only the last, so every guard but one
    # used to be discarded the moment a loader read the rule.
    parts = ["selection"]
    for i, p in enumerate(reqs):
        yaml.append(f"  require{i}:")
        yaml.append(f"    message|re: '{p}'")
        parts.append(f"require{i}")
    if excs:
        # A list under one key is OR, which is exactly what "not filter" wants.
        yaml.append("  filter:")
        yaml.append("    message|re:")
        for p in excs:
            yaml.append(f"      - '{p}'")
        parts.append("not filter")
    yaml.append(f"  condition: {' and '.join(parts)}")
    yaml.append("falsepositives:")
    yaml.append("  - Document what you found while testing this.")
    yaml.append("level: medium")
    return "\n".join(yaml)


def _b_yara(r, t, pat, reqs, excs, pipe, ci, src):
    name = re.sub(r"\W+", "_", r.name.strip()) or "Sieve_Pattern"
    mods = " nocase" if r.ignore_case else ""
    strings = [f'        $find = /{r.anchored_core() or LINE_RUN}/{mods.strip()}']
    for i, p in enumerate(reqs):
        strings.append(f"        $require{i} = /{p}/{mods.strip()}")
    for i, p in enumerate(excs):
        strings.append(f"        $exclude{i} = /{p}/{mods.strip()}")
    cond = ["$find"] + [f"$require{i}" for i in range(len(reqs))] \
        + [f"not $exclude{i}" for i in range(len(excs))]
    return f'''rule {name}
{{
    meta:
        description = "{(r.intent or r.name).replace('"', "'")}"
        author = "built with Sieve"

    strings:
{chr(10).join(strings)}

    condition:
        {" and ".join(cond)}
}}'''


def _b_suricata(r, t, pat, reqs, excs, pipe, ci, src):
    core = r.anchored_core() or LINE_RUN
    mods = "i" if r.ignore_case else ""
    msg = (r.name or "Sieve pattern").replace('"', "'")
    lines = [f'alert http any any -> any any (msg:"{msg}"; flow:established,to_server;',
             f'    pcre:"/{core}/{mods}";']
    for p in reqs:
        lines.append(f'    pcre:"/{p}/{mods}";')
    for p in excs:
        lines.append(f'    pcre:!"/{p}/{mods}";')
    lines.append("    classtype:policy-violation; sid:1000001; rev:1;)")
    note = ("\n\n# Anchor on a cheap content: match before the pcre, or every\n"
            "# packet pays the regex cost. Suricata will warn you about this.")
    return "\n".join(lines) + note


def _b_json(recipe, suite=None):
    """The whole document: rules AND the proof cases, as the blurb promises."""
    import json as _json
    doc = recipe.to_dict()
    doc["proof"] = suite.to_list() if suite is not None else []
    return _json.dumps(doc, indent=2)


_BUILDERS = {
    "grep_e": _b_grep_e, "grep_p": _b_grep_p, "ripgrep": _b_ripgrep,
    "sed": _b_sed, "awk": _b_awk, "powershell": _b_powershell,
    "python": _b_python, "javascript": _b_javascript, "go": _b_go,
    "java": _b_java, "csharp": _b_csharp, "rust": _b_rust, "php": _b_php,
    "splunk": _b_splunk, "elastic": _b_elastic, "sigma": _b_sigma,
    "yara": _b_yara, "suricata": _b_suricata, "json": _b_json,
}
