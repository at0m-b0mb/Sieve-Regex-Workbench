"""
Sieve without the window.

The point of keeping `core` free of any toolkit is that the same engine runs
in CI. A pattern saved from the window is a plain file; `sieve test` re-runs
its proof cases and exits non-zero when one fails, which is what makes a
detection rule something you can put in a pipeline rather than something you
remember to check.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import explain, export, flavors, library, redos, samples, scan

from .core.proof import Suite
from .core.rules import Recipe, RecipeError, recipe_from_pattern

OK, FAILED, ERROR = 0, 1, 2

def _load(path: str) -> tuple[Recipe, Suite]:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    return Recipe.from_dict(data), Suite.from_list(data.get("proof", []))

def _pattern_of(value: str) -> tuple[Recipe, Suite]:
    """Accept either a saved pattern file or a raw regex."""
    candidate = Path(value)
    if candidate.exists() and candidate.is_file():
        try:
            return _load(value)
        except (json.JSONDecodeError, RecipeError):
            pass
    return recipe_from_pattern(value), Suite()

# --- commands ---------------------------------------------------------------

def cmd_test(args) -> int:
    recipe, suite = _load(args.pattern)
    if not suite.cases:
        print(f"{recipe.name}: no proof cases to run.", file=sys.stderr)
        return ERROR
    outcome = suite.run(recipe)
    if outcome.error:
        print(f"error: {outcome.error}", file=sys.stderr)
        return ERROR
    for result in outcome.results:
        mark = "pass" if result.passed else "FAIL"
        print(f"  {mark}  {result.case.text[:88]}")
        if not result.passed:
            print(f"        {result.explanation}")
    print(f"\n{recipe.name}: {outcome.headline()}")
    return OK if outcome.green else FAILED

def cmd_scan(args) -> int:
    recipe, _ = _pattern_of(args.pattern)
    result = scan.scan(recipe, args.path, include=args.include or "",
                       context=args.context)
    writer = {"text": scan.to_text, "csv": scan.to_csv,
              "json": scan.to_json}[args.format]
    print(writer(result, redact=args.redact))
    if args.format == "text":
        print(result.summary(), file=sys.stderr)
    return OK if result.hits else FAILED

def cmd_explain(args) -> int:
    recipe, _ = _pattern_of(args.pattern)
    pattern = recipe.pattern()
    print(pattern)
    print()
    print(explain.summary(pattern))
    print()
    for line in explain.prose(pattern):
        print("  " + line)
    return OK

def cmd_lint(args) -> int:
    recipe, _ = _pattern_of(args.pattern)
    pattern = recipe.pattern()

    verdict = redos.analyse(pattern, recipe.flags())
    print(f"safety   {verdict.headline}"
          + (f"  ({verdict.growth})" if verdict.growth else ""))
    print(f"         {verdict.blurb}")
    for finding in verdict.findings:
        print(f"         · {finding.kind}: {finding.excerpt}")
    print()

    worst = OK
    for fid, report in flavors.check_all(pattern).items():
        print(f"{report.flavor.title:<32} {report.headline}")
        for issue in report.issues:
            print(f"    [{issue.severity}] {issue.message}")
        if not report.runs and args.strict:
            worst = FAILED
    if verdict.is_risky:
        worst = FAILED
    return worst

def cmd_emit(args) -> int:
    recipe, _ = _pattern_of(args.pattern)
    if args.target not in export.BY_ID:
        print("unknown target. choose one of:", file=sys.stderr)
        for target in export.TARGETS:
            print(f"  {target.id:<12} {target.title}", file=sys.stderr)
        return ERROR
    emission = export.emit(recipe, args.target, source=args.source)
    print(emission.code)
    if not emission.report.runs:
        print(f"\n# WARNING: {emission.report.headline} in "
              f"{emission.report.flavor.title}", file=sys.stderr)
        for issue in emission.report.issues:
            print(f"#   {issue.message}", file=sys.stderr)
        return FAILED
    return OK

def cmd_library(args) -> int:
    entries = library.search(args.query) if args.query else list(library.ENTRIES)
    if args.family:
        entries = [e for e in entries if args.family.lower() in e.family.lower()]
    for entry in entries:
        if args.quiet:
            print(f"{entry.id}\t{entry.pattern}")
            continue
        print(f"{entry.id}  —  {entry.title}   [{entry.family}]")
        print(f"    {entry.summary}")
        print(f"    {entry.pattern}")
        print(f"    caveat: {entry.caveat}")
        print()
    if not args.quiet:
        print(f"{len(entries)} of {len(library.ENTRIES)} patterns")
    return OK if entries else FAILED

def cmd_samples(args) -> int:
    if args.name:
        sample = samples.BY_ID.get(args.name)
        if sample is None:
            print(f"unknown sample: {args.name}", file=sys.stderr)
            return ERROR
        print(sample.text, end="")
        return OK
    for sample in samples.SAMPLES:
        print(f"{sample.id:<10} {sample.title:<26} {sample.blurb}")
    return OK

def cmd_gui(args) -> int:
    from .ui.app import main as gui_main
    return gui_main([sys.argv[0]] + ([args.pattern] if args.pattern else []))

# --- wiring -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sieve",
        description="A regex workbench for security work. "
                    "Run with no arguments to open the window.")
    subs = parser.add_subparsers(dest="command")

    p = subs.add_parser("test", help="run a pattern's proof cases")
    p.add_argument("pattern", help="a .sieve file")
    p.set_defaults(func=cmd_test)

    p = subs.add_parser("scan", help="run a pattern over files")
    p.add_argument("pattern", help="a .sieve file, or a raw regex")
    p.add_argument("path", help="a file or a folder")
    p.add_argument("--include", help="only these names, e.g. '*.log,*.conf'")
    p.add_argument("--context", type=int, default=0, metavar="N")
    p.add_argument("--redact", action="store_true",
                   help="replace every match with blocks in the output")
    p.add_argument("--format", choices=("text", "csv", "json"), default="text")
    p.set_defaults(func=cmd_scan)

    p = subs.add_parser("explain", help="read a pattern back in English")
    p.add_argument("pattern")
    p.set_defaults(func=cmd_explain)

    p = subs.add_parser("lint", help="check a pattern for ReDoS and portability")
    p.add_argument("pattern")
    p.add_argument("--strict", action="store_true",
                   help="fail if the pattern will not run in every engine")
    p.set_defaults(func=cmd_lint)

    p = subs.add_parser("emit", help="write a pattern for another tool")
    p.add_argument("pattern")
    p.add_argument("target", help="grep_e, ripgrep, sigma, yara, go, …")
    p.add_argument("--source", default="logfile",
                   help="the file the emitted command should read")
    p.set_defaults(func=cmd_emit)

    p = subs.add_parser("library", help="browse the pattern library")
    p.add_argument("query", nargs="?", default="")
    p.add_argument("--family")
    p.add_argument("--quiet", action="store_true", help="id and pattern only")
    p.set_defaults(func=cmd_library)

    p = subs.add_parser("samples", help="print a built-in corpus")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_samples)

    p = subs.add_parser("gui", help="open the window")
    p.add_argument("pattern", nargs="?")
    p.set_defaults(func=cmd_gui)
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "func", None) is None:
        args = parser.parse_args(["gui"])
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc.filename}: no such file", file=sys.stderr)
        return ERROR
    except (RecipeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR
    except KeyboardInterrupt:
        return ERROR

if __name__ == "__main__":
    sys.exit(main())
