"""
Running a finished recipe over real files.

Once a pattern is proven, the next question is always "so what does it find in
the actual data". This walks files or a directory, applies the recipe, and
returns hits with their surrounding lines.

Two things here are deliberate. Binary files are skipped by sniffing for a
null byte rather than by extension, because attackers do not use the extension
you expect. And redaction is available at the point of output: if a pattern
finds card numbers, you want the report to prove they are there without
copying them into a ticket.
"""

from __future__ import annotations

import fnmatch
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .rules import Recipe
from . import matcher

SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv",
             ".mypy_cache", ".pytest_cache", "dist", "build", ".idea",
             ".DS_Store", ".tox", "site-packages"}

BINARY_SNIFF = 8192


@dataclass
class Hit:
    path: str
    line_number: int
    text: str
    spans: list[tuple[int, int]] = field(default_factory=list)
    groups: dict[str, str] = field(default_factory=dict)
    before: list[str] = field(default_factory=list)
    after: list[str] = field(default_factory=list)

    def redacted(self) -> str:
        """The line with every match replaced, keeping the shape visible."""
        if not self.spans:
            return self.text
        out = []
        cursor = 0
        for a, b in sorted(self.spans):
            out.append(self.text[cursor:a])
            out.append("█" * max(1, b - a))
            cursor = b
        out.append(self.text[cursor:])
        return "".join(out)


@dataclass
class ScanResult:
    hits: list[Hit] = field(default_factory=list)
    files_read: int = 0
    files_skipped: int = 0
    lines_read: int = 0
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    stopped_early: bool = False

    def summary(self) -> str:
        files = f"{self.files_read} file{'s' if self.files_read != 1 else ''}"
        hits = f"{len(self.hits)} hit{'s' if len(self.hits) != 1 else ''}"
        base = (f"{hits} in {files} · {self.lines_read:,} lines · "
                f"{self.seconds:.2f}s")
        if self.files_skipped:
            base += f" · {self.files_skipped} skipped"
        if self.stopped_early:
            base += " · stopped at the limit"
        return base

    def by_file(self) -> dict[str, list[Hit]]:
        out: dict[str, list[Hit]] = {}
        for h in self.hits:
            out.setdefault(h.path, []).append(h)
        return out


def looks_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(BINARY_SNIFF)
    except OSError:
        return True
    return b"\x00" in chunk


def walk(root: Path, *, include: str = "", exclude_globs: tuple[str, ...] = (),
         follow_symlinks: bool = False, max_files: int = 20000) -> list[Path]:
    """Files under `root`, honouring include/exclude globs and skip-dirs."""
    if root.is_file():
        return [root]
    found: list[Path] = []
    patterns = [p.strip() for p in include.split(",") if p.strip()]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if patterns and not any(fnmatch.fnmatch(name, p) for p in patterns):
                continue
            full = Path(dirpath) / name
            rel = str(full)
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g)
                   for g in exclude_globs):
                continue
            found.append(full)
            if len(found) >= max_files:
                return found
    return found


def scan(recipe: Recipe, paths, *, include: str = "",
         exclude_globs: tuple[str, ...] = (), context: int = 0,
         max_hits: int = 5000, max_file_mb: float = 64.0,
         should_stop=None, on_progress=None) -> ScanResult:
    """Apply a recipe to every text file under `paths`.

    `should_stop` is polled between files so the window's Stop button works;
    `on_progress` is called with (done, total, path) for the progress bar.
    """
    started = time.perf_counter()
    result = ScanResult()

    targets: list[Path] = []
    for p in ([paths] if isinstance(paths, (str, Path)) else paths):
        path = Path(p).expanduser()
        if not path.exists():
            result.errors.append(f"{path}: not found")
            continue
        targets.extend(walk(path, include=include, exclude_globs=exclude_globs))

    limit_bytes = int(max_file_mb * 1024 * 1024)
    total = len(targets)

    for index, path in enumerate(targets, start=1):
        if should_stop is not None and should_stop():
            result.stopped_early = True
            break
        if on_progress is not None:
            on_progress(index, total, str(path))
        try:
            if path.stat().st_size > limit_bytes:
                result.files_skipped += 1
                continue
            if looks_binary(path):
                result.files_skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.errors.append(f"{path}: {exc.strerror or exc}")
            result.files_skipped += 1
            continue

        run = matcher.run(recipe, text, max_lines=200000)
        if run.error:
            result.errors.append(f"{path}: {run.error}")
            break
        result.files_read += 1
        result.lines_read += len(run.lines)

        lines = run.lines
        for line in lines:
            if not line.kept:
                continue
            i = line.number - 1
            hit = Hit(str(path), line.number, line.text, line.spans, line.groups,
                      [l.text for l in lines[max(0, i - context):i]] if context else [],
                      [l.text for l in lines[i + 1:i + 1 + context]] if context else [])
            result.hits.append(hit)
            if len(result.hits) >= max_hits:
                result.stopped_early = True
                break
        if result.stopped_early:
            break

    result.seconds = time.perf_counter() - started
    return result


# --- reports ----------------------------------------------------------------

def to_text(result: ScanResult, *, redact: bool = False) -> str:
    out = [f"# Sieve scan — {result.summary()}", ""]
    for path, hits in result.by_file().items():
        out.append(path)
        for h in hits:
            body = h.redacted() if redact else h.text
            out.append(f"  {h.line_number:>6}: {body}")
        out.append("")
    for err in result.errors:
        out.append(f"! {err}")
    return "\n".join(out)


def to_csv(result: ScanResult, *, redact: bool = False) -> str:
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    fields = sorted({k for h in result.hits for k in h.groups})
    writer.writerow(["path", "line", "text"] + fields)
    for h in result.hits:
        body = h.redacted() if redact else h.text
        writer.writerow([h.path, h.line_number, body]
                        + [h.groups.get(f, "") for f in fields])
    return buf.getvalue()


def to_json(result: ScanResult, *, redact: bool = False) -> str:
    import json
    payload = {
        "summary": result.summary(),
        "files_read": result.files_read,
        "files_skipped": result.files_skipped,
        "lines_read": result.lines_read,
        "seconds": round(result.seconds, 3),
        "redacted": redact,
        "errors": result.errors,
        "hits": [
            {"path": h.path, "line": h.line_number,
             "text": h.redacted() if redact else h.text,
             "fields": h.groups}
            for h in result.hits
        ],
    }
    return json.dumps(payload, indent=2)
