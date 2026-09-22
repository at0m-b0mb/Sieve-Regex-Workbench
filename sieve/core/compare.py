"""
What changed.

The question a detection engineer asks after every edit is "I just loosened
that rule — what did it let in?", and no regex tool answers it. You are left
comparing two screens of highlighted text by eye, which is exactly the task
people are worst at.

So: take a baseline of what the pattern kept, edit, and get back the lines
that crossed the line in either direction. It is a set difference, which is
the whole point — it is trivial to compute and nobody offers it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .matcher import LineResult, RunResult


@dataclass(frozen=True)
class Baseline:
    """What a pattern kept at a moment in time."""

    label: str
    kept: frozenset[str]
    total: int

    @classmethod
    def of(cls, result: RunResult, label: str = "") -> "Baseline":
        # Keyed on the line's text rather than its number, so the comparison
        # survives the corpus being scrolled, re-pasted or reordered. Two
        # identical lines count once, which is the right answer for "what
        # kind of thing did this let in".
        return cls(label=label,
                   kept=frozenset(l.text for l in result.lines if l.kept),
                   total=len(result.lines))


@dataclass
class Difference:
    """The lines that crossed the line, in either direction."""

    gained: list[str] = field(default_factory=list)   # newly kept, listed
    lost: list[str] = field(default_factory=list)     # no longer kept, listed
    # The real counts. The lists above are a bounded sample, and reporting
    # their length as the total would be the same quiet lie as a truncated
    # scan claiming it read the whole file.
    gained_total: int = 0
    lost_total: int = 0
    baseline_kept: int = 0
    now_kept: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.gained_total or self.lost_total)

    @property
    def listing_is_partial(self) -> bool:
        return (len(self.gained) < self.gained_total
                or len(self.lost) < self.lost_total)

    def headline(self) -> str:
        if not self.changed:
            return f"No change — still {self.now_kept} kept"
        parts = []
        if self.gained_total:
            parts.append(f"{self.gained_total} newly kept")
        if self.lost_total:
            parts.append(f"{self.lost_total} no longer kept")
        line = " · ".join(parts)
        if self.listing_is_partial:
            shown = len(self.gained) + len(self.lost)
            line += f" ({shown} listed)"
        return line

    def direction(self) -> str:
        """Plain language for which way the pattern moved."""
        if not self.changed:
            return "This edit changed nothing about what the pattern keeps."
        if self.gained_total and not self.lost_total:
            return ("The pattern got looser: it now keeps everything it did "
                    "before, and more.")
        if self.lost_total and not self.gained_total:
            return ("The pattern got stricter: everything it keeps now, it "
                    "kept before.")
        return ("The pattern moved sideways: it gained some lines and lost "
                "others, so this is not simply looser or stricter.")


def compare(baseline: Baseline, result: RunResult, *, limit: int = 40) -> Difference:
    """What `result` keeps that `baseline` did not, and the other way round."""
    now = frozenset(l.text for l in result.lines if l.kept)
    gained = sorted(now - baseline.kept)
    lost = sorted(baseline.kept - now)
    return Difference(gained=gained[:limit], lost=lost[:limit],
                      gained_total=len(gained), lost_total=len(lost),
                      baseline_kept=len(baseline.kept), now_kept=len(now))
