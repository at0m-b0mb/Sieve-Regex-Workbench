"""
How it works — the diagram, the reasoning, and the colophon.

Not a help page. The flow chart is the product's argument in one picture: text
goes in on the left, passes three named gates, and comes out as kept lines
with fields; everything else — the library, the proof cases, the safety check,
the exports — hangs off that spine.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from ...core import export, library
from .. import theme
from ..marks import FlowChart, SieveMark
from ..widgets import (Card, caption, hairline, intro, label, overline,
                       page_body, row, scrolled, title)

STAGES = [
    ("FIND",
     "What the match is made of. Several Find rules join one after another, "
     "or as alternatives, or as an unordered set — your choice, stated once "
     "rather than encoded in punctuation."),
    ("REQUIRE",
     "A condition on the line rather than on the match. “Only when the word "
     "failure is also present.” Compiles to a lookahead, or to a second pass "
     "where the target engine has none."),
    ("EXCLUDE",
     "The noise you already know about: your own scanner, your health checks, "
     "the one service that logs an error every minute and always has. This is "
     "the rule kind that turns a demo into a detection."),
]

WHY = [
    ("Rules stay separate",
     "Three intentions kept apart, joined only when the pattern is emitted. "
     "Six months later, someone can switch off one Exclude rule and see what "
     "changes — which is impossible once it has all been flattened into one "
     "line of punctuation."),
    ("Every claim is tested",
     f"The {len(library.ENTRIES)} library patterns each carry the examples "
     "they must match and must not, and the test suite runs all of them. Your "
     "own proof cases work the same way and are saved with the pattern."),
    ("The target engine gets a vote",
     f"{len(export.TARGETS)} export targets, checked against what each engine "
     "can really do. RE2 and POSIX grep have no lookaround at all, so Sieve "
     "emits a two-pass pipeline rather than quietly dropping your Exclude "
     "rules and handing you something that over-matches."),
    ("Nothing is called safe",
     "The Safety page reports what it checked and what it measured. A pattern "
     "it likes can still be pathological against an input shape nobody "
     "generated, and saying otherwise would be the most dangerous sentence in "
     "the application."),
]


class AboutPage(QWidget):
    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        host, box = page_body()

        box.addWidget(title("How Sieve works"))
        box.addWidget(intro(
            "Text goes in on the left and passes three named gates. Everything "
            "else in the application hangs off that spine: the library fills "
            "the gates, the proof cases hold them in place, and the exports "
            "carry them to whatever will actually run them."))

        chart_card = Card()
        self.chart = FlowChart(self.mode)
        self.chart.setMinimumHeight(400)
        chart_card.add(self.chart, 1)
        box.addWidget(chart_card)

        stages = Card("The three gates")
        for name, text in STAGES:
            stages.add(label(name, object_name="CardTitle"))
            stages.add(label(text, wrap=True))
            stages.add(hairline())
        box.addWidget(stages)

        why = Card("Why it is built this way")
        for name, text in WHY:
            why.add(label(name, object_name="CardTitle"))
            why.add(label(text, wrap=True))
            why.add(hairline())
        box.addWidget(why)

        use = Card("A first pass, end to end", flat=True)
        for n, step in enumerate([
            "Open Library and take a pattern as a Find rule — say “SSH auth "
            "failure” or “AWS access key ID”.",
            "On Build, add an Exclude rule for the noise you already know "
            "about. Watch the plain-English reading agree with what you meant.",
            "On Proof, pick a sample corpus. The match map beside the text "
            "shows where the hits land; excluded lines are tinted, so you can "
            "see what you threw away rather than only what you kept.",
            "Pin the behaviour down: paste a line that must match and one that "
            "must never, and they re-run on every edit from then on.",
            "Run Safety. It reads the pattern for known-bad shapes, then times "
            "the real engine against adversarial input and plots the curve.",
            "Ship it. Pick your target and copy — the pattern arrives written "
            "in that engine's flavor, with the caveats printed underneath.",
        ], start=1):
            use.add(label(f"{n}.  {step}", wrap=True))
        box.addWidget(use)

        colophon = Card("Colophon", flat=True)
        colophon.add_layout(row(SieveMark(44, self.mode), None))
        colophon.add(label(
            f"Set in {theme.SERIF} for identity and figures, {theme.SANS} for "
            f"the controls, and {theme.MONO} for patterns and log text — the "
            "three jobs a single family does badly.", wrap=True))
        colophon.add(label(
            "The ground is warm paper rather than white, so a screen full of "
            "monospaced text does not glare. One accent, a deep brass, used "
            "for anything that carries words; a brighter gold reserved for "
            "marks that carry none. Dark mode is true black with neutral "
            "greys above it — nothing in it reads as blue.", wrap=True))
        colophon.add(label(
            "The mark is a sieve seen from the side: two grains through the "
            "mesh, one held back. Find, and exclude.", wrap=True))
        colophon.add(hairline())
        colophon.add(caption(
            "Sieve is for authorised work on systems and data you are "
            "responsible for. The patterns here find things; what you do "
            "about them is the job."))
        box.addWidget(colophon)
        box.addStretch(1)

        outer.addWidget(scrolled(host))

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.chart.set_mode(mode)
        for mark in self.findChildren(SieveMark):
            mark.set_mode(mode)
