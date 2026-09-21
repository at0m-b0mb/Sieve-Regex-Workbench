"""
Safety — will this pattern hold up against hostile input?

The one page here where the answer can be an incident. A regex in a WAF rule,
a log parser or an input validator that backtracks catastrophically is a
denial of service someone can trigger with a short request.

Two methods, shown separately because they mean different things. The static
read finds the shapes known to blow up; the probe builds adversarial input and
times the real engine. Neither is allowed to say "safe" — the verdict says
what was checked and what happened, and nothing more.
"""

from __future__ import annotations

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QWidget

from ...core import redos
from .. import theme
from ..marks import GrowthCurve
from ..widgets import (Badge, Card, PatternEdit, QuietButton, Stat, caption,
                       intro, label, page_body, primary, row, scrolled, title)


class _Worker(QObject):
    """Runs the probe off the interface thread.

    The probe is bounded to well under two seconds, but "bounded" and "fast"
    are different claims, and a window that stops repainting during a safety
    check is a window people stop running safety checks in.
    """

    done = pyqtSignal(object)

    def __init__(self, pattern: str, flags: int):
        super().__init__()
        self.pattern = pattern
        self.flags = flags

    def run(self) -> None:
        try:
            verdict = redos.analyse(self.pattern, self.flags, measure=True)
        except Exception as exc:                     # never kill the thread
            verdict = redos.Verdict(redos.UNKNOWN, checked=[str(exc)])
        self.done.emit(verdict)


class SafetyPage(QWidget):
    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self.thread: QThread | None = None
        self.verdict: redos.Verdict | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        host, box = page_body()

        box.addWidget(title("Safety"))
        box.addWidget(intro(
            "A regex is code, and this is the one place a plausible-looking "
            "pattern can take down the thing running it. Sieve reads the "
            "pattern for the shapes that blow up, then builds adversarial "
            "input and times the real engine against it."))

        source = Card("The pattern under test")
        self.pattern = PatternEdit(self.mode, "the recipe's pattern appears here")
        self.pattern.setFixedHeight(58)
        self.pattern.setLineWrapMode(self.pattern.LineWrapMode.WidgetWidth)
        source.add(self.pattern)
        self.run_button = primary("Run the check")
        self.run_button.clicked.connect(self.run_check)
        pull = QuietButton("Pull in the pattern from Build")
        pull.clicked.connect(self._pull)
        source.add_layout(row(self.run_button, pull, None))
        box.addWidget(source)

        verdict = Card("Verdict")
        self.badge = Badge("not run", "neutral", self.mode)
        self.headline = label("", object_name="CardTitle")
        verdict.add_layout(row(self.headline, None, self.badge))
        self.blurb = label("", wrap=True)
        verdict.add(self.blurb)
        self.growth = label("", object_name="Faint")
        verdict.add(self.growth)
        box.addWidget(verdict)

        curve = Card("Measured runtime")
        curve.add(caption(
            "Seconds against input length, both on log scales. A line parallel "
            "to the dashed reference is linear time. Anything steeper means "
            "the cost grows faster than the input does."))
        self.plot = GrowthCurve(self.mode)
        curve.add(self.plot)
        self.attack = label("", wrap=True)
        curve.add(self.attack)
        box.addWidget(curve)

        findings = Card("What the static read found")
        self.findings = label("", wrap=True)
        findings.add(self.findings)
        box.addWidget(findings)

        fixes = Card("How to make it cheaper")
        self.fixes = label("", wrap=True)
        fixes.add(self.fixes)
        box.addWidget(fixes)

        honesty = Card("What was checked", flat=True)
        self.checked = label("", wrap=True)
        honesty.add(self.checked)
        honesty.add(caption(
            "This page never says a pattern is safe. A pattern it likes can "
            "still be pathological against an input shape nobody generated. "
            "It reports what it looked for and what it measured — an engine "
            "with linear-time guarantees is the only thing that removes the "
            "risk rather than reducing it."))
        box.addWidget(honesty)
        box.addStretch(1)

        outer.addWidget(scrolled(host))
        state.recipeChanged.connect(self._follow)
        self._follow()

    def _pull(self) -> None:
        self.pattern.set_text(self.state.recipe.pattern())

    def _follow(self) -> None:
        current = self.pattern.toPlainText().strip()
        if not current:
            self._pull()

    def run_check(self) -> None:
        pattern = self.pattern.toPlainText().strip()
        if not pattern:
            self.state.status("There is no pattern to check yet", "warn")
            return
        if self.thread is not None and self.thread.isRunning():
            return

        self.run_button.setEnabled(False)
        self.run_button.setText("Measuring…")
        self.badge.set_tone("neutral", "running")

        self.thread = QThread(self)
        self.worker = _Worker(pattern, self.state.recipe.flags())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.done.connect(self._show)
        self.worker.done.connect(self.thread.quit)
        self.thread.finished.connect(self._cleanup)
        self.thread.start()

    def _cleanup(self) -> None:
        self.run_button.setEnabled(True)
        self.run_button.setText("Run the check")

    def _show(self, verdict: redos.Verdict) -> None:
        self.verdict = verdict
        tone = {redos.CATASTROPHIC: "danger", redos.SUPERLINEAR: "fail",
                redos.SUSPECT: "warn", redos.NOTHING_FOUND: "pass",
                redos.UNKNOWN: "neutral"}[verdict.grade]
        self.badge.set_tone(tone, verdict.grade.replace("_", " "))
        self.headline.setText(verdict.headline)
        self.headline.setStyleSheet(
            f"{theme.font_css('card_title')}"
            f"color: {theme.color(tone if tone != 'neutral' else 'ink', self.mode)};")
        self.blurb.setText(verdict.blurb)
        self.growth.setText(verdict.growth)

        self.plot.set_points(verdict.measurements,
                             "worst case measured" if verdict.measurements else "")
        if verdict.attack_input:
            self.attack.setText("Input that produced it:  "
                                + verdict.attack_input)
            self.attack.setStyleSheet(
                f"{theme.font_css('mono_small')}"
                f"color: {theme.color('ink_muted', self.mode)};")
        else:
            self.attack.setText("")

        if verdict.findings:
            self.findings.setText("\n\n".join(
                f"{f.kind}   {f.excerpt}\n{f.detail}" for f in verdict.findings))
        else:
            self.findings.setText(
                "None of the known-bad shapes are present in this pattern.")

        self.fixes.setText("\n".join("· " + t for t in
                                     redos.safer_rewrite(self.pattern.toPlainText())))
        self.checked.setText(", ".join(verdict.checked) + ".")

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.pattern.apply_mode(mode)
        self.badge.apply_mode(mode)
        self.plot.set_mode(mode)
        if self.verdict is not None:
            self._show(self.verdict)
