"""
Read — what does this regex actually do?

Paste something from a blog post, a vendor rule or a five-year-old detection
and get it back as an ordered reading, plus the table of which engines will
run it. Both halves come from the same tokeniser the editor highlights with,
so what you see coloured and what you see explained can never disagree.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QHeaderView,
                             QSplitter, QTableWidget, QTableWidgetItem,
                             QVBoxLayout, QWidget)

from ...core import explain, flavors
from .. import theme
from ..widgets import (Card, PatternEdit, QuietButton, caption, intro,
                       label, page_body, row, scrolled, title)


class ReadPage(QWidget):
    loadRequested = pyqtSignal()

    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(140)
        self._debounce.timeout.connect(self._analyse)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._left())
        split.addWidget(self._right())
        split.setSizes([620, 440])
        outer.addWidget(split)

        state.recipeChanged.connect(self._maybe_follow)
        self._analyse()

    def _left(self) -> QWidget:
        host, box = page_body()
        box.addWidget(title("Read"))
        box.addWidget(intro(
            "Paste a pattern and get it back in order, one piece at a time. "
            "Inherited regexes are how most detections are written, and "
            "reading one is faster than re-deriving it."))

        source = Card()
        self.input = PatternEdit(self.mode,
                                 "paste a regex here, or pull in the one you are building")
        self.input.setFixedHeight(64)
        self.input.setLineWrapMode(self.input.LineWrapMode.WidgetWidth)
        self.input.changed.connect(lambda _: self._debounce.start())
        source.add(self.input)

        pull = QuietButton("Pull in the pattern from Build")
        pull.clicked.connect(self._pull)
        send = QuietButton("Send this to Build as a new Find rule")
        send.clicked.connect(self._push)
        paste = QuietButton("Paste")
        paste.clicked.connect(self._paste)
        source.add_layout(row(pull, None, paste))
        source.add_layout(row(send, None))
        box.addWidget(source)

        self.summary = label("", wrap=True, object_name="PageIntro")
        box.addWidget(self.summary)

        breakdown = Card("Piece by piece")
        self.tokens = QTableWidget(0, 2)
        self.tokens.setHorizontalHeaderLabels(["Piece", "What it means"])
        self.tokens.verticalHeader().setVisible(False)
        self.tokens.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tokens.setAlternatingRowColors(True)
        self.tokens.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.tokens.setMinimumHeight(340)
        self.tokens.setMinimumWidth(220)
        breakdown.add(self.tokens)
        box.addWidget(breakdown, 1)
        return scrolled(host)

    def _right(self) -> QWidget:
        host, box = page_body()

        matrix = Card("Where it will run")
        matrix.add(caption(
            "Checked against each engine's real capabilities. A blocking "
            "issue means the pattern does not compile there at all — which is "
            "usually discovered in production, by a rule that quietly matches "
            "nothing."))
        # Two columns, not three: a "why" column in a side panel truncates to
        # "At…" and "Th…", which is worse than not showing it. The reasons get
        # full width of their own below.
        self.matrix = QTableWidget(0, 2)
        self.matrix.setHorizontalHeaderLabels(["Engine", "Verdict"])
        self.matrix.verticalHeader().setVisible(False)
        self.matrix.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.matrix.setAlternatingRowColors(True)
        self.matrix.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.matrix.setMinimumHeight(270)
        self.matrix.setMinimumWidth(220)
        matrix.add(self.matrix)
        box.addWidget(matrix)

        objections = Card("What each engine objects to")
        self.objections = label("", wrap=True)
        objections.add(self.objections)
        box.addWidget(objections)

        self.notes = Card("Fixes")
        self.notes_body = label("", wrap=True)
        self.notes.add(self.notes_body)
        box.addWidget(self.notes)
        box.addStretch(1)
        return scrolled(host)

    # -- actions -------------------------------------------------------------

    def _pull(self) -> None:
        self.input.set_text(self.state.recipe.pattern())
        self._analyse()

    def _push(self) -> None:
        from ...core.rules import Rule
        text = self.input.toPlainText().strip()
        if not text:
            return
        self.state.add_rule(Rule(pattern=text, label="pattern read in"))
        self.state.status("Added to the recipe as a Find rule", "pass")
        self.loadRequested.emit()

    def _paste(self) -> None:
        text = QApplication.clipboard().text().strip()
        if text:
            self.input.set_text(text)
            self._analyse()

    def _maybe_follow(self) -> None:
        if not self.input.toPlainText().strip():
            self._pull()

    # -- analysis ------------------------------------------------------------

    def _analyse(self) -> None:
        pattern = self.input.toPlainText().strip()
        if not pattern:
            self.summary.setText("Nothing to read yet.")
            self.tokens.setRowCount(0)
            self.matrix.setRowCount(0)
            self.objections.setText("")
            self.notes_body.setText("")
            return

        self.summary.setText(explain.summary(pattern))

        tokens = explain.tokenise(pattern)
        self.tokens.setRowCount(len(tokens))
        for i, token in enumerate(tokens):
            piece = QTableWidgetItem("    " * token.depth + token.text)
            piece.setFont(self._mono())
            if token.kind == "unrecognised":
                piece.setForeground(QColor(theme.color("fail", self.mode)))
            self.tokens.setItem(i, 0, piece)
            meaning = QTableWidgetItem(token.meaning
                                       + (f"  ({token.note})" if token.note else ""))
            self.tokens.setItem(i, 1, meaning)
        self.tokens.resizeColumnToContents(0)

        reports = flavors.check_all(pattern)
        self.matrix.setRowCount(len(reports))
        tones = {"Runs as written": "pass", "Runs, with caveats": "warn",
                 "Runs after a rewrite": "warn", "Will not run": "fail"}
        objections = []
        for i, (fid, report) in enumerate(reports.items()):
            why = "; ".join(x.message for x in report.issues) or report.flavor.note
            name = QTableWidgetItem(report.flavor.title)
            name.setToolTip(why)
            self.matrix.setItem(i, 0, name)
            verdict = QTableWidgetItem(report.headline)
            verdict.setForeground(QColor(theme.color(
                tones.get(report.headline, "ink_muted"), self.mode)))
            verdict.setToolTip(why)
            self.matrix.setItem(i, 1, verdict)
            if report.issues:
                short = report.flavor.title.split(" (")[0]
                objections.append(f"{short}  —  " + "; ".join(
                    x.message.replace(report.flavor.title, "it").rstrip(".")
                    + (f"  ({x.construct})" if x.construct else "")
                    for x in report.issues) + ".")
        self.matrix.resizeColumnToContents(1)
        self.objections.setText("\n".join(objections) if objections else
                                "Nothing. This pattern runs everywhere Sieve "
                                "knows about.")

        fixes = []
        seen = set()
        for report in reports.values():
            for issue in report.issues:
                if issue.fix and issue.fix not in seen:
                    seen.add(issue.fix)
                    fixes.append(f"· {issue.fix}")
        self.notes_body.setText("\n".join(fixes) if fixes else
                                "No rewrites needed for any engine Sieve knows.")

    def _mono(self):
        from PyQt6.QtGui import QFont
        font = QFont(theme.MONO.split(",")[0])
        font.setPixelSize(12)
        return font

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.input.apply_mode(mode)
        self._analyse()
